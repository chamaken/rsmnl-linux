use std::{
    collections::HashMap,
    env, mem,
    net::{IpAddr, Ipv4Addr},
    os::unix::io::{AsRawFd, FromRawFd},
    process,
    time::Duration,
};

extern crate libc;
use libc::{c_int, c_void, socklen_t};

extern crate errno;
use errno::Errno;

extern crate mio;
use mio::{net::UdpSocket, Events, Interest, Poll, Token};

extern crate rsmnl as mnl;
use mnl::{AttrTbl, CbResult, CbStatus, GenError, MsgVec, Msghdr, Socket};

extern crate rsmnl_linux as linux;
use linux::netfilter::{
    nfnetlink::Nfgenmsg,
    nfnetlink_conntrack as nfct,
    nfnetlink_conntrack::{CtattrType, CtattrTypeTbl},
};

mod timerfd;

#[derive(Debug)]
struct Nstats {
    pkts: u64,
    bytes: u64,
}

fn data_cb(hmap: &mut HashMap<IpAddr, Box<Nstats>>) -> impl FnMut(&Msghdr) -> CbResult + '_ {
    move |nlh: &Msghdr| {
        let tb = CtattrTypeTbl::from_nlmsg(mem::size_of::<Nfgenmsg>(), nlh)?;

        let mut addr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)); // as default
        if let Some(tuple_tb) = tb.tuple_orig()? {
            if let Some(ip_tb) = tuple_tb.ip()? {
                ip_tb.v4_src()?.map(|r| {
                    addr = IpAddr::V4(*r);
                });
                ip_tb.v6_src()?.map(|r| {
                    addr = IpAddr::V6(*r);
                });
            }
        }

        let ns = hmap
            .entry(addr)
            .or_insert(Box::new(Nstats { pkts: 0, bytes: 0 }));

        if let Some(counters_tb) = tb.counters_orig()? {
            counters_tb.packets()?.map(|c| {
                ns.pkts += u64::from_be(*c);
            });
            counters_tb.bytes()?.map(|c| {
                ns.bytes += u64::from_be(*c);
            });
        }

        Ok(CbStatus::Ok)
    }
}

fn handle(nl: &mut Socket, hmap: &mut HashMap<IpAddr, Box<Nstats>>) -> CbResult {
    let mut buf = mnl::dump_buffer();
    loop {
        match nl.recvfrom(&mut buf) {
            Ok(nrecv) => match mnl::cb_run(&buf[0..nrecv], 0, 0, Some(data_cb(hmap))) {
                Ok(CbStatus::Ok) => continue,
                ret => return ret,
            },
            Err(errno) => {
                if errno.0 == libc::EAGAIN {
                    return Ok(CbStatus::Ok);
                }
                if errno.0 == libc::ENOBUFS {
                    println!(
                        "The daemon has hit ENOBUFS, you can \
			      increase the size of your receiver \
			      buffer to mitigate this or enable \
			      reliable delivery."
                    );
                } else {
                    println!("mnl_socket_recvfrom: {}", errno);
                }
                return mnl::gen_errno!(errno.0);
            }
        }
    }
}

pub const SO_RECVBUFFORCE: c_int = 33;

fn main() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        println!("\nUsage: {} <poll-secs>", args[0]);
        process::exit(libc::EXIT_FAILURE);
    }
    let secs = args[1].parse::<u32>().unwrap();
    println!("Polling every {} seconds from kernel...", secs);

    // Set high priority for this process, less chances to overrun
    // the netlink receiver buffer since the scheduler gives this process
    // more chances to run.
    unsafe {
        libc::nice(-20);
    };

    // Open netlink socket to operate with netfilter
    let mut nl = Socket::open(libc::NETLINK_NETFILTER, 0)
        .map_err(|errno| format!("mnl_socket_open: {}", errno))?;

    // Subscribe to destroy events to avoid leaking counters. The same
    // socket is used to periodically atomically dump and reset counters.
    nl.bind(nfct::NF_NETLINK_CONNTRACK_DESTROY, mnl::SOCKET_AUTOPID)
        .map_err(|errno| format!("mnl_socket_bind: {}", errno))?;

    // Set netlink receiver buffer to 16 MBytes, to avoid packet drops
    unsafe {
        let buffersize: c_int = 1 << 22;
        libc::setsockopt(
            nl.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_RECVBUFFORCE,
            &buffersize as *const _ as *const c_void,
            mem::size_of::<socklen_t>() as u32,
        );
    }

    // The two tweaks below enable reliable event delivery, packets may
    // be dropped if the netlink receiver buffer overruns. This happens ...
    //
    // a) if the kernel spams this user-space process until the receiver
    //    is filled.
    //
    // or:
    //
    // b) if the user-space process does not pull messages from the
    //    receiver buffer so often.
    let _ = nl.set_broadcast_error(true);
    let _ = nl.set_no_enobufs(true);
    // set nonblock for mio
    let _ = nl.set_nonblock();

    let mut nlv = MsgVec::new();
    let mut nlh = nlv.put_header();
    // Counters are atomically zeroed in each dump
    nlh.nlmsg_type = (libc::NFNL_SUBSYS_CTNETLINK << 8) as u16 | nfct::IPCTNL_MSG_CT_GET_CTRZERO;
    nlh.nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;

    let nfh = nlv.put_extra_header::<Nfgenmsg>().unwrap();
    nfh.nfgen_family = libc::AF_INET as u8;
    nfh.version = libc::NFNETLINK_V0 as u8;
    nfh.res_id = 0;

    // Filter by mark: We only want to dump entries whose mark is zero
    CtattrType::put_mark(&mut nlv, &0u32.to_be()).unwrap();
    CtattrType::put_mark_mask(&mut nlv, &0xffffffffu32.to_be()).unwrap();

    let mut hmap = HashMap::<IpAddr, Box<Nstats>>::new();

    // mio initializations
    let token = Token(nl.as_raw_fd() as usize);
    let mut listener = unsafe { UdpSocket::from_raw_fd(nl.as_raw_fd()) };
    let mut timer = timerfd::Timerfd::create(libc::CLOCK_MONOTONIC, 0).unwrap();
    timer
        .settime(
            0,
            &timerfd::Itimerspec {
                it_interval: Duration::new(secs as u64, 0),
                it_value: Duration::new(0, 1),
            },
        )
        .unwrap();

    // Create an poll instance
    let mut poll = Poll::new().unwrap();
    // Start listening for incoming connections
    poll.registry()
        .register(&mut listener, token, Interest::READABLE)
        .unwrap();
    poll.registry()
        .register(&mut timer, Token(0), Interest::READABLE)
        .unwrap();
    // Create storage for events
    let mut events = Events::with_capacity(256);
    loop {
        poll.poll(&mut events, None).unwrap();
        for event in events.iter() {
            match usize::from(event.token()) {
                0 => {
                    // timer
                    timer.read().unwrap(); // just consume
                    nl.sendto(&nlv)
                        .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
                    for (addr, nstats) in hmap.iter() {
                        print!("src={:?} ", addr);
                        println!("counters {} {}", nstats.pkts, nstats.bytes);
                    }
                }
                _ => {
                    let _ = handle(&mut nl, &mut hmap).unwrap();
                }
            }
        }
    }
}
