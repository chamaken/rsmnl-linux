use std::{
    env, mem,
    os::unix::io::{AsRawFd, FromRawFd},
    process,
    time::Duration,
};

extern crate errno;
use errno::Errno;

extern crate mio;
use mio::{net::UdpSocket, Events, Interest, Poll, Token};

extern crate rsmnl as mnl;
use mnl::{AttrTbl, CbResult, CbStatus, GenError, MsgVec, Msghdr, Socket};

extern crate rsmnl_linux as linux;
use linux::netfilter::{
    nfnetlink::Nfgenmsg, nfnetlink_conntrack as nfct, nfnetlink_conntrack::CtattrStatsCpuTbl,
};

extern crate libc; // for timerfd
mod timerfd;

fn data_cb(nlh: &Msghdr) -> CbResult {
    let tb = CtattrStatsCpuTbl::from_nlmsg(mem::size_of::<Nfgenmsg>(), nlh)?;
    let nfh = nlh.payload::<Nfgenmsg>()?;
    print!("CPU={} ", u16::from_be(nfh.res_id));
    tb.found()?.map(|x| print!("found={} ", u32::from_be(*x)));
    tb.invalid()?
        .map(|x| print!("invalid={} ", u32::from_be(*x)));
    tb.insert()?.map(|x| print!("insert={} ", u32::from_be(*x)));
    tb.insert_failed()?
        .map(|x| print!("insert_failed={} ", u32::from_be(*x)));
    tb.drop()?.map(|x| print!("drop={} ", u32::from_be(*x)));
    tb.early_drop()?
        .map(|x| print!("early_drop={} ", u32::from_be(*x)));
    tb.stats_error()?
        .map(|x| print!("stats_error={} ", u32::from_be(*x)));
    tb.search_restart()?
        .map(|x| print!("search_restart={} ", u32::from_be(*x)));
    tb.clash_resolve()?
        .map(|x| print!("crash_resolve={} ", u32::from_be(*x)));
    println!("");
    Ok(CbStatus::Ok)
}

fn handle(nl: &mut Socket) -> CbResult {
    let mut buf = mnl::dump_buffer();
    loop {
        match nl.recvfrom(&mut buf) {
            Ok(nrecv) => match mnl::cb_run(&buf[0..nrecv], 0, 0, Some(data_cb)) {
                Ok(CbStatus::Ok) => continue,
                ret => return ret,
            },
            Err(errno) => {
                if errno.0 == libc::EAGAIN {
                    return Ok(CbStatus::Ok);
                } else {
                    println!("mnl_socket_recvfrom: {}", errno);
                }
                return mnl::gen_errno!(errno.0);
            }
        }
    }
}

fn main() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        println!("\nUsage: {} <poll-secs>", args[0]);
        process::exit(libc::EXIT_FAILURE);
    }
    let secs = args[1].parse::<u32>().unwrap();
    println!("Polling every {} seconds from kernel...", secs);

    let mut nlv = MsgVec::new();
    let mut nlh = nlv.put_header();
    nlh.nlmsg_type = (libc::NFNL_SUBSYS_CTNETLINK << 8) as u16 | nfct::IPCTNL_MSG_CT_GET_STATS_CPU;
    nlh.nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;

    let nfh = nlv.put_extra_header::<Nfgenmsg>().unwrap();
    nfh.nfgen_family = libc::AF_UNSPEC as u8;
    nfh.version = libc::NFNETLINK_V0 as u8;
    nfh.res_id = 0;

    // Open netlink socket to operate with netfilter
    let mut nl = Socket::open(libc::NETLINK_NETFILTER, 0)
        .map_err(|errno| format!("mnl_socket_open: {}", errno))?;
    let _ = nl.set_nonblock();

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
                        .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;
                }
                _ => {
                    let _ = handle(&mut nl).unwrap();
                }
            }
        }
    }
}
