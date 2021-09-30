use std::{
    env, fs, mem,
    os::unix::io::{AsRawFd, FromRawFd},
    process, thread,
    time::Duration,
};

extern crate libc;
use libc::{c_int, c_void, socklen_t};

extern crate errno;
use errno::Errno;

extern crate mio;
use mio::{net::UdpSocket, Events, Interest, Poll, Token};

extern crate bit_vec;
extern crate chrono;
extern crate once_cell;

extern crate crossbeam_channel;
use crossbeam_channel::{unbounded, Receiver, Sender};

extern crate rsmnl as mnl;
use mnl::{CbResult, CbStatus, GenError, MsgVec, Msghdr, Socket};

extern crate rsmnl_linux as linux;
use linux::netfilter::{
    nfnetlink::Nfgenmsg, nfnetlink_conntrack as nfct, nfnetlink_conntrack::CtattrType,
};

mod mapping;
mod msg;
mod msgfmt;
mod output;
mod timerfd;
use {msg::SendTemplateFactory, msg::Set, output::file_out};

fn data_cb<'a>(
    stf: &'a mut SendTemplateFactory,
    tmpl_tx: &'a Sender<Set>,
    data_tx: &'a Sender<Set>,
) -> impl FnMut(&Msghdr) -> CbResult + 'a {
    move |nlh: &Msghdr| {
        if let Some((mut dset, bv)) = Set::from_nlmsg(nlh).unwrap() {
            let (id, ret) = stf.once(&bv);
            if let Some(tset) = ret {
                tmpl_tx.send(tset.clone()).unwrap();
            }
            let hdr = dset.header_mut();
            hdr.id = u16::to_be(id);
            data_tx.send(dset).unwrap();
        }

        Ok(CbStatus::Ok)
    }
}

fn handle(
    nl: &mut Socket,
    stf: &mut SendTemplateFactory,
    tmpl_tx: &Sender<Set>,
    data_tx: &Sender<Set>,
) -> CbResult {
    let mut buf = mnl::dump_buffer();
    // let mut cb = data_cb(stf, tx);
    loop {
        match nl.recvfrom(&mut buf) {
            Ok(nrecv) => {
                match mnl::cb_run(&buf[0..nrecv], 0, 0, Some(data_cb(stf, tmpl_tx, data_tx))) {
                    Ok(CbStatus::Ok) => continue,
                    ret => return ret,
                }
            }
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

// Open netlink socket to operate with netfilter
fn init_socket(nonblock: bool) -> Result<Socket, Errno> {
    let mut nl = Socket::open(libc::NETLINK_NETFILTER, 0)?;

    // Subscribe to destroy events to avoid leaking counters. The same
    // socket is used to periodically atomically dump and reset counters.
    nl.bind(nfct::NF_NETLINK_CONNTRACK_DESTROY, mnl::SOCKET_AUTOPID)?;

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
    if nonblock {
        let _ = nl.set_nonblock();
    }

    Ok(nl)
}

fn fill_hdr(mtype: u16, flags: u16, l3num: u8, version: u8) -> MsgVec {
    let mut nlv = MsgVec::new();
    let mut nlh = nlv.put_header();
    // Counters are atomically zeroed in each dump
    nlh.nlmsg_type = (libc::NFNL_SUBSYS_CTNETLINK << 8) as u16 | mtype;
    nlh.nlmsg_flags = libc::NLM_F_REQUEST as u16 | flags;

    let nfh = nlv.put_extra_header::<Nfgenmsg>().unwrap();
    nfh.nfgen_family = l3num;
    nfh.version = version;
    nfh.res_id = 0;

    // Filter by mark: We only want to dump entries whose mark is zero
    CtattrType::put_mark(&mut nlv, &0u32.to_be()).unwrap();
    CtattrType::put_mark_mask(&mut nlv, &0xffffffffu32.to_be()).unwrap();

    nlv
}

fn flush() -> Result<(), Errno> {
    let nl = init_socket(false)?;
    let nlv = fill_hdr(
        nfct::IPCTNL_MSG_CT_DELETE,
        libc::NLM_F_ACK as u16,
        libc::AF_UNSPEC as u8,
        1,
    );
    nl.sendto(&nlv)?;
    let mut buf = mnl::dump_buffer();
    let portid = nl.portid();
    loop {
        let nrecv = nl.recvfrom(&mut buf)?;
        match mnl::cb_run(&buf[..nrecv], 0, portid, mnl::NOCB) {
            Ok(CbStatus::Ok) => continue,
            Ok(CbStatus::Stop) => break,
            Err(err) => {
                if let Some(errno) = err.downcast_ref::<Errno>() {
                    return Err(*errno);
                } else {
                    unreachable!();
                }
            }
        }
    }

    Ok(())
}

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

    // init
    let mut stf = SendTemplateFactory::new();
    let (tmpl_tx, tmpl_rx): (Sender<Set>, Receiver<Set>) = unbounded();
    let (data_tx, data_rx): (Sender<Set>, Receiver<Set>) = unbounded();
    let mut file = fs::File::create("nfct.ipfix").unwrap();
    let _write_out = thread::spawn(move || file_out(&mut file, tmpl_rx, data_rx));

    flush().map_err(|errno| format!("flush: {}", errno))?;
    let mut nl = init_socket(true).map_err(|errno| format!("init_socket: {}", errno))?;
    let nlv = fill_hdr(
        nfct::IPCTNL_MSG_CT_GET_CTRZERO,
        libc::NLM_F_DUMP as u16,
        libc::AF_UNSPEC as u8,
        libc::NFNETLINK_V0 as u8,
    );

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
                }
                _ => {
                    handle(&mut nl, &mut stf, &tmpl_tx, &data_tx).unwrap();
                }
            }
        }
    }
}
