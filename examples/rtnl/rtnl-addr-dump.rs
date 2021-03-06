use std::{
    env, mem, process,
    time::{SystemTime, UNIX_EPOCH},
    vec::Vec,
};

extern crate libc;

extern crate rsmnl as mnl;
use mnl::{AttrTbl, CbResult, CbStatus, MsgVec, Msghdr, Socket};

extern crate rsmnl_linux as linux;
use linux::{
    if_addr::{IfAddrTbl, Ifaddrmsg},
    rtnetlink::Rtgenmsg,
};

fn data_cb(nlh: &Msghdr) -> CbResult {
    let ifa = nlh.payload::<Ifaddrmsg>().unwrap();
    print!("index={} family={} ", ifa.ifa_index, ifa.ifa_family);

    let tb = IfAddrTbl::from_nlmsg(mem::size_of::<Ifaddrmsg>(), nlh)?;
    print!("addr=");
    if ifa.ifa_family == libc::AF_INET as u8 {
        tb.address4()?.map(|x| print!("{} ", x));
    } else if ifa.ifa_family == libc::AF_INET6 as u8 {
        tb.address6()?.map(|x| print!("{} ", x));
    }

    print!("scope=");
    match ifa.ifa_scope {
        0 => print!("global "),
        200 => print!("site "),
        253 => print!("link "),
        254 => print!("host "),
        255 => print!("nowhere "),
        _ => print!("{} ", ifa.ifa_scope),
    }

    println!("");
    Ok(CbStatus::Ok)
}

fn main() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <inet|inet6>", args[0]);
        process::exit(libc::EXIT_FAILURE);
    }

    let mut nlv = MsgVec::new();
    let mut nlh = nlv.put_header();
    nlh.nlmsg_type = libc::RTM_GETADDR as u16;
    nlh.nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
    let seq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    nlh.nlmsg_seq = seq;
    let rt = nlv.put_extra_header::<Rtgenmsg>().unwrap();
    if args[1] == "inet" {
        rt.rtgen_family = libc::AF_INET as u8;
    } else if args[1] == "inet6" {
        rt.rtgen_family = libc::AF_INET6 as u8;
    }

    let mut nl = Socket::open(libc::NETLINK_ROUTE, 0)
        .map_err(|errno| format!("mnl_socket_open: {}", errno))?;

    nl.bind(0, mnl::SOCKET_AUTOPID)
        .map_err(|errno| format!("mnl_socket_bind: {}", errno))?;
    let portid = nl.portid();

    nl.sendto(&nlv)
        .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;

    let mut buf = mnl::dump_buffer();
    loop {
        let nrecv = nl
            .recvfrom(&mut buf)
            .map_err(|errno| format!("mnl_socket_recvfrom: {}", errno))?;

        match mnl::cb_run(&buf[..nrecv], seq, portid, Some(data_cb)) {
            Ok(CbStatus::Ok) => continue,
            Ok(CbStatus::Stop) => break,
            Err(errno) => return Err(format!("mnl_cb_run: {}", errno)),
        }
    }

    Ok(())
}
