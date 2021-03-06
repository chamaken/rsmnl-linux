use std::mem;

extern crate rsmnl as mnl;
use mnl::{AttrTbl, CbResult, CbStatus, Msghdr, Socket};

extern crate rsmnl_linux as linux;
use linux::{
    if_link::IflaTbl,
    ifh,
    rtnetlink::{self, Ifinfomsg},
};

fn data_cb(nlh: &Msghdr) -> CbResult {
    let ifm: &Ifinfomsg = nlh.payload()?;
    print!(
        "index={} type={} flags=0x{:x} family={} ",
        ifm.ifi_index, ifm.ifi_type, ifm.ifi_flags, ifm.ifi_family
    );

    if ifm.ifi_flags & ifh::IFF_RUNNING != 0 {
        print!("[RUNNING] ");
    } else {
        print!("[NOT RUNNING] ");
    }

    let tb = IflaTbl::from_nlmsg(mem::size_of::<Ifinfomsg>(), nlh)?;
    tb.mtu()?.map(|x| print!("mtu={} ", x));
    tb.ifname()?.map(|x| print!("name={} ", x));

    println!("");
    Ok(CbStatus::Ok)
}

fn main() -> Result<(), String> {
    let mut nl = Socket::open(libc::NETLINK_ROUTE, 0)
        .map_err(|errno| format!("mnl_socket_open: {}", errno))?;
    nl.bind(rtnetlink::RTMGRP_LINK, mnl::SOCKET_AUTOPID)
        .map_err(|errno| format!("mnl_socket_bind: {}", errno))?;

    let mut buf = mnl::default_buffer();
    loop {
        let nrecv = nl
            .recvfrom(&mut buf)
            .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;
        match mnl::cb_run(&buf[0..nrecv], 0, 0, Some(&mut data_cb)) {
            Ok(CbStatus::Ok) => continue,
            Ok(CbStatus::Stop) => break,
            Err(errno) => return Err(format!("mnl_cb_run: {}", errno)),
        }
    }

    Ok(())
}
