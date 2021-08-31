use std::{
    env, mem, process,
    time::{SystemTime, UNIX_EPOCH},
};

extern crate libc;

extern crate rsmnl as mnl;
use mnl::{AttrTbl, CbResult, CbStatus, MsgVec, Msghdr, Socket};

extern crate rsmnl_linux as linux;
use linux::{
    genetlink as genl,
    genetlink::{CtrlAttr, CtrlAttrTbl},
};

fn data_cb(nlh: &Msghdr) -> CbResult {
    let tb = CtrlAttrTbl::from_nlmsg(mem::size_of::<libc::genlmsghdr>(), nlh)?;
    tb.family_name()?.map(|x| print!("name: {}, ", x));
    tb.family_id()?.map(|x| print!("id: {}, ", x));
    tb.version()?.map(|x| print!("version: {}, ", x));
    tb.hdrsize()?.map(|x| print!("hdrsize: {}, ", x));
    tb.maxattr()?.map(|x| print!("maxattr: {}", x));
    println!("");

    if let Some(optbs) = tb.ops()? {
        println!("  ops:");
        for optb in optbs {
            optb.id()?.map(|x| print!("    id: 0x{:x}, ", x));
            optb.flags()?.map(|x| print!("flags: 0x{:08x} ", x));
            println!("");
        }
    }

    if let Some(mctbs) = tb.mcast_groups()? {
        println!("  grps:");
        for mctb in mctbs {
            mctb.id()?.map(|x| print!("    id: 0x{:x}, ", x));
            mctb.name()?.map(|x| print!("name: {} ", x));
            println!("");
        }
    }

    Ok(CbStatus::Ok)
}

fn main() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() > 2 {
        println!("{} [family name]", args[0]);
        process::exit(libc::EXIT_FAILURE);
    }

    let mut nlv = MsgVec::new();
    let mut nlh = nlv.put_header();
    nlh.nlmsg_type = libc::GENL_ID_CTRL as u16;
    nlh.nlmsg_flags = libc::NLM_F_REQUEST as u16 | libc::NLM_F_ACK as u16;
    let seq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    nlh.nlmsg_seq = seq;
    if args.len() < 2 {
        nlh.nlmsg_flags |= libc::NLM_F_DUMP as u16;
    }

    let genl = nlv.put_extra_header::<libc::genlmsghdr>().unwrap();
    genl.cmd = libc::CTRL_CMD_GETFAMILY as u8;
    genl.version = 1;

    CtrlAttr::put_family_id(&mut nlv, &genl::GENL_ID_CTRL).unwrap();
    if args.len() >= 2 {
        CtrlAttr::put_family_name(&mut nlv, &args[1]).unwrap();
    }

    let mut nl = Socket::open(libc::NETLINK_GENERIC, 0)
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

        match mnl::cb_run(&buf[0..nrecv], seq, portid, Some(data_cb)) {
            Ok(CbStatus::Ok) => continue,
            Ok(CbStatus::Stop) => break,
            Err(errno) => return Err(format!("mnl_cb_run: {}", errno)),
        }
    }

    Ok(())
}
