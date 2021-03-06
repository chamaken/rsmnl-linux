use std::{
    mem,
    time::{SystemTime, UNIX_EPOCH},
};

extern crate libc;

extern crate rsmnl as mnl;
use mnl::{AttrTbl, CbResult, CbStatus, MsgVec, Msghdr, Socket};

extern crate rsmnl_linux as linux;
use linux::netfilter::{
    nfnetlink::Nfgenmsg, nfnetlink_conntrack as nfct, nfnetlink_conntrack::CtattrTypeTbl,
};

fn data_cb(nlh: &Msghdr) -> CbResult {
    let tb = CtattrTypeTbl::from_nlmsg(mem::size_of::<Nfgenmsg>(), nlh)?;
    if let Some(tuple_tb) = tb.tuple_orig()? {
        if let Some(ip_tb) = tuple_tb.ip()? {
            ip_tb.v4_src()?.map(|x| print!("src={} ", x));
            ip_tb.v4_dst()?.map(|x| print!("dst={} ", x));
            ip_tb.v6_src()?.map(|x| print!("src={} ", x));
            ip_tb.v6_dst()?.map(|x| print!("dst={} ", x));
        }
        if let Some(proto_tb) = tuple_tb.proto()? {
            proto_tb.num()?.map(|x| print!("proto={} ", x));
            proto_tb
                .src_port()?
                .map(|x| print!("sport={} ", u16::from_be(*x)));
            proto_tb
                .dst_port()?
                .map(|x| print!("dport={} ", u16::from_be(*x)));
            proto_tb
                .icmp_id()?
                .map(|x| print!("id={} ", u16::from_be(*x)));
            proto_tb.icmp_type()?.map(|x| print!("type={} ", x));
            proto_tb.icmp_code()?.map(|x| print!("code={} ", x));
            proto_tb
                .icmpv6_id()?
                .map(|x| print!("id={} ", u16::from_be(*x)));
            proto_tb.icmpv6_type()?.map(|x| print!("type={} ", x));
            proto_tb.icmpv6_code()?.map(|x| print!("code={} ", x));
        }
    }

    tb.mark()?.map(|x| print!("mark={} ", u32::from_be(*x)));
    tb.secmark()?
        .map(|x| print!("secmark={} ", u32::from_be(*x))); // obsolete?

    if let Some(cntb) = tb.counters_orig()? {
        print!("original ");
        cntb.packets()?
            .map(|x| print!("packets={} ", u64::from_be(*x)));
        cntb.bytes()?.map(|x| print!("bytes={} ", u64::from_be(*x)));
    }

    if let Some(cntb) = tb.counters_reply()? {
        print!("reply ");
        cntb.packets()?
            .map(|x| print!("packets={} ", u64::from_be(*x)));
        cntb.bytes()?.map(|x| print!("bytes={} ", u64::from_be(*x)));
    }

    println!("");
    Ok(CbStatus::Ok)
}

fn main() -> Result<(), String> {
    let mut nl = Socket::open(libc::NETLINK_NETFILTER, 0)
        .map_err(|errno| format!("mnl_socket_open: {}", errno))?;
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .map_err(|errno| format!("mnl_socket_bind: {}", errno))?;

    let mut nlv = MsgVec::new();
    let mut nlh = nlv.put_header();
    nlh.nlmsg_type = (libc::NFNL_SUBSYS_CTNETLINK << 8) as u16 | nfct::IPCTNL_MSG_CT_GET;
    nlh.nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
    let seq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    nlh.nlmsg_seq = seq;
    let nfh = nlv.put_extra_header::<Nfgenmsg>().unwrap();
    nfh.nfgen_family = libc::AF_INET as u8;
    nfh.version = libc::NFNETLINK_V0 as u8;
    nfh.res_id = 0;
    nl.sendto(&nlv)
        .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;

    let mut buf = mnl::dump_buffer();
    let portid = nl.portid();
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
