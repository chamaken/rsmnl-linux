use std::mem;

extern crate libc;

extern crate rsmnl as mnl;
use mnl::{AttrTbl, CbResult, CbStatus, Msghdr, Socket};

extern crate rsmnl_linux as linux;
use linux::netfilter::{
    nfnetlink::Nfgenmsg,
    nfnetlink_conntrack as nfct,
    nfnetlink_conntrack::{CtattrTypeTbl, CtnlMsgTypes},
};

fn data_cb(nlh: &Msghdr) -> CbResult {
    match nlh.nlmsg_type & 0xFF {
        n if n == CtnlMsgTypes::New as u16 => {
            if nlh.nlmsg_flags & (libc::NLM_F_CREATE | libc::NLM_F_EXCL) as u16 != 0 {
                print!("{:9} ", "[NEW] ");
            } else {
                print!("{:9} ", "[UPDATE] ");
            }
        }
        n if n == CtnlMsgTypes::Delete as u16 => {
            print!("{:9} ", "[DESTROY] ");
        }
        _ => {
            print!("{:9} ", "[UNKNOWN] ");
        }
    }

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

    println!("");
    Ok(CbStatus::Ok)
}

fn main() -> Result<(), String> {
    let mut nl = Socket::open(libc::NETLINK_NETFILTER, 0)
        .map_err(|errno| format!("mnl_socket_open: {}", errno))?;
    nl.bind(
        nfct::NF_NETLINK_CONNTRACK_NEW
            | nfct::NF_NETLINK_CONNTRACK_UPDATE
            | nfct::NF_NETLINK_CONNTRACK_DESTROY,
        mnl::SOCKET_AUTOPID,
    )
    .map_err(|errno| format!("mnl_socket_bind: {}", errno))?;

    let mut buf = mnl::default_buffer();
    loop {
        let nrecv = nl
            .recvfrom(&mut buf)
            .map_err(|errno| format!("mnl_socket_recvfrom: {}", errno))?;
        mnl::cb_run(&buf[..nrecv], 0, 0, Some(data_cb))
            .map_err(|errno| format!("mnl_cb_run: {}", errno))?;
    }
}
