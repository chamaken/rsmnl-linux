use std::{
    env, mem, process,
    time::{SystemTime, UNIX_EPOCH},
};

extern crate libc;

extern crate rsmnl as mnl;
use mnl::{AttrTbl, CbResult, CbStatus, MsgVec, Msghdr, Socket};

extern crate rsmnl_linux as linux;
use linux::{
    neighbour::{NdaTbl, Ndmsg},
    rtnetlink,
};

fn data_cb(nlh: &Msghdr) -> CbResult {
    let ndm = nlh.payload::<Ndmsg>().unwrap();
    print!("index={} family={} ", ndm.ndm_ifindex, ndm.ndm_family);

    let tb = NdaTbl::from_nlmsg(mem::size_of::<Ndmsg>(), nlh)?;
    match ndm.ndm_family as i32 {
        libc::AF_INET => tb.v4dst()?.map(|x| print!("dst={} ", x)),
        libc::AF_INET6 => tb.v6dst()?.map(|x| print!("dst={} ", x)),
        _ => None,
    };

    tb.lladdr()?.map(|x| {
        print!(
            "hwaddr={} ",
            x.into_iter()
                .map(|&e| format!("{:02x}", e))
                .collect::<Vec<_>>()
                .join(":")
        )
    });

    print!("state=");
    match ndm.ndm_state {
        libc::NUD_INCOMPLETE => print!("incomplete "),
        libc::NUD_REACHABLE => print!("reachable "),
        libc::NUD_STALE => print!("stale "),
        libc::NUD_DELAY => print!("delay "),
        libc::NUD_PROBE => print!("probe "),
        libc::NUD_FAILED => print!("failed "),
        libc::NUD_NOARP => print!("noarp "),
        libc::NUD_PERMANENT => print!("permanent "),
        state => print!("{} ", state),
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
    nlh.nlmsg_type = libc::RTM_GETNEIGH;
    nlh.nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
    let seq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    nlh.nlmsg_seq = seq;

    let mut rt = nlv.put_extra_header::<rtnetlink::Rtgenmsg>().unwrap();
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
        match mnl::cb_run(&buf[0..nrecv], seq, portid, Some(data_cb)) {
            Ok(CbStatus::Ok) => continue,
            Ok(CbStatus::Stop) => break,
            Err(errno) => return Err(format!("mnl_cb_run: {}", errno)),
        }
    }

    Ok(())
}
