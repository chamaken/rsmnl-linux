use std::mem;

extern crate libc;

extern crate errno;
use errno::Errno;

extern crate rsmnl as mnl;
use mnl:: { Socket, Msghdr, CbStatus, CbResult, AttrTbl, };

extern crate rsmnl_linux as linux;
use linux:: {
    netlink::Family,
    rtnetlink:: { self, Rtmsg, RtattrTypeTbl },
};

fn attributes_show_ip(family: i32, tb: &RtattrTypeTbl) -> Result<(), Errno> {
    tb.table()?.map(|x| print!("table={} ", x));
    if family == libc::AF_INET {
        tb.v4dst()?.map(|x| print!("dst={} ", x));
        tb.v4src()?.map(|x| print!("src={} ", x));
    } else if family == libc::AF_INET6 {
        tb.v6dst()?.map(|x| print!("dst={} ", x));
        tb.v6src()?.map(|x| print!("src={} ", x));
    }
    tb.oif()?.map(|x| print!("oif={} ", x));
    tb.flow()?.map(|x| print!("flow={} ", x));
    if family == libc::AF_INET {
        tb.v4prefsrc()?.map(|x| print!("prefsrc={} ", x));
        tb.v4gateway()?.map(|x| print!("gw={} ", x));
    } else if family == libc::AF_INET6 {
        tb.v6prefsrc()?.map(|x| print!("prefsrc={} ", x));
        tb.v6gateway()?.map(|x| print!("gw={} ", x));
    }
    tb.priority()?.map(|x| print!("prio={} ", x));
    if let Some(xtb) = tb.metrics()? {
        print!("\n  metrics: ");
        xtb.lock()?.map(|x| print!("lock={} ", x));
        xtb.mtu()?.map(|x| print!("mtu={} ", x));
        xtb.window()?.map(|x| print!("window={} ", x));
        xtb.rtt()?.map(|x| print!("rtt={} ", x));
        xtb.rttvar()?.map(|x| print!("rttvar={} ", x));
        xtb.ssthresh()?.map(|x| print!("ssthresh={} ", x));
        xtb.cwnd()?.map(|x| print!("cwnd={} ", x));
        xtb.advmss()?.map(|x| print!("advmss={} ", x));
        xtb.reordering()?.map(|x| print!("reordering={} ", x));
        xtb.hoplimit()?.map(|x| print!("hoplimit={} ", x));
        xtb.initcwnd()?.map(|x| print!("initcwnd={} ", x));
        xtb.features()?.map(|x| print!("features={} ", x));
        xtb.rto_min()?.map(|x| print!("rto_min={} ", x));
        xtb.initrwnd()?.map(|x| print!("initrwnd={} ", x));
        xtb.quickack()?.map(|x| print!("quickack={} ", x));
        xtb.cc_algo()?.map(|x| print!("cc_algo={} ", x));
        xtb.fastopen_no_cookie()?.map(|x| print!("fastopen_no_cookie={} ", x));
    }
    Ok(())
}

fn data_cb(nlh: &Msghdr) -> CbResult {
    let rm = nlh.payload::<Rtmsg>()?;

    match nlh.nlmsg_type {
        n if n == rtnetlink::RTM_NEWROUTE => print!("[NEW] "),
        n if n == rtnetlink::RTM_DELROUTE => print!("[DEL] "),
        _ => {},
    }

    // protocol family = AF_INET | AF_INET6 //
    print!("family={} ", rm.rtm_family);

    // destination CIDR, eg. 24 or 32 for IPv4
    print!("dst_len={} ", rm.rtm_dst_len);

    // source CIDR
    print!("src_len={} ", rm.rtm_src_len);

    // type of service (TOS), eg. 0
    print!("tos={} ", rm.rtm_tos);

    // table id:
    //	RT_TABLE_UNSPEC		= 0
    //
    //	... user defined values ...
    //
    //		RT_TABLE_COMPAT		= 252
    //		RT_TABLE_DEFAULT	= 253
    //		RT_TABLE_MAIN		= 254
    //		RT_TABLE_LOCAL		= 255
    //		RT_TABLE_MAX		= 0xFFFFFFFF
    //
    //	Synonimous attribute: RTA_TABLE.
    print!("table={} ", rm.rtm_table);

    // type:
    // 	RTN_UNSPEC	= 0
    // 	RTN_UNICAST	= 1
    // 	RTN_LOCAL	= 2
    // 	RTN_BROADCAST	= 3
    //	RTN_ANYCAST	= 4
    //	RTN_MULTICAST	= 5
    //	RTN_BLACKHOLE	= 6
    //	RTN_UNREACHABLE	= 7
    //	RTN_PROHIBIT	= 8
    //	RTN_THROW	= 9
    //	RTN_NAT		= 10
    //	RTN_XRESOLVE	= 11
    //	__RTN_MAX	= 12
    print!("type={} ", rm.rtm_type);

    // scope:
    // 	RT_SCOPE_UNIVERSE	= 0   : everywhere in the universe
    //
    //	... user defined values ...
    //
    //	 	RT_SCOPE_SITE		= 200
    //	 	RT_SCOPE_LINK		= 253 : destination attached to link
    //	 	RT_SCOPE_HOST		= 254 : local address
    //	 	RT_SCOPE_NOWHERE	= 255 : not existing destination
    print!("scope={} ", rm.rtm_scope);

    // protocol:
    // 	RTPROT_UNSPEC	= 0
    // 	RTPROT_REDIRECT = 1
    // 	RTPROT_KERNEL	= 2 : route installed by kernel
    // 	RTPROT_BOOT	= 3 : route installed during boot
    // 	RTPROT_STATIC	= 4 : route installed by administrator
    //
    // Values >= RTPROT_STATIC are not interpreted by kernel, they are
    // just user-defined.
    print!("proto={} ", rm.rtm_protocol);

    // flags:
    // 	RTM_F_NOTIFY	= 0x100: notify user of route change
    // 	RTM_F_CLONED	= 0x200: this route is cloned
    // 	RTM_F_EQUALIZE	= 0x400: Multipath equalizer: NI
    // 	RTM_F_PREFIX	= 0x800: Prefix addresses
    print!("flags={:x} ", rm.rtm_flags);

    attributes_show_ip(rm.rtm_family as i32,
                       &RtattrTypeTbl::from_nlmsg(mem::size_of::<Rtmsg>(), nlh)?)?;
    println!("");

    Ok(CbStatus::Ok)
}

fn main() {
    let mut nl = Socket::open(Family::Route, 0)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(rtnetlink::RTMGRP_IPV4_ROUTE | rtnetlink::RTMGRP_IPV6_ROUTE,
            mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));

    let mut buf = mnl::default_buffer();
    loop {
        let nrecv = nl.recvfrom(&mut buf)
            .unwrap_or_else(|errno| panic!("mnl_socket_recvfrom: {}", errno));
        match mnl::cb_run(&buf[0..nrecv], 0, 0, Some(data_cb)) {
            Ok(CbStatus::Ok) => continue,
            Ok(CbStatus::Stop) => break,
            Err(errno) => panic!("mnl_cb_run: {}", errno),
        }
    }
}
