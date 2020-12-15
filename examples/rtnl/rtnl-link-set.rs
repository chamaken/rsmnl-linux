use std:: {
    env,
    time:: {SystemTime, UNIX_EPOCH}
};

extern crate rsmnl as mnl;
use mnl:: { MsgVec, Socket, };

extern crate rsmnl_linux as linux;
use linux:: {
    netlink,
    rtnetlink,
    rtnetlink::Ifinfomsg,
    if_link::Ifla,
    ifh,
};

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 3 {
        panic!("Usage: {} [ifname] [up|down]", args[0]);
    }

    let mut change: u32 = 0;
    let mut flags: u32 = 0;
    match args[2].to_lowercase().as_ref() {
        "up" => {
            change |= ifh::IFF_UP;
            flags |= ifh::IFF_UP;
        },
        "down" => {
            change |= ifh::IFF_UP;
            flags &= !ifh::IFF_UP;
        },
        _ => panic!("{} is not neither `up' nor `down'", args[2]),
    }

    let mut nl = Socket::open(netlink::Family::Route, 0)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));
    let portid = nl.portid();

    let seq = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;

    let mut nlv = MsgVec::new();
    let mut nlh = nlv.push_header();
    nlh.nlmsg_type = rtnetlink::RTM_NEWLINK;
    nlh.nlmsg_flags = netlink::NLM_F_REQUEST | netlink::NLM_F_ACK;
    nlh.nlmsg_seq = seq;
    let ifm: &mut Ifinfomsg = nlv.push_extra_header().unwrap();
    ifm.ifi_family = 0; // no libc::AF_UNSPEC;
    ifm.ifi_change = change;
    ifm.ifi_flags = flags;

    nlv.push_str(Ifla::Ifname, &args[1]).unwrap();
    // Ifla::put_ifname(&mut nlh, &args[1]).unwrap();

    nl.sendto(&nlv)
        .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));

    let mut buf = mnl::default_buffer();
    let nrecv = nl.recvfrom(&mut buf)
        .unwrap_or_else(|errno| panic!("mnl_socket_recvfrom: {}", errno));
    mnl::cb_run(&buf[0..nrecv], seq, portid, mnl::NOCB)
        .unwrap_or_else(|errno| panic!("mnl_cb_run: {}", errno));
}
