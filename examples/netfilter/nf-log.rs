use std::{env, mem, process, vec::Vec};

extern crate libc;

extern crate errno;
use errno::Errno;

extern crate rsmnl as mnl;
use mnl::{AttrTbl, CbResult, CbStatus, MsgVec, Msghdr, Socket};

extern crate rsmnl_linux as linux;
use linux::netfilter::{
    nfnetlink as nfnl,
    nfnetlink::Nfgenmsg,
    nfnetlink_log as nful,
    nfnetlink_log::{
        NfulnlAttrConfig, NfulnlAttrTypeTbl, NfulnlMsgConfigCmd, NfulnlMsgConfigCmds,
        NfulnlMsgConfigMode, NfulnlMsgPacketHdr, NfulnlMsgTypes,
    },
};

fn log_cb(nlh: &Msghdr) -> CbResult {
    let mut ph = &NfulnlMsgPacketHdr {
        hw_protocol: 0,
        hook: 0,
        _pad: 0,
    };
    let mut prefix = "";
    let mut mark: u32 = 0;

    let tb = NfulnlAttrTypeTbl::from_nlmsg(mem::size_of::<Nfgenmsg>(), nlh)?;
    tb.packet_hdr()?.map(|x| ph = x);
    tb.prefix()?.map(|x| prefix = x);
    tb.mark()?.map(|x| mark = *x);

    println!(
        "log received (prefix=\"{}\", hw=0x{:x}, hook={}, mark={})",
        prefix, ph.hw_protocol, ph.hook, mark
    );

    Ok(CbStatus::Ok)
}

fn nflog_build_cfg_pf_request(nlv: &mut MsgVec, command: u8) -> Result<(), Errno> {
    let mut nlh = nlv.put_header();
    nlh.nlmsg_type = (nfnl::NFNL_SUBSYS_ULOG << 8) | NfulnlMsgTypes::Config as u16;
    nlh.nlmsg_flags = libc::NLM_F_REQUEST as u16;

    let nfg = nlv.put_extra_header::<Nfgenmsg>()?;
    nfg.nfgen_family = libc::AF_INET as u8;
    nfg.version = libc::NFNETLINK_V0 as u8;

    let cmd = NfulnlMsgConfigCmd { command: command };
    // nlv.put(NfulnlAttrConfig::Cmd, &cmd)?;
    NfulnlAttrConfig::put_cmd(nlv, &cmd)?;

    Ok(())
}

fn nflog_build_cfg_request(nlv: &mut MsgVec, command: u8, qnum: u16) -> Result<(), Errno> {
    let mut nlh = nlv.put_header();
    nlh.nlmsg_type = (nfnl::NFNL_SUBSYS_ULOG << 8) | NfulnlMsgTypes::Config as u16;
    nlh.nlmsg_flags = libc::NLM_F_REQUEST as u16;

    let nfg = nlv.put_extra_header::<Nfgenmsg>()?;
    nfg.nfgen_family = libc::AF_INET as u8;
    nfg.version = libc::NFNETLINK_V0 as u8;
    nfg.res_id = qnum.to_be();

    let cmd = nful::NfulnlMsgConfigCmd { command: command };
    // nlv.put(NfulnlAttrConfig::Cmd, &cmd)?;
    NfulnlAttrConfig::put_cmd(nlv, &cmd)?;

    Ok(())
}

fn nflog_build_cfg_params(nlv: &mut MsgVec, mode: u8, range: u32, qnum: u16) -> Result<(), Errno> {
    let mut nlh = nlv.put_header();
    nlh.nlmsg_type = (nfnl::NFNL_SUBSYS_ULOG << 8) | NfulnlMsgTypes::Config as u16;
    nlh.nlmsg_flags = libc::NLM_F_REQUEST as u16;

    let nfg = nlv.put_extra_header::<Nfgenmsg>()?;
    nfg.nfgen_family = libc::AF_UNSPEC as u8;
    nfg.version = nfnl::NFNETLINK_V0;
    nfg.res_id = qnum.to_be();

    let params = NfulnlMsgConfigMode {
        copy_range: range.to_be(),
        copy_mode: mode,
        _pad: 0,
    };
    // nlv.put(NfulnlAttrConfig::Mode, &params)?;
    NfulnlAttrConfig::put_mode(nlv, &params)?;
    Ok(())
}

fn main() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} [queue_num]", args[0]);
        process::exit(libc::EXIT_FAILURE);
    }
    let qnum: u16 = args[1].trim().parse().expect("queue number required");

    let mut nl = Socket::open(libc::NETLINK_NETFILTER, 0)
        .map_err(|errno| format!("mnl_socket_open: {}", errno))?;

    nl.bind(0, mnl::SOCKET_AUTOPID)
        .map_err(|errno| format!("mnl_socket_bind: {}", errno))?;
    let portid = nl.portid();

    let mut nlv = MsgVec::new();
    nflog_build_cfg_pf_request(&mut nlv, NfulnlMsgConfigCmds::PfUnbind as u8)
        .map_err(|errno| format!("nflog_build_cfg_pf_request: {}", errno))?;

    nl.sendto(&nlv)
        .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;

    nlv.reset();
    nflog_build_cfg_pf_request(&mut nlv, NfulnlMsgConfigCmds::PfBind as u8)
        .map_err(|errno| format!("nflog_build_cfg_pf_request: {}", errno))?;

    nl.sendto(&nlv)
        .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;

    nlv.reset();
    nflog_build_cfg_request(&mut nlv, NfulnlMsgConfigCmds::Bind as u8, qnum)
        .map_err(|errno| format!("nflog_build_cfg_request: {}", errno))?;

    nl.sendto(&nlv)
        .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;

    nlv.reset();
    nflog_build_cfg_params(&mut nlv, nful::NFULNL_COPY_PACKET, 0xffff, qnum)
        .map_err(|errno| format!("nflog_build_cfg_params: {}", errno))?;

    nl.sendto(&nlv)
        .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;

    let mut buf = mnl::default_buffer();
    loop {
        let nrecv = nl
            .recvfrom(&mut buf)
            .map_err(|errno| format!("mnl_socket_recvfrom: {}", errno))?;
        mnl::cb_run(&buf[..nrecv], 0, portid, Some(log_cb))
            .map_err(|errno| format!("mnl_cb_run: {}", errno))?;
    }
}
