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
    nfnetlink_queue as nfqnl,
    nfnetlink_queue::{
        NfqnlAttrConfig, NfqnlAttrType, NfqnlAttrTypeTbl, NfqnlMsgConfigCmd, NfqnlMsgConfigParams,
        NfqnlMsgTypes, NfqnlMsgVerdictHdr,
    },
};

fn queue_cb(packet_id: &mut u32) -> impl FnMut(&Msghdr) -> CbResult + '_ {
    move |nlh: &Msghdr| {
        let tb = NfqnlAttrTypeTbl::from_nlmsg(mem::size_of::<Nfgenmsg>(), nlh)?;
        tb.packet_hdr()?.map(|ph| {
            *packet_id = u32::from_be(ph.packet_id);
            println!(
                "packet received (id={} hw=0x{:04x} hook={})",
                packet_id,
                u16::from_be(ph.hw_protocol),
                ph.hook
            );
        });
        Ok(CbStatus::Ok)
    }
}

fn nfq_build_cfg_pf_request(nlv: &mut MsgVec, command: u8) -> Result<(), Errno> {
    let mut nlh = nlv.put_header();
    nlh.nlmsg_type = (nfnl::NFNL_SUBSYS_QUEUE << 8) | NfqnlMsgTypes::Config as u16;
    nlh.nlmsg_flags = libc::NLM_F_REQUEST as u16;

    let nfg = nlv.put_extra_header::<Nfgenmsg>()?;
    nfg.nfgen_family = libc::AF_UNSPEC as u8;
    nfg.version = libc::NFNETLINK_V0 as u8;

    let cmd = NfqnlMsgConfigCmd {
        command: command,
        pf: libc::AF_INET.to_be() as u16,
        ..Default::default()
    };
    // nlv.put(NfqnlAttrConfig::Cmd, &cmd)?;
    NfqnlAttrConfig::put_cmd(nlv, &cmd)?;

    Ok(())
}

fn nfq_build_cfg_request(nlv: &mut MsgVec, command: u8, queue_num: u16) -> Result<(), Errno> {
    let mut nlh = nlv.put_header();
    nlh.nlmsg_type = (nfnl::NFNL_SUBSYS_QUEUE << 8) | NfqnlMsgTypes::Config as u16;
    nlh.nlmsg_flags = libc::NLM_F_REQUEST as u16;

    let nfg = nlv.put_extra_header::<Nfgenmsg>()?;
    nfg.nfgen_family = libc::AF_UNSPEC as u8;
    nfg.version = libc::NFNETLINK_V0 as u8;
    nfg.res_id = queue_num.to_be();

    let cmd = NfqnlMsgConfigCmd {
        command: command,
        pf: (libc::AF_INET as u16).to_be(),
        ..Default::default()
    };
    // nlv.put(NfqnlAttrConfig::Cmd, &cmd)?;
    NfqnlAttrConfig::put_cmd(nlv, &cmd)?;

    Ok(())
}

fn nfq_build_cfg_params(
    nlv: &mut MsgVec,
    mode: u8,
    range: u32,
    queue_num: u16,
) -> Result<(), Errno> {
    let mut nlh = nlv.put_header();
    nlh.nlmsg_type = (nfnl::NFNL_SUBSYS_QUEUE << 8) | NfqnlMsgTypes::Config as u16;
    nlh.nlmsg_flags = libc::NLM_F_REQUEST as u16;

    let nfg = nlv.put_extra_header::<Nfgenmsg>()?;
    nfg.nfgen_family = libc::AF_UNSPEC as u8;
    nfg.version = libc::NFNETLINK_V0 as u8;
    nfg.res_id = queue_num.to_be();

    let params = NfqnlMsgConfigParams {
        copy_range: range.to_be(),
        copy_mode: mode,
    };
    // nlv.put(NfqnlAttrConfig::Params, &params)?;
    NfqnlAttrConfig::put_params(nlv, &params)?;

    Ok(())
}

fn nfq_build_verdict(nlv: &mut MsgVec, id: u32, queue_num: u16, verd: u32) -> Result<(), Errno> {
    let mut nlh = nlv.put_header();
    nlh.nlmsg_type = (nfnl::NFNL_SUBSYS_QUEUE << 8) | NfqnlMsgTypes::Verdict as u16;
    nlh.nlmsg_flags = libc::NLM_F_REQUEST as u16;
    let nfg = nlv.put_extra_header::<Nfgenmsg>()?;
    nfg.nfgen_family = libc::AF_UNSPEC as u8;
    nfg.version = libc::NFNETLINK_V0 as u8;
    nfg.res_id = queue_num.to_be();

    let vh = NfqnlMsgVerdictHdr {
        verdict: verd.to_be(),
        id: id.to_be(),
    };
    // nlv.put(NfqnlAttrType::VerdictHdr, &vh)?;
    NfqnlAttrType::put_verdict_hdr(nlv, &vh)?;

    Ok(())
}

fn main() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} [queue_num]", args[0]);
        process::exit(libc::EXIT_FAILURE);
    }
    let queue_num: u16 = args[1].trim().parse().expect("queue number required");

    let mut nl = Socket::open(libc::NETLINK_NETFILTER, 0)
        .map_err(|errno| format!("mnl_socket_open: {}", errno))?;

    nl.bind(0, mnl::SOCKET_AUTOPID)
        .map_err(|errno| format!("mnl_socket_bind: {}", errno))?;
    let portid = nl.portid();

    let mut nlv = MsgVec::new();
    nfq_build_cfg_pf_request(&mut nlv, nfqnl::NFQNL_CFG_CMD_PF_UNBIND)
        .map_err(|errno| format!("nfq_build_cfg_pf_request: {}", errno))?;
    nl.sendto(&nlv)
        .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;

    nlv.reset();
    nfq_build_cfg_pf_request(&mut nlv, nfqnl::NFQNL_CFG_CMD_PF_BIND)
        .map_err(|errno| format!("nfq_build_cfg_pf_request: {}", errno))?;
    nl.sendto(&nlv)
        .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;

    nlv.reset();
    nfq_build_cfg_request(&mut nlv, nfqnl::NFQNL_CFG_CMD_BIND, queue_num)
        .map_err(|errno| format!("nfq_build_cfg_request: {}", errno))?;
    nl.sendto(&nlv)
        .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;

    nlv.reset();
    nfq_build_cfg_params(&mut nlv, nfqnl::NFQNL_COPY_PACKET, 0xFFFF, queue_num)
        .map_err(|errno| format!("nfq_build_cfg_params: {}", errno))?;
    nl.sendto(&nlv)
        .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;

    let mut buf = mnl::default_buffer();
    let mut id: u32 = 0;
    loop {
        let nrecv = nl
            .recvfrom(&mut buf)
            .map_err(|errno| format!("mnl_socket_recvfrom: {}", errno))?;
        mnl::cb_run(&buf[..nrecv], 0, portid, Some(queue_cb(&mut id)))
            .map_err(|errno| format!("mnl_cb_run: {}", errno))?;

        nlv.reset();
        nfq_build_verdict(&mut nlv, id, queue_num, libc::NF_ACCEPT as u32)
            .map_err(|errno| format!("nfq_build_verdict: {}", errno))?;
        nl.sendto(&nlv)
            .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;
    }
}
