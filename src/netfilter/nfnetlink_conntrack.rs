use errno::Errno;
use mnl::{Attr, AttrTbl, MsgVec, Result};
use netfilter::nf_conntrack_tcp::NfCtTcpFlags;
use std::net::{Ipv4Addr, Ipv6Addr};

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CtnlMsgTypes {
    // IPCTNL_MSG_
    New = 0,
    Get,
    Delete,
    GetCtrzero,
    GetStatsCpu,
    GetStats,
    GetDying,
    GetUnconfirmed,
    MAX,
}
pub const IPCTNL_MSG_CT_NEW: u16 = CtnlMsgTypes::New as u16;
pub const IPCTNL_MSG_CT_GET: u16 = CtnlMsgTypes::Get as u16;
pub const IPCTNL_MSG_CT_DELETE: u16 = CtnlMsgTypes::Delete as u16;
pub const IPCTNL_MSG_CT_GET_CTRZERO: u16 = CtnlMsgTypes::GetCtrzero as u16;
pub const IPCTNL_MSG_CT_GET_STATS_CPU: u16 = CtnlMsgTypes::GetStatsCpu as u16;
pub const IPCTNL_MSG_CT_GET_STATS: u16 = CtnlMsgTypes::GetStats as u16;
pub const IPCTNL_MSG_CT_GET_DYING: u16 = CtnlMsgTypes::GetDying as u16;
pub const IPCTNL_MSG_CT_GET_UNCONFIRMED: u16 = CtnlMsgTypes::GetUnconfirmed as u16;
pub const IPCTNL_MSG_MAX: u16 = CtnlMsgTypes::MAX as u16;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CtnlExpMsgTypes {
    // IPCTNL_MSG_EXP_
    New = 0,
    Get,
    Delete,
    GetStatsCpu,
    MAX,
}
pub const IPCTNL_MSG_EXP_NEW: u16 = CtnlExpMsgTypes::New as u16;
pub const IPCTNL_MSG_EXP_GET: u16 = CtnlExpMsgTypes::Get as u16;
pub const IPCTNL_MSG_EXP_DELETE: u16 = CtnlExpMsgTypes::Delete as u16;
pub const IPCTNL_MSG_EXP_GET_STATS_CPU: u16 = CtnlExpMsgTypes::GetStatsCpu as u16;
pub const IPCTNL_MSG_EXP_MAX: u16 = CtnlExpMsgTypes::MAX as u16;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname = "CtattrTypeTbl"]
pub enum CtattrType {
    // CTA_
    Unspec = 0,

    #[nla_nest(CtattrTupleTbl, tuple_orig)]
    TupleOrig,

    #[nla_nest(CtattrTupleTbl, tuple_reply)]
    TupleReply,

    #[nla_type(u32, status)] // big endian
    Status,

    #[nla_nest(CtattrProtoinfoTbl, protoinfo)]
    Protoinfo,

    #[nla_nest(CtattrHelpTbl, help)]
    Help,

    NatSrc,

    #[nla_type(u32, timeout)] // big endian
    Timeout,

    #[nla_type(u32, mark)] // big endian
    Mark,

    #[nla_nest(CtattrCountersTbl, counters_orig)]
    CountersOrig,

    #[nla_nest(CtattrCountersTbl, counters_reply)]
    CountersReply,

    #[nla_type(u32, use_count)]
    Use,

    #[nla_type(u32, id)]
    Id,

    NatDst,

    #[nla_nest(CtattrTupleTbl, tuple_master)]
    TupleMaster,

    #[nla_nest(CtattrSeqadjTbl, seq_adj_orig)]
    SeqAdjOrig,

    #[nla_nest(CtattrSeqadjTbl, seq_adj_reply)]
    SeqAdjReply,

    #[nla_type(u32, secmark)]
    Secmark, // obsolete

    #[nla_type(u16, zone)]
    Zone,

    #[nla_nest(CtattrSecctxTbl, secctx)]
    Secctx,

    #[nla_nest(CtattrTstampTbl, timestamp)]
    Timestamp,

    #[nla_type(u32, mark_mask)]
    MarkMask,

    #[nla_type(bytes, labels)]
    Labels,

    #[nla_type(bytes, labels_mask)]
    LabelsMask,

    #[nla_nest(CtattrSynproxyTbl, synproxy)]
    Synproxy,

    Filter,
    _MAX,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname = "CtattrTupleTbl"]
pub enum CtattrTuple {
    // CTA_TUPLE_
    Unspec = 0,

    #[nla_nest(CtattrIpTbl, ip)]
    Ip,

    #[nla_nest(CtattrL4ProtoTbl, proto)]
    Proto,

    #[nla_type(u16, zone)]
    Zone,

    _MAX,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname = "CtattrIpTbl"]
pub enum CtattrIp {
    // CTA_IP_
    Unspec = 0,

    #[nla_type(Ipv4Addr, v4_src)]
    V4Src,

    #[nla_type(Ipv4Addr, v4_dst)]
    V4Dst,

    #[nla_type(Ipv6Addr, v6_src)]
    V6Src,

    #[nla_type(Ipv6Addr, v6_dst)]
    V6Dst,

    _MAX,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname = "CtattrL4ProtoTbl"]
pub enum CtattrL4proto {
    // CTA_PROTO_
    Unspec = 0,

    #[nla_type(u8, num)]
    Num,

    #[nla_type(u16, src_port)] // big endian
    SrcPort,

    #[nla_type(u16, dst_port)] // big endian
    DstPort,

    #[nla_type(u16, icmp_id)] // big endian
    IcmpId,

    #[nla_type(u8, icmp_type)]
    IcmpType,

    #[nla_type(u8, icmp_code)]
    IcmpCode,

    #[nla_type(u16, icmpv6_id)] // big endian
    Icmpv6Id,

    #[nla_type(u8, icmpv6_type)]
    Icmpv6Type,

    #[nla_type(u8, icmpv6_code)]
    Icmpv6Code,
    _MAX,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname = "CtattrProtoinfoTbl"]
pub enum CtattrProtoinfo {
    // CTA_PROTOINFO_
    Unspec = 0,

    #[nla_nest(CtattrProtoinfoTcpTbl, tcp)]
    Tcp,

    #[nla_nest(CtattrProtoinfoDccpTbl, dccp)]
    Dccp,

    #[nla_nest(CtattrProtoinfoSctpTbl, sctp)]
    Sctp,
    _MAX,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname = "CtattrProtoinfoTcpTbl"]
pub enum CtattrProtoinfoTcp {
    // CTA_PROTOINFO_TCP_
    Unspec = 0,

    #[nla_type(u8, state)]
    State,

    #[nla_type(u8, wscale_original)]
    WscaleOriginal,

    #[nla_type(u8, wscale_reply)]
    WscaleReply,

    #[nla_type(NfCtTcpFlags, flags_original)]
    FlagsOriginal,

    #[nla_type(NfCtTcpFlags, flags_reply)]
    FlagsReply,
    _MAX,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname = "CtattrProtoinfoDccpTbl"]
pub enum CtattrProtoinfoDccp {
    // CTA_PROTOINFO_DCCP_
    Unspec = 0,

    #[nla_type(u8, state)]
    State,

    #[nla_type(u8, role)]
    Role,

    #[nla_type(u64, handshake_seq)]
    HandshakeSeq,

    Pad,
    _MAX,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname = "CtattrProtoinfoSctpTbl"]
pub enum CtattrProtoinfoSctp {
    // CTA_PROTOINFO_SCTP_
    Unspec = 0,

    #[nla_type(u8, state)]
    State,

    #[nla_type(u32, vtag_original)]
    VtagOriginal,

    #[nla_type(u32, vtag_reply)]
    VtagReply,

    _MAX,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname = "CtattrCountersTbl"]
pub enum CtattrCounters {
    // CTA_COUNTERS_
    Unspec = 0,

    #[nla_type(u64, packets)]
    Packets, // 64bit counters

    #[nla_type(u64, bytes)]
    Bytes, // 64bit counters

    Packets32, // old 32bit counters, unused, XXX: 32Packets
    Bytes32,   // old 32bit counters, unused, XXX: 32Bytes
    Pad,
    _MAX,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname = "CtattrTstampTbl"]
pub enum CtattrTstamp {
    // CTA_TIMESTAMP_
    Unspec = 0,

    #[nla_type(u64, start)]
    Start = 1,

    #[nla_type(u64, stop)]
    Stop = 2,

    Pad = 3,
    _MAX = 4,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname = "CtattrNatTbl"]
pub enum CtattrNat {
    // CTA_NAT_
    Unspec = 0,

    #[nla_type(Ipv4Addr, v4_minip)]
    V4Minip,

    #[nla_type(Ipv4Addr, v4_maxip)]
    V4Maxip,

    #[nla_nest(CtattrProtonatTbl, proto)]
    Proto,

    #[nla_type(Ipv6Addr, v6_minip)]
    V6Minip,

    #[nla_type(Ipv6Addr, v6_maxip)]
    V6Maxip,

    _MAX,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname = "CtattrProtonatTbl"]
pub enum CtattrProtonat {
    // CTA_PROTONAT_
    Unspec = 0,

    #[nla_type(u16, port_min)]
    PortMin = 1,

    #[nla_type(u16, port_max)]
    PortMax = 2,

    _MAX = 3,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname = "CtattrSeqadjTbl"]
pub enum CtattrSeqadj {
    // CTA_SEQADJ_
    Unspec = 0,

    #[nla_type(u32, correction_pos)]
    CorrectionPos,

    #[nla_type(u32, offset_before)]
    OffsetBefore,

    #[nla_type(u32, offset_after)]
    OffsetAfter,

    _MAX,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname = "CtattrNatseqTbl"]
pub enum CtattrNatseq {
    // CTA_NAT_SEQ_
    Unspec = 0,
    CorrectionPos,
    OffsetBefore,
    OffsetAfter,
    _MAX,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname = "CtattrSynproxyTbl"]
pub enum CtattrSynproxy {
    // CTA_SYNPROXY_
    Unspec = 0,

    #[nla_type(u32, isn)]
    Isn,

    #[nla_type(u32, its)]
    Its,

    #[nla_type(u32, tsoff)]
    Tsoff,

    _MAX,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname = "CtattrExpectTbl"]
pub enum CtattrExpect {
    // CTA_EXPECT_
    Unspec = 0,

    #[nla_nest(CtattrTupleTbl, master)]
    Master,

    #[nla_nest(CtattrTupleTbl, tuple)]
    Tuple,

    #[nla_nest(CtattrTupleTbl, mask)]
    Mask,

    #[nla_type(u32, timeout)]
    Timeout,

    #[nla_type(u32, id)]
    Id,

    #[nla_type(str, help_name)]
    HelpName,

    #[nla_type(u16, zone)]
    Zone,

    #[nla_type(u32, flags)]
    Flags,

    #[nla_type(u32, class)]
    Class,

    #[nla_nest(CtattrExpectNatTbl, nat)]
    Nat,

    #[nla_type(cstr, expfn)]
    Fn,

    _MAX,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname = "CtattrExpectNatTbl"]
pub enum CtattrExpectNat {
    // CTA_EXPECT_NAT_
    Unspec = 0,

    #[nla_type(u32, dir)]
    Dir,

    #[nla_nest(CtattrTupleTbl, tuple)]
    Tuple,

    _MAX,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname = "CtattrHelpTbl"]
pub enum CtattrHelp {
    // CTA_HELP_
    Unspec = 0,

    #[nla_type(str, name)]
    Name,

    #[nla_type(bytes, info)]
    Info,

    _MAX,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname = "CtattrSecctxTbl"]
pub enum CtattrSecctx {
    // CTA_SECCTX_
    Unspec = 0,

    #[nla_type(str, name)]
    Name,

    _MAX,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname = "CtattrStatsCpuTbl"]
pub enum CtattrStatsCpu {
    // CTA_STATS_
    Unspec,
    Searched, // no longer used

    #[nla_type(u32, found)]
    Found,

    New, // no longer used

    #[nla_type(u32, invalid)]
    Invalid,

    Ignore,
    Delete,     // no longer used
    DeleteList, // no longer used

    #[nla_type(u32, insert)]
    Insert,

    #[nla_type(u32, insert_failed)]
    InsertFailed,

    #[nla_type(u32, drop)]
    Drop,

    #[nla_type(u32, early_drop)]
    EarlyDrop,

    #[nla_type(u32, stats_error)]
    StatsError, // note: `#[deny(ambiguous_associated_items)]` on by default

    #[nla_type(u32, search_restart)]
    SearchRestart,

    #[nla_type(u32, clash_resolve)]
    CrashResolve,

    _MAX,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname = "CtattrStatsGlobalTbl"]
pub enum CtattrStatsGlobal {
    // CTA_STATS_GLOBAL_
    Unspec = 0,

    #[nla_type(u32, entries)]
    Entries,

    #[nla_type(u32, max_entries)]
    MaxEntries,

    _MAX,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname = "CtattrExpectStatsTbl"]
pub enum CtattrExpectStats {
    // CTA_STATS_EXP_
    Unspec = 0,

    #[nla_type(u32, new)]
    New,

    #[nla_type(u32, create)]
    Create,

    #[nla_type(u32, delete)]
    Delete,

    _MAX,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname = "CtattrFilterTbl"]
pub enum CtattrFilter {
    // CTA_FILTER_
    Unspec = 0,

    #[nla_type(u32, orig_flags)]
    OrigFlags,

    #[nla_type(u32, reply_flags)]
    ReplyFlags,

    _MAX,
}

// XXX: copy only NF_NETLINK_ from nfnetlink_compat.h
//
// Old nfnetlink macros for userspace
// nfnetlink groups: Up to 32 maximum
pub const NF_NETLINK_CONNTRACK_NEW: u32 = 0x00000001;
pub const NF_NETLINK_CONNTRACK_UPDATE: u32 = 0x00000002;
pub const NF_NETLINK_CONNTRACK_DESTROY: u32 = 0x00000004;
pub const NF_NETLINK_CONNTRACK_EXP_NEW: u32 = 0x00000008;
pub const NF_NETLINK_CONNTRACK_EXP_UPDATE: u32 = 0x00000010;
pub const NF_NETLINK_CONNTRACK_EXP_DESTROY: u32 = 0x00000020;
