use errno::Errno;
use libc;
use mnl::{Attr, AttrTbl, MsgVec, Result};
use std::net::{Ipv4Addr, Ipv6Addr};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Ndmsg {
    pub ndm_family: u8,
    pub ndm_pad1: u8,
    pub ndm_pad2: u16,
    pub ndm_ifindex: i32,
    pub ndm_state: u16,
    pub ndm_flags: u8,
    pub ndm_type: u8,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname = "NdaTbl"]
pub enum Nda {
    Unspec,

    #[nla_type(Ipv4Addr, v4dst)]
    #[nla_type(Ipv6Addr, v6dst)]
    Dst,

    #[nla_type(bytes, lladdr)]
    Lladdr,

    #[nla_type(NdaCacheinfo, cacheinfo)]
    Cacheinfo,

    #[nla_type(u32, probes)]
    Probes,

    #[nla_type(u16, vlan)]
    Vlan,

    #[nla_type(u16, port)]
    Port,

    #[nla_type(u32, vni)]
    Vni,

    #[nla_type(u32, ifindex)]
    Ifindex,

    #[nla_type(u32, master)]
    Master,

    #[nla_type(i32, link_netnsid)]
    LinkNetnsid,

    #[nla_type(u32, src_vni)]
    SrcVni,

    #[nla_type(u8, protocol)]
    Protocol,

    #[nla_type(u32, nh_id)]
    NhId,

    #[nla_nest(NfeaTbl, fdb_ext_attrs)]
    FdbExtAttrs,

    _MAX,
}

/*
 *	Neighbor Cache Entry Flags
 */
pub const NTF_USE: u8 = 0x01;
pub const NTF_SELF: u8 = 0x02;
pub const NTF_MASTER: u8 = 0x04;
pub const NTF_PROXY: u8		= 0x08	/* == ATF_PUBL */;
pub const NTF_EXT_LEARNED: u8 = 0x10;
pub const NTF_OFFLOADED: u8 = 0x20;
pub const NTF_STICKY: u8 = 0x40;
pub const NTF_ROUTER: u8 = 0x80;

/*
 *	Neighbor Cache Entry States.
 */
pub const NUD_INCOMPLETE: u8 = 0x01;
pub const NUD_REACHABLE: u8 = 0x02;
pub const NUD_STALE: u8 = 0x04;
pub const NUD_DELAY: u8 = 0x08;
pub const NUD_PROBE: u8 = 0x10;
pub const NUD_FAILED: u8 = 0x20;

// Dummy states
pub const NUD_NOARP: u8 = 0x40;
pub const NUD_PERMANENT: u8 = 0x80;
pub const NUD_NONE: u8 = 0x00;

/* NUD_NOARP & NUD_PERMANENT are pseudostates, they never change
 * and make no address resolution or NUD.
 * NUD_PERMANENT also cannot be deleted by garbage collectors.
 * When NTF_EXT_LEARNED is set for a bridge fdb entry the different cache entry
 * states don't make sense and thus are ignored. Such entries don't age and
 * can roam.
 */

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct NdaCacheinfo {
    pub ndm_confirmed: u32,
    pub ndm_used: u32,
    pub ndm_updated: u32,
    pub ndm_refcnt: u32,
}

/*****************************************************************
 *		Neighbour tables specific messages.
 *
 * To retrieve the neighbour tables send RTM_GETNEIGHTBL with the
 * NLM_F_DUMP flag set. Every neighbour table configuration is
 * spread over multiple messages to avoid running into message
 * size limits on systems with many interfaces. The first message
 * in the sequence transports all not device specific data such as
 * statistics, configuration, and the default parameter set.
 * This message is followed by 0..n messages carrying device
 * specific parameter sets.
 * Although the ordering should be sufficient, NDTA_NAME can be
 * used to identify sequences. The initial message can be identified
 * by checking for NDTA_CONFIG. The device specific messages do
 * not contain this TLV but have NDTPA_IFINDEX set to the
 * corresponding interface index.
 *
 * To change neighbour table attributes, send RTM_SETNEIGHTBL
 * with NDTA_NAME set. Changeable attribute include NDTA_THRESH[1-3],
 * NDTA_GC_INTERVAL, and all TLVs in NDTA_PARMS unless marked
 * otherwise. Device specific parameter sets can be changed by
 * setting NDTPA_IFINDEX to the interface index of the corresponding
 * device.
 ****/
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct NdtStats {
    pub ndts_allocs: u64,
    pub ndts_destroys: u64,
    pub ndts_hash_grows: u64,
    pub ndts_res_failed: u64,
    pub ndts_lookups: u64,
    pub ndts_hits: u64,
    pub ndts_rcv_probes_mcast: u64,
    pub ndts_rcv_probes_ucast: u64,
    pub ndts_periodic_gc_runs: u64,
    pub ndts_forced_gc_runs: u64,
    pub ndts_table_fulls: u64,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname = "NdtpaTbl"]
pub enum Ndtpa {
    Unspec,

    #[nla_type(u32, ifindex)]
    Ifindex, // u32

    #[nla_type(u32, refcnt)]
    Refcnt, // u32

    #[nla_type(u64, reachable_time)]
    ReachableTime, // u64

    #[nla_type(u64, base_reachable_time)]
    BaseReachableTime, // u64

    #[nla_type(u64, retrans_time)]
    RetransTime, // u64

    #[nla_type(u64, gc_staletime)]
    GcStaletime, // u64

    #[nla_type(u64, delay_probe_time)]
    DelayProbeTime, // u64

    #[nla_type(u64, queue_len)]
    QueueLen, // u32

    #[nla_type(u64, app_probes)]
    AppProbes, // u32

    #[nla_type(u32, ucast_probes)]
    UcastProbes, // u32

    #[nla_type(u32, mcast_probes)]
    McastProbes, // u32

    #[nla_type(u64, anycast_delay)]
    AnycastDelay, // u64

    #[nla_type(u64, proxy_delay)]
    ProxyDelay, // u64

    #[nla_type(u32, proxy_qlen)]
    ProxyQlen, // u32

    #[nla_type(u64, locktime)]
    Locktime, // u64

    #[nla_type(u32, queue_lenbytes)]
    QueueLenbytes, // u32

    #[nla_type(u32, mcast_reprobes)]
    McastReprobes, // u32

    PAD,
    _MAX,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Ndtmsg {
    pub ndtm_family: u8,
    pub ndtm_pad1: u8,
    pub ndtm_pad2: u16,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct NdtConfig {
    pub ndtc_key_len: u16,
    pub ndtc_entry_size: u16,
    pub ndtc_entries: u32,
    pub ndtc_last_flush: u32, // delta to now in msecs
    pub ndtc_last_rand: u32,
    pub ndtc_hash_rnd: u32,
    pub ndtc_hash_mask: u32,
    pub ndtc_hash_chain_gc: u32,
    pub ndtc_proxy_qlen: u32,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname = "NdtaTbl"]
pub enum Ndta {
    Unspec,

    #[nla_type(str, name)]
    Name,

    #[nla_type(u32, thresh1)]
    Thresh1,

    #[nla_type(u32, thresh2)]
    Thresh2,

    #[nla_type(u32, thresh3)]
    Thresh3,

    #[nla_type(NdtConfig, config)]
    Config,

    #[nla_nest(NdtpaTbl, parms)]
    Parms,

    #[nla_type(NdtStats, stats)]
    Stats,

    #[nla_type(u64, gc_interval)]
    GcInterval,
    Pad,
    _MAX,
}

// FDB activity notification bits used in NFEA_ACTIVITY_NOTIFY:
// - FDB_NOTIFY_BIT - notify on activity/expire for any entry
// - FDB_NOTIFY_INACTIVE_BIT - mark as inactive to avoid multiple notifications
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Fdb {
    NotifyBit = 1 << 0,
    NotifyInactiveBit = 1 << 1,
    _MAX,
}

// embedded into NDA_FDB_EXT_ATTRS:
// [NDA_FDB_EXT_ATTRS] = {
//     [NFEA_ACTIVITY_NOTIFY]
//     ...
// }
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname = "NfeaTbl"]
pub enum Nfea {
    Unspec,

    #[nla_type(u8, activity_notify)]
    ActivityNotify,

    #[nla_type(flag, dont_refresh)]
    DontRefresh,

    _MAX,
}
