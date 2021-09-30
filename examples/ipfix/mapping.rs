#![allow(dead_code)]

use crate::msgfmt::IeIdentifier;
use once_cell::sync::Lazy;
use std::ops::{Index, IndexMut};

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum NfConntrackAttr {
    OrigIpv4Src = 0, // sourceIPv4Address(8)
    OrigIpv4Dst,     // destinationIPv4Address(12)
    ReplIpv4Src,     // postNATDestinationIPv4Address(225)
    ReplIpv4Dst,     // postNATSourceIPv4Address(226)
    OrigIpv6Src = 4, // sourceIPv6Address(27)
    OrigIpv6Dst,     // destinationIPv6Address(28)
    ReplIpv6Src,     // postNATDestinationIPv6Address(281)
    ReplIpv6Dst,     // postNATSourceIPv6Address(282)
    OrigPortSrc = 8, // sourceTransportPort(7)
    OrigPortDst,     // destinationTransportPort(11)
    ReplPortSrc,     // postNAPTDestinationTransportPort(228)
    ReplPortDst,     // postNAPTSourceTransportPort(227)
    IcmpType = 12,   // icmpTypeIPv4(176)
    IcmpCode,        // icmpCodeIPv4(177)
    IcmpId,
    Icmpv6Type,      // icmpTypeIPv6(178)
    Icmpv6Code = 16, // icmpCodeIPv6(179)
    Icmpv6Id,
    OrigL3proto, // ipVersion(60)
    ReplL3proto,
    OrigL4proto = 20, // protocolIdentifier(4)
    ReplL4proto,
    TcpState,
    SnatIpv4,
    DnatIpv4 = 24,
    SnatPort,
    DnatPort,
    Timeout,
    Mark = 28,
    OrigCounterPackets, // packetDeltaCount(2)
    ReplCounterPackets,
    OrigCounterBytes, // octetDeltaCount(1)
    ReplCounterBytes = 32,
    UseCount,
    Id, // flowId(148)
    Status,
    TcpFlagsOrig = 36,
    TcpFlagsRepl,
    TcpMaskOrig,
    TcpMaskRepl,
    MasterIpv4Src = 40,
    MasterIpv4Dst,
    MasterIpv6Src,
    MasterIpv6Dst,
    MasterPortSrc = 44,
    MasterPortDst,
    MasterL3proto,
    MasterL4proto,
    Secmark = 48,
    OrigNatSeqCorrectionPos,
    OrigNatSeqOffsetBefore,
    OrigNatSeqOffsetAfter,
    ReplNatSeqCorrectionPos = 52,
    ReplNatSeqOffsetBefore,
    ReplNatSeqOffsetAfter,
    SctpState,
    SctpVtagOrig = 56,
    SctpVtagRepl,
    HelperName,
    DccpState,
    DccpRole = 60,
    DccpHandshakeSeq,
    TcpWscaleOrig,
    TcpWscaleRepl,
    Zone = 64,
    Secctx,
    TimestampStart, // flowStartNanoseconds(156)
    TimestampStop,  // flowEndNanoseconds(157)
    HelperInfo = 68,
    Connlabels,
    ConnlabelsMask,
    OrigZone,
    ReplZone = 72,
    SnatIpv6,
    DnatIpv6,
    SynproxyIsn,
    SynproxyIts = 76,
    SynproxyTsoff,
    Max,
}

pub struct CtaMap<T>([Option<T>; NfConntrackAttr::Max as usize]);
impl<T> Index<NfConntrackAttr> for CtaMap<T> {
    type Output = Option<T>;

    fn index(&self, k: NfConntrackAttr) -> &Self::Output {
        &self.0[k as usize]
    }
}
impl<T> IndexMut<NfConntrackAttr> for CtaMap<T> {
    fn index_mut(&mut self, k: NfConntrackAttr) -> &mut Self::Output {
        &mut self.0[k as usize]
    }
}

pub static CTA_IE2: Lazy<CtaMap<(IeIdentifier, u16)>> = Lazy::new(|| {
    let mut cta_ie = CtaMap([None; NfConntrackAttr::Max as usize]);
    macro_rules! _s {
        ($cta: ident, $ie: ident, $len: expr) => {
            cta_ie[NfConntrackAttr::$cta] = Some((IeIdentifier::$ie, $len))
        };
    }

    _s!(OrigIpv4Src, SourceIPv4Address, 4);
    _s!(OrigIpv4Dst, DestinationIPv4Address, 4);
    _s!(ReplIpv4Src, PostNATDestinationIPv4Address, 4);
    _s!(ReplIpv4Dst, PostNATSourceIPv4Address, 4);
    _s!(OrigIpv6Src, SourceIPv6Address, 16);
    _s!(OrigIpv6Dst, DestinationIPv6Address, 16);
    _s!(ReplIpv6Src, PostNATDestinationIPv6Address, 16);
    _s!(ReplIpv6Dst, PostNATSourceIPv6Address, 16);
    _s!(OrigPortSrc, SourceTransportPort, 2);
    _s!(OrigPortDst, DestinationTransportPort, 2);
    _s!(ReplPortSrc, PostNAPTDestinationTransportPort, 2);
    _s!(ReplPortDst, PostNAPTSourceTransportPort, 2);
    _s!(IcmpType, IcmpTypeIPv4, 1);
    _s!(IcmpCode, IcmpCodeIPv4, 1);
    _s!(Icmpv6Type, IcmpTypeIPv6, 1);
    _s!(Icmpv6Code, IcmpCodeIPv6, 1);
    _s!(OrigL3proto, IpVersion, 1);
    _s!(OrigL4proto, ProtocolIdentifier, 1);
    _s!(OrigCounterPackets, PacketDeltaCount, 8);
    _s!(OrigCounterBytes, OctetDeltaCount, 8);
    _s!(Id, FlowId, 8);
    _s!(TimestampStart, FlowStartNanoseconds, 8);
    _s!(TimestampStop, FlowEndNanoseconds, 8);

    cta_ie
});
