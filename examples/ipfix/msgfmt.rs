#![allow(dead_code)]

// This header file defines structures for the IPFIX protocol in accordance with
// draft-ietf-ipfix-protocol-19.txt

pub const IPFIX_VENDOR_IETF: u32 = 0x00000000;

// defined in RFC 5103 IPFIX Biflow Export
pub const IPFIX_VENDOR_REVERSE: u32 = 29305;

// Section 3.1
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MessageHeader {
    pub version: u16,
    pub length: u16,
    pub export_time: u32,
    pub seq: u32,
    pub domain_id: u32,
}

// Section 3.3.2
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SetHeader {
    pub id: u16,
    pub length: u16,
}

// Section 3.4.1
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TemplateHeader {
    pub id: u16,
    pub count: u16,
}

// Section 3.2
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IanaFieldSpecifier {
    pub id: u16,
    pub length: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EnterpriseFieldSpecifier {
    pub id: u16,
    pub length: u16,
    pub enterprise_num: u32,
}

// Information Element Identifiers as of draft-ietf-ipfix-info-11.txt
#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum IeIdentifier {
    // reserved
    OctetDeltaCount = 1,
    PacketDeltaCount = 2,
    // reserved
    ProtocolIdentifier = 4,
    ClassOfServiceIPv4 = 5,
    TcpControlBits = 6,
    SourceTransportPort = 7,
    SourceIPv4Address = 8,
    SourceIPv4Mask = 9,
    IngressInterface = 10,
    DestinationTransportPort = 11,
    DestinationIPv4Address = 12,
    DestinationIPv4Mask = 13,
    EgressInterface = 14,
    IpNextHopIPv4Address = 15,
    BgpSourceAsNumber = 16,
    BgpDestinationAsNumber = 17,
    BgpNextHopIPv4Address = 18,
    PostMCastPacketDeltaCount = 19,
    PostMCastOctetDeltaCount = 20,
    FlowEndSysUpTime = 21,
    FlowStartSysUpTime = 22,
    PostOctetDeltaCount = 23,
    PostPacketDeltaCount = 24,
    MinimumPacketLength = 25,
    MaximumPacketLength = 26,
    SourceIPv6Address = 27,
    DestinationIPv6Address = 28,
    SourceIPv6Mask = 29,
    DestinationIPv6Mask = 30,
    FlowLabelIPv6 = 31,
    IcmpTypeCodeIPv4 = 32,
    IgmpType = 33,
    // reserved
    // reserved
    FlowActiveTimeOut = 36,
    FlowInactiveTimeout = 37,
    // reserved
    // reserved
    ExportedOctetTotalCount = 40,
    ExportedMessageTotalCount = 41,
    ExportedFlowTotalCount = 42,
    // reserved
    SourceIPv4Prefix = 44,
    DestinationIPv4Prefix = 45,
    MplsTopLabelType = 46,
    MplsTopLabelIPv4Address = 47,
    // reserved
    // reserved
    // reserved
    // reserved
    MinimumTtl = 52,
    MaximumTtl = 53,
    IdentificationIPv4 = 54,
    PostClassOfServiceIPv4 = 55,
    SourceMacAddress = 56,
    PostDestinationMacAddr = 57,
    VlanId = 58,
    PostVlanId = 59,
    IpVersion = 60,
    FlowDirection = 61,
    IpNextHopIPv6Address = 62,
    BgpNexthopIPv6Address = 63,
    Ipv6ExtensionHeaders = 64,
    // reserved
    // reserved
    // reserved
    // reserved
    // reserved
    MplsTopLabelStackEntry = 70,
    MplsLabelStackEntry2 = 71,
    MplsLabelStackEntry3 = 72,
    MplsLabelStackEntry4 = 73,
    MplsLabelStackEntry5 = 74,
    MplsLabelStackEntry6 = 75,
    MplsLabelStackEntry7 = 76,
    MplsLabelStackEntry8 = 77,
    MplsLabelStackEntry9 = 78,
    MplsLabelStackEntry10 = 79,
    DestinationMacAddress = 80,
    PostSourceMacAddress = 81,
    // reserved
    // reserved
    // reserved
    OctetTotalCount = 85,
    PacketTotalCount = 86,
    // reserved
    FragmentOffsetIPv4 = 88,
    // reserved
    BgpNextAdjacentAsNumber = 128,
    BgpPrevAdjacentAsNumber = 129,
    ExporterIPv4Address = 130,
    ExporterIPv6Address = 131,
    DroppedOctetDeltaCount = 132,
    DroppedPacketDeltaCount = 133,
    DroppedOctetTotalCount = 134,
    DroppedPacketTotalCount = 135,
    FlowEndReason = 136,
    ClassOfServiceIPv6 = 137,
    PostClassOfServiceIPv6 = 138,
    IcmpTypeCodeIPv6 = 139,
    MplsTopLabelIPv6Address = 140,
    LineCardId = 141,
    PortId = 142,
    MeteringProcessId = 143,
    ExportingProcessId = 144,
    TemplateId = 145,
    WlanChannelId = 146,
    WlanSsid = 147,
    FlowId = 148,
    SourceId = 149,
    FlowStartSeconds = 150,
    FlowEndSeconds = 151,
    FlowStartMilliseconds = 152,
    FlowEndMilliseconds = 153,
    FlowStartMicroseconds = 154,
    FlowEndMicroseconds = 155,
    FlowStartNanoseconds = 156,
    FlowEndNanoseconds = 157,
    FlowStartDeltaMicroseconds = 158,
    FlowEndDeltaMicroseconds = 159,
    SystemInitTimeMilliseconds = 160,
    FlowDurationMilliseconds = 161,
    FlowDurationMicroseconds = 162,
    ObservedFlowTotalCount = 163,
    IgnoredPacketTotalCount = 164,
    IgnoredOctetTotalCount = 165,
    NotSentFlowTotalCount = 166,
    NotSentPacketTotalCount = 167,
    NotSentOctetTotalCount = 168,
    DestinationIPv6Prefix = 169,
    SourceIPv6Prefix = 170,
    PostOctetTotalCount = 171,
    PostPacketTotalCount = 172,
    FlowKeyIndicator = 173,
    PostMCastPacketTotalCount = 174,
    PostMCastOctetTotalCount = 175,
    IcmpTypeIPv4 = 176,
    IcmpCodeIPv4 = 177,
    IcmpTypeIPv6 = 178,
    IcmpCodeIPv6 = 179,
    UdpSourcePort = 180,
    UdpDestinationPort = 181,
    TcpSourcePort = 182,
    TcpDestinationPort = 183,
    TcpSequenceNumber = 184,
    TcpAcknowledgementNumber = 185,
    TcpWindowSize = 186,
    TcpUrgentPointer = 187,
    TcpHeaderLength = 188,
    IpHeaderLength = 189,
    TotalLengthIPv4 = 190,
    PayloadLengthIPv6 = 191,
    IpTimeToLive = 192,
    NextHeaderIPv6 = 193,
    IpClassOfService = 194,
    IpDiffServCodePoint = 195,
    IpPrecedence = 196,
    FragmentFlagsIPv4 = 197,
    OctetDeltaSumOfSquares = 198,
    OctetTotalSumOfSquares = 199,
    MplsTopLabelTtl = 200,
    MplsLabelStackLength = 201,
    MplsLabelStackDepth = 202,
    MplsTopLabelExp = 203,
    IpPayloadLength = 204,
    UdpMessageLength = 205,
    IsMulticast = 206,
    InternetHeaderLengthIPv4 = 207,
    Ipv4Options = 208,
    TcpOptions = 209,
    PaddingOctets = 210,
    // reserved
    // reserved
    HeaderLengthIPv4 = 213,
    MplsPayloadLength = 214,

    // select usefuls from:
    // http://www.iana.org/assignments/ipfix/ipfix.txt
    PostNATSourceIPv4Address = 225,
    PostNATDestinationIPv4Address = 226,
    PostNAPTSourceTransportPort = 227,
    PostNAPTDestinationTransportPort = 228,
    FirewallEvent = 233,
    PostNATSourceIPv6Address = 281,
    PostNATDestinationIPv6Address = 282,
}

// defined in http://www.iana.org/assignments/enterprise-numbers
pub const IPFIX_VENDOR_NETFILTER: u32 = 21373;

// Information elements of the netfilter vendor id
pub enum NfIdentifier {
    Rawpacket = 1,       // pointer
    RawpacketLength = 2, // uint32_t
    Prefix = 3,          // string
    Mark = 4,            // uint32_t
    Hook = 5,            // uint8_t
    ConntrackId = 6,     // uint32_t
    SeqLocal = 7,        // uint32_t
    SeqGlobal = 8,       // uint32_t
}
