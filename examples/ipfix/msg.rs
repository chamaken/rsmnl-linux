#![allow(dead_code)]
#![allow(unused_imports)]
use std::{
    collections::HashMap,
    marker::PhantomData,
    mem,
    time::{Duration, Instant},
};

use bit_vec::BitVec;
use chrono::{TimeZone, Utc};
use errno::Errno;
use once_cell::sync::Lazy;

use linux::netfilter::{nfnetlink::Nfgenmsg, nfnetlink_conntrack::CtattrTypeTbl};
use mnl::{AttrTbl, Msghdr};

use crate::mapping::{NfConntrackAttr, CTA_IE2};
use crate::msgfmt::{
    EnterpriseFieldSpecifier, IanaFieldSpecifier, MessageHeader, SetHeader, TemplateHeader,
};

#[derive(Clone)]
pub struct MsgVec<T>(Vec<u8>, PhantomData<T>);

impl<T: Sized> MsgVec<T> {
    fn vec(&mut self) -> &mut Vec<u8> {
        &mut self.0
    }

    pub fn bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn header(&self) -> &T {
        assert!(self.len() >= mem::size_of::<T>());
        unsafe { &(*(self.bytes().as_ptr() as *const _ as *const T)) }
    }

    pub fn header_mut(&mut self) -> &mut T {
        assert!(self.len() >= mem::size_of::<T>());
        unsafe { &mut (*(self.vec().as_mut_ptr() as *mut _ as *mut T)) }
    }

    fn put<U: Sized + Copy>(&mut self, v: &U) {
        let old_len = self.vec().len();
        let new_len = old_len + mem::size_of::<U>();
        self.vec().reserve(mem::size_of::<U>());
        unsafe {
            let ptr = self.vec().as_mut_ptr().offset(old_len as isize) as *mut _ as *mut U;
            *ptr = *v;
            self.vec().set_len(new_len);
        }
    }
}

pub type TemplateRecord = MsgVec<TemplateHeader>;
impl TemplateRecord {
    pub fn new(id: u16) -> Self {
        let mut ret = MsgVec(Vec::new(), PhantomData);
        ret.put(&TemplateHeader { id: id, count: 0 });
        ret
    }

    pub fn put_iana_field(&mut self, id: u16, len: u16) {
        self.put(&IanaFieldSpecifier {
            id: id,
            length: len,
        });
        let hdr = self.header_mut();
        hdr.count = u16::to_be(u16::from_be(hdr.count) + 1);
    }

    pub fn put_enterprise_field(&mut self, id: u16, len: u16, enterprise_num: u32) {
        self.put(&EnterpriseFieldSpecifier {
            id: id,
            length: len,
            enterprise_num: enterprise_num,
        });
        let hdr = self.header_mut();
        hdr.count = u16::to_be(u16::from_be(hdr.count) + 1);
    }
}

pub type Set = MsgVec<SetHeader>;
impl Set {
    pub fn new() -> Self {
        let mut ret = MsgVec(Vec::new(), PhantomData);
        ret.put(&SetHeader {
            id: 0,
            length: mem::size_of::<SetHeader>() as u16,
        });
        ret
    }

    pub fn put_template(&mut self, tr: &TemplateRecord) {
        self.vec().extend(tr.bytes());
        let len = self.len() as u16;
        let hdr = self.header_mut();
        hdr.length = u16::to_be(len);
    }

    pub fn put_data<T: Copy>(&mut self, data: &T) {
        self.put(data);
        let len = self.len() as u16;
        let hdr = self.header_mut();
        hdr.length = u16::to_be(len);
    }
}

pub type Message = MsgVec<MessageHeader>;
impl Message {
    pub fn new() -> Self {
        let mut ret = MsgVec(Vec::new(), PhantomData);
        ret.put(&MessageHeader {
            version: u16::to_be(0x000a),
            length: u16::to_be(mem::size_of::<MessageHeader>() as u16),
            export_time: 0,
            seq: 0,
            domain_id: 0,
        });
        ret
    }

    pub fn put_set(&mut self, sr: &Set) {
        self.vec().extend(sr.bytes());
        let len = self.len() as u16;
        let hdr = self.header_mut();
        hdr.length = u16::to_be(len);
    }
}

#[derive(Clone, Copy)]
struct TbRes<T, E: std::fmt::Debug>(Result<Option<T>, E>);
impl<T, E: std::fmt::Debug> TbRes<T, E> {
    pub fn e1(self) -> Option<T> {
        self.0.expect("may be a kernel bug")
    }

    pub fn e2(self) -> T {
        self.e1().expect("must have a value")
    }

    pub fn e3(self) -> T {
        self.e1().expect("nf_conntrack_acct must be enabled")
    }

    pub fn e4(self) -> T {
        self.e1().expect("nf_conntrack_timestamp must be enabled")
    }
}

/// https://stackoverflow.com/questions/30326600/how-to-encode-and-decode-64-bit-format-ntp-timestamp
/// https://commons.apache.org/proper/commons-net/javadocs/api-1.4.1/src-html/org/apache/commons/net/ntp/TimeStamp.html
const NSEC_PER_SEC: i64 = 1000_000_000;
static MSB1BASE_TIME: Lazy<i64> = Lazy::new(|| {
    Utc.ymd(1900, 1, 1)
        .and_hms_nano(0, 0, 0, 0)
        .timestamp_nanos()
});
static MSB0BASE_TIME: Lazy<i64> = Lazy::new(|| {
    Utc.ymd(2036, 2, 7)
        .and_hms_nano(6, 28, 16, 0)
        .timestamp_nanos()
});
fn to_ntp(be_nsec: u64) -> u64 {
    let nsec = u64::from_be(be_nsec);
    let use_base1 = (nsec as i64) < *MSB0BASE_TIME; // time < Feb-2036
    let base_time = if use_base1 {
        nsec as i64 - *MSB1BASE_TIME // dates <= Feb-2036
    } else {
        // if base0 needed for dates >= Feb-2036
        nsec as i64 - *MSB0BASE_TIME
    };

    let mut seconds = (base_time / NSEC_PER_SEC) as u32;
    let fraction = (((base_time % NSEC_PER_SEC) * 0x100000000) / NSEC_PER_SEC) as u32;
    if use_base1 {
        // set high-order bit if msb1baseTime 1900 used
        seconds |= 0x80000000;
    }

    ((u32::to_be(seconds) as u64) << 32) | u32::to_be(fraction) as u64
}

fn to_hts(ntp_ts: u64) -> u64 {
    let seconds = u32::from_be(((ntp_ts >> 32) & 0xffffffff) as u32);
    let mut fraction = u32::from_be((ntp_ts & 0xffffffff) as u32);
    fraction = ((fraction as f64 * 1000000000f64) / 4294967296f64) as u32;
    let msb = seconds & 0x80000000;
    let ts = if msb == 0 {
        *MSB0BASE_TIME
    } else {
        *MSB1BASE_TIME
    } + (seconds as i64 * NSEC_PER_SEC as i64)
        + fraction as i64;
    u64::to_be(ts as u64)
}

fn to_ip_version(family: &u8) -> u8 {
    if *family == libc::AF_INET6 as u8 {
        6
    } else {
        4
    }
}

impl Set {
    pub fn from_nlmsg(nlh: &Msghdr) -> Result<Option<(Self, BitVec)>, Errno> {
        let tb = CtattrTypeTbl::from_nlmsg(mem::size_of::<Nfgenmsg>(), nlh)?;

        // check whether counters is zero first
        let orig_cnt_tb = TbRes(tb.counters_orig()).e3();
        let repl_cnt_tb = TbRes(tb.counters_reply()).e3();
        if *TbRes(orig_cnt_tb.packets()).e3() == 0 && *TbRes(repl_cnt_tb.packets()).e3() == 0 {
            return Ok(None);
        }

        let nfg: &Nfgenmsg = nlh.payload()?;
        let mut sr = Set::new();
        let mut bv = BitVec::from_elem(NfConntrackAttr::Max as usize, false);

        let orig_tuple_tb = TbRes(tb.tuple_orig()).e2();
        let orig_ip_tb = TbRes(orig_tuple_tb.ip()).e2();
        if let Some(addr) = TbRes(orig_ip_tb.v4_src()).e1() {
            sr.put_data(addr);
            bv.set(NfConntrackAttr::OrigIpv4Src as usize, true);
        }
        if let Some(addr) = TbRes(orig_ip_tb.v4_dst()).e1() {
            sr.put_data(addr);
            bv.set(NfConntrackAttr::OrigIpv4Dst as usize, true);
        }

        let repl_tuple_tb = TbRes(tb.tuple_reply()).e2();
        let repl_ip_tb = TbRes(repl_tuple_tb.ip()).e2();
        if let Some(addr) = TbRes(repl_ip_tb.v4_src()).e1() {
            if Some(addr) != TbRes(orig_ip_tb.v4_dst()).e1() {
                sr.put_data(addr);
                bv.set(NfConntrackAttr::ReplIpv4Src as usize, true);
            }
        }
        if let Some(addr) = TbRes(repl_ip_tb.v4_dst()).e1() {
            if Some(addr) != TbRes(orig_ip_tb.v4_src()).e1() {
                sr.put_data(addr);
                bv.set(NfConntrackAttr::ReplIpv4Dst as usize, true);
            }
        }

        if let Some(addr) = TbRes(orig_ip_tb.v6_src()).e1() {
            sr.put_data(addr);
            bv.set(NfConntrackAttr::OrigIpv6Src as usize, true);
        }
        if let Some(addr) = TbRes(orig_ip_tb.v6_dst()).e1() {
            sr.put_data(addr);
            bv.set(NfConntrackAttr::OrigIpv6Dst as usize, true);
        }
        if let Some(addr) = TbRes(repl_ip_tb.v6_src()).e1() {
            if Some(addr) != TbRes(orig_ip_tb.v6_dst()).e1() {
                sr.put_data(addr);
                bv.set(NfConntrackAttr::ReplIpv6Src as usize, true);
            }
        }
        if let Some(addr) = TbRes(repl_ip_tb.v6_dst()).e1() {
            if Some(addr) != TbRes(orig_ip_tb.v6_src()).e1() {
                sr.put_data(addr);
                bv.set(NfConntrackAttr::ReplIpv6Dst as usize, true);
            }
        }

        if let Some(orig_proto_tb) = TbRes(orig_tuple_tb.proto()).e1() {
            if let Some(sport) = TbRes(orig_proto_tb.src_port()).e1() {
                sr.put_data(sport);
                bv.set(NfConntrackAttr::OrigPortSrc as usize, true);
            }
            if let Some(dport) = TbRes(orig_proto_tb.dst_port()).e1() {
                sr.put_data(dport);
                bv.set(NfConntrackAttr::OrigPortDst as usize, true);
            }

            if let Some(repl_proto_tb) = TbRes(repl_tuple_tb.proto()).e1() {
                if let Some(sport) = TbRes(repl_proto_tb.src_port()).e1() {
                    if TbRes(orig_proto_tb.dst_port()).e1() != Some(sport) {
                        sr.put_data(sport);
                        bv.set(NfConntrackAttr::ReplPortSrc as usize, true);
                    }
                }
                if let Some(dport) = TbRes(repl_proto_tb.dst_port()).e1() {
                    if TbRes(orig_proto_tb.src_port()).e1() != Some(dport) {
                        sr.put_data(dport);
                        bv.set(NfConntrackAttr::ReplPortDst as usize, true);
                    }
                }
            }

            if let Some(icmp_type) = TbRes(orig_proto_tb.icmp_type()).e1() {
                sr.put_data(icmp_type);
                bv.set(NfConntrackAttr::IcmpType as usize, true);
            }
            if let Some(icmp_code) = TbRes(orig_proto_tb.icmp_code()).e1() {
                sr.put_data(icmp_code);
                bv.set(NfConntrackAttr::IcmpCode as usize, true);
            }

            if let Some(icmpv6_type) = TbRes(orig_proto_tb.icmpv6_type()).e1() {
                sr.put_data(icmpv6_type);
                bv.set(NfConntrackAttr::Icmpv6Type as usize, true);
            }
            if let Some(icmpv6_code) = TbRes(orig_proto_tb.icmpv6_code()).e1() {
                sr.put_data(icmpv6_code);
                bv.set(NfConntrackAttr::Icmpv6Code as usize, true);
            }
        }

        sr.put_data(&to_ip_version(&nfg.nfgen_family));
        bv.set(NfConntrackAttr::OrigL3proto as usize, true);

        if let Some(orig_proto_tb) = TbRes(orig_tuple_tb.proto()).e1() {
            if let Some(proto) = TbRes(orig_proto_tb.num()).e1() {
                sr.put_data(proto);
                bv.set(NfConntrackAttr::OrigL4proto as usize, true);
            }
        }

        let orig_cnt_tb = TbRes(tb.counters_orig()).e3();
        let repl_cnt_tb = TbRes(tb.counters_reply()).e3();
        sr.put_data(TbRes(orig_cnt_tb.packets()).e3());
        bv.set(NfConntrackAttr::OrigCounterPackets as usize, true);
        sr.put_data(TbRes(repl_cnt_tb.packets()).e3());
        bv.set(NfConntrackAttr::ReplCounterPackets as usize, true);
        sr.put_data(TbRes(orig_cnt_tb.bytes()).e3());
        bv.set(NfConntrackAttr::OrigCounterBytes as usize, true);
        sr.put_data(TbRes(repl_cnt_tb.bytes()).e3());
        bv.set(NfConntrackAttr::ReplCounterBytes as usize, true);

        let id: u64 = *TbRes(tb.id()).e2() as u64;
        sr.put_data(&id);
        bv.set(NfConntrackAttr::Id as usize, true);

        let ts_tb = TbRes(tb.timestamp()).e4();
        if let Some(start) = TbRes(ts_tb.start()).e1() {
            sr.put_data(&to_ntp(*start));
            bv.set(NfConntrackAttr::TimestampStart as usize, true);
        }
        if let Some(stop) = TbRes(ts_tb.stop()).e1() {
            sr.put_data(&to_ntp(*stop));
            bv.set(NfConntrackAttr::TimestampStop as usize, true);
        }

        Ok(Some((sr, bv)))
    }

    pub fn from_bitvec(bv: &BitVec, id: u16) -> Self {
        let mut tmpl = TemplateRecord::new(id);
        macro_rules! bv2iana {
            ($bv: expr, $iana: expr, $len: expr) => {
                if bv[$bv] {
                    tmpl.put_iana_field(u16::to_be($iana), u16::to_be($len));
                }
            };
        }

        bv2iana!(0, 8, 4);
        bv2iana!(1, 12, 4);
        bv2iana!(2, 225, 4);
        bv2iana!(3, 226, 4);
        bv2iana!(4, 27, 16);
        bv2iana!(5, 28, 16);
        bv2iana!(6, 281, 16);
        bv2iana!(7, 282, 16);
        bv2iana!(8, 7, 2);
        bv2iana!(9, 11, 2);
        bv2iana!(10, 228, 2);
        bv2iana!(11, 227, 2);
        bv2iana!(12, 176, 1);
        bv2iana!(13, 177, 1);
        bv2iana!(15, 178, 1);
        bv2iana!(16, 179, 1);
        bv2iana!(18, 60, 1);
        bv2iana!(20, 4, 1);

        // counters, rfc5103 bidirection Reverse PEN
        bv2iana!(29, 2, 8);
        if bv[29] {
            tmpl.put_enterprise_field(u16::to_be(2 | 0x8000), u16::to_be(8), u32::to_be(29305));
        }
        bv2iana!(31, 1, 8);
        if bv[31] {
            tmpl.put_enterprise_field(u16::to_be(1 | 0x8000), u16::to_be(8), u32::to_be(29305));
        }

        bv2iana!(34, 148, 8);
        bv2iana!(66, 156, 8);
        bv2iana!(67, 157, 8);

        let mut sr = Set::new();
        let hdr = sr.header_mut();
        hdr.id = u16::to_be(2);
        sr.put_template(&tmpl);

        sr
    }

    pub fn from_bv(bv: &BitVec, id: u16) -> Self {
        let mut tmpl = TemplateRecord::new(id);

        macro_rules! _i {
            ($cta: ident) => {
                if bv[NfConntrackAttr::$cta as usize] {
                    // XXX: not unwrap() but expect() with nifty message
                    let (ie, len) = CTA_IE2[NfConntrackAttr::$cta].unwrap();
                    tmpl.put_iana_field(u16::to_be(ie as u16), u16::to_be(len));
                }
            };
        }
        // counters, rfc5103 bidirection Reverse PEN
        macro_rules! _r {
            ($cta: ident) => {
                if bv[NfConntrackAttr::$cta as usize] {
                    let (ie, len) = CTA_IE2[NfConntrackAttr::$cta].unwrap();
                    tmpl.put_enterprise_field(
                        u16::to_be(ie as u16 | 0x8000),
                        u16::to_be(len),
                        u32::to_be(29305),
                    );
                }
            };
        }

        _i!(OrigIpv4Src);
        _i!(OrigIpv4Dst);
        _i!(ReplIpv4Src);
        _i!(ReplIpv4Dst);
        _i!(OrigIpv6Src);
        _i!(OrigIpv6Dst);
        _i!(ReplIpv6Src);
        _i!(ReplIpv6Dst);
        _i!(OrigPortSrc);
        _i!(OrigPortDst);
        _i!(ReplPortSrc);
        _i!(ReplPortDst);
        _i!(IcmpType);
        _i!(IcmpCode);
        _i!(Icmpv6Type);
        _i!(Icmpv6Code);
        _i!(OrigL3proto);
        _i!(OrigL4proto);

        _i!(OrigCounterPackets);
        _r!(OrigCounterPackets);
        _i!(OrigCounterBytes);
        _r!(OrigCounterBytes);

        _i!(Id);
        _i!(TimestampStart);
        _i!(TimestampStop);

        let mut sr = Set::new();
        let hdr = sr.header_mut();
        hdr.id = u16::to_be(2);
        sr.put_template(&tmpl);

        sr
    }
}

// ---- Design decition ----
// template's SetRecord has only one template
pub struct SendTemplateFactory {
    template_id: u16,
    hmap: HashMap<BitVec, (Instant, u16, Set)>,
}

impl SendTemplateFactory {
    pub fn new() -> Self {
        Self {
            template_id: 256,
            hmap: HashMap::new(),
        }
    }

    pub fn once(&mut self, bv: &BitVec) -> (u16, Option<&Set>) {
        let now = Instant::now();
        let (_, id, sr) = self.hmap.entry(bv.clone()).or_insert((
            now,
            self.template_id,
            // Set::from_bitvec(&bv, u16::to_be(self.template_id)),
            Set::from_bv(&bv, u16::to_be(self.template_id)),
        ));
        if *id == self.template_id {
            self.template_id += 1;
            (*id, Some(sr))
        } else {
            (*id, None)
        }
    }

    pub fn beyond(&mut self, bv: &BitVec, duration: Duration) -> (u16, Option<&Set>) {
        // let duration = Duration::from_secs(300);
        let now = Instant::now();
        let (start, id, sr) = self.hmap.entry(bv.clone()).or_insert((
            now - duration,
            self.template_id,
            // Set::from_bitvec(&bv, u16::to_be(self.template_id)),
            Set::from_bv(&bv, u16::to_be(self.template_id)),
        ));
        if start.elapsed() < duration {
            (*id, None)
        } else {
            *start = now;
            if *id == self.template_id {
                self.template_id += 1;
            }
            (*id, Some(sr))
        }
    }
}
