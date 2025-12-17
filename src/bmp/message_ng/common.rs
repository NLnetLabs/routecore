use std::{fmt, net::{IpAddr, Ipv4Addr, Ipv6Addr}};

use chrono::{offset::LocalResult, DateTime, TimeZone, Utc};
use log::warn;
use zerocopy::{
    byteorder, FromBytes, Immutable, IntoBytes, KnownLayout, NetworkEndian, TryFromBytes
};


#[derive(IntoBytes, FromBytes, KnownLayout, Immutable)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Asn(byteorder::U32::<NetworkEndian>);
//impl From<byteorder::U32::<NetworkEndian>> for Asn {
//    fn from(value: byteorder::U32::<NetworkEndian>) -> Self {
//        Asn(value.into())
//    }
//}

impl Asn {
    pub fn from_u32(value: u32) -> Self {
        Self(byteorder::U32::<NetworkEndian>::from_bytes(value.to_be_bytes()))
    }
}

impl fmt::Display for Asn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AS{}", self.0)
    }
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct CommonHeader {
    pub version: u8,
    pub length: byteorder::U32<NetworkEndian>,
    pub msg_type: MessageType,
}

impl CommonHeader {
    pub fn length(&self) -> usize {
        // FIXME this pops up in flame graph
        usize::try_from(u32::from(self.length)).unwrap()
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct MessageType(u8);

impl MessageType {
    pub const ROUTE_MONITORING:         Self = Self(0);
    pub const STATISTICS_REPORT:        Self = Self(1);
    pub const PEER_DOWN_NOTIFICATION:   Self = Self(2);
    pub const PEER_UP_NOTIFICATION:     Self = Self(3);
    pub const INITIATION:               Self = Self(4);
    pub const TERMININATION:            Self = Self(5);
    pub const ROUTE_MIRRORING:          Self = Self(0);
}

#[derive(Eq, PartialEq, Ord, PartialOrd)]
#[derive(IntoBytes, FromBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct PerPeerHeaderV3 {
    pub peer_type: PeerType,
    pub flags: u8,
    pub distinguisher: [u8; 8],
    pub address: [u8; 16],
    pub asn: Asn,
    pub bgp_id: [u8; 4],
    pub timestamp_sec: byteorder::U32<NetworkEndian>,
    pub timestamp_usec: byteorder::U32<NetworkEndian>,
}

//pub type PerPeerHeader = PerPeerHeaderV3;

// XXX this is a non-standardized, imaginary Per Peer Header for BMP v4, merely here for trying out
// what the API could look like.
#[derive(IntoBytes, FromBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct PerPeerHeaderV4 {
    pub peer_type: PeerType,
    pub flags: u16,
    pub distinguisher: [u8; 8],
    pub address: [u8; 16],
    pub asn: Asn,
    pub bgp_id: [u8; 4],
    pub timestamp_sec: byteorder::U32<NetworkEndian>,
    pub timestamp_usec: byteorder::U32<NetworkEndian>,
}


#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct PeerType(u8);
impl PeerType {
    pub const GLOBAL_INSTANCE:      Self = Self(0);
    pub const RD_INSTANCE:          Self = Self(1);
    pub const LOCAL_INSTANCE:       Self = Self(2);
    pub const LOCAL_RIB_INSTANCE:   Self = Self(3);
    pub const RESERVED:             Self = Self(255);
}

impl From<PeerType> for u8 {
    fn from(value: PeerType) -> Self {
        value.0
    }
}

/// Specify which RIB the contents of a message originated from.
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum RibType {
    AdjRibIn,
    AdjRibOut,
    LocRib,
}


impl PerPeerHeaderV3 {
    pub fn without_type_and_flags(&self) -> &[u8] {
         //FIXME this also needs to strip out timestamps!!!
         // make a dedicated zerocopy struct for this
        &self.as_bytes()[2..34]
    }
    pub fn peer_type(&self) -> PeerType {
        self.peer_type
    }

    pub fn flags(&self) -> u8 {
        self.flags
    }

    pub fn distinguisher(&self) -> [u8; 8] {
        self.distinguisher
    }

    pub fn address(&self) -> IpAddr {
        if self.is_ipv4() {
            Ipv4Addr::new(
                self.address[12],
                self.address[13],
                self.address[14],
                self.address[15],
            )
            .into()
        } else {
            Ipv6Addr::from(self.address).into()
        }
    }

    pub fn asn(&self) -> Asn {
        self.asn
    }

    pub fn bgp_id(&self) -> [u8; 4] {
        self.bgp_id
    }

    pub fn ts_seconds(&self) -> u32 {
        self.timestamp_sec.into()
    }

    pub fn ts_micros(&self) -> u32 {
        self.timestamp_usec.into()
    }

    pub fn timestamp(&self) -> DateTime<Utc> {
        let s = self.ts_seconds() as i64;
        let us = self.ts_micros();
        if let LocalResult::Single(ts) = Utc.timestamp_opt(s, us * 1000) {
            ts
        } else {
            todo!("return error?");
            warn!(
                "invalid timestamp in Per-peer header: {}.{},\
                 returning epoch",
                s, us
            );
            DateTime::<Utc>::MIN_UTC
        }
    }

    /// Returns true if the IP Version bit is 0.
    pub fn is_ipv4(&self) -> bool {
        self.flags() & 0x80 == 0
    }

    /// Returns true if the IP Version bit is 1.
    pub fn is_ipv6(&self) -> bool {
        self.flags() & 0x80 == 0x80
    }

    /// Returns true if the L bit is 0.
    pub fn is_pre_policy(&self) -> bool {
        self.flags() & 0x40 == 0
    }

    /// Returns true if the A flags is 1.
    pub fn is_legacy_format(&self) -> bool {
        self.flags() & 0x20 == 0x20
    }

    /// Returns true if the L bit is 1.
    pub fn is_post_policy(&self) -> bool {
        self.flags() & 0x40 == 0x40
    }

    /// Returns the RIB type (Adj-RIB-In / Out) for this message.
    pub fn adj_rib_type(&self) -> RibType {
        match self.flags() & 0x10 == 0x10 {
            false => RibType::AdjRibIn,
            true => RibType::AdjRibOut,
        }
    }

    pub fn rib_type(&self) -> RibType {
        if self.peer_type() == PeerType::LOCAL_RIB_INSTANCE {
            RibType::LocRib
        } else {
            self.adj_rib_type()
        }
    }
}


//------------ TLV ------------------------------------------------------------

#[derive(TryFromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct Tlvs {
    raw: [u8],
}

impl Tlvs {
    pub fn iter<'a>(&'a self) -> TlvIterator<'a> {
        TlvIterator { raw: &self.raw }
    }
}

#[derive(TryFromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct RawTlv {
    t: byteorder::U16<NetworkEndian>,
    length: byteorder::U16<NetworkEndian>,
    value: [u8],
}

impl RawTlv {
    pub fn length(&self) -> usize {
        self.length.into()
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

#[repr(C, packed)]
pub struct TlvIterator<'a> {
    raw: &'a [u8],
}

impl<'a> Iterator for TlvIterator<'a> {
    type Item = &'a RawTlv;

    fn next(&mut self) -> Option<Self::Item> {
        if self.raw.is_empty() {
            return None;
        }
        let all = RawTlv::try_ref_from_bytes(self.raw).unwrap();
        let res = RawTlv::try_ref_from_bytes(
            &self.raw[..usize::from(4 + all.length)],
        )
        .unwrap();
        self.raw = &self.raw[usize::from(4 + res.length)..];
        Some(res)
    }
}

#[derive(TryFromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct IndexedTlvs {
    raw: [u8],
}

