//! BMP message parsing.
//!
//! This module contains functionality to parse BGP messages from raw bytes,
//! providing access to its contents based on the underlying `bytes` buffer
//! without allocating.

use crate::asn::Asn;
use crate::bgp::message::{Message as BgpMsg, OpenMessage as BgpOpen, UpdateMessage as BgpUpdate, NotificationMessage as BgpNotification};
use crate::bgp::message::{AFI, SAFI, SessionConfig};
use crate::util::parser::ParseError;
use crate::typeenum; // from util::macros

use bytes::Buf;
use chrono::{DateTime, TimeZone, Utc};
use log::warn;
use octseq::{OctetsRef, Parser};


use std::error::Error;
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::hash::Hash;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};


// --- Error stuff, refactor this crate-wide after bgmp is merged ------------

/// Errors related to BMP messages.
#[derive(Debug)]
pub enum MessageError {
    Incomplete,
    IllegalSize,
    InvalidMsgType,
}

impl Display for MessageError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        use MessageError::*;
        match self {
            Incomplete => write!(f, "incomplete message"),
            IllegalSize => write!(f, "illegaly sized message"),
            InvalidMsgType => write!(f, "invalid message type"),
        }
    }
}

impl Error for MessageError { }


/// Full BMP message.
/// 
/// The [`Message`] enum carries variants representing the full BMP Messages,
/// including the [`CommonHeader`], possibly a [`PerPeerHeader`] and the
/// additional payload. The payload often comprises one or multiple
/// [`bgp::Message`](crate::bgp::Message)s.

pub enum Message<Octets: AsRef<[u8]>> {
    RouteMonitoring(RouteMonitoring<Octets>),
    StatisticsReport(StatisticsReport<Octets>),
    PeerDownNotification(PeerDownNotification<Octets>),
    PeerUpNotification(PeerUpNotification<Octets>),
    InitiationMessage(InitiationMessage<Octets>),
    TerminationMessage(TerminationMessage<Octets>),
    RouteMirroring(RouteMirroring<Octets>),
}


typeenum!(
    /// Types of BMP messages as defined in
    /// [RFC7854](https://datatracker.ietf.org/doc/html/rfc7854).
    MessageType, u8,
    0 => RouteMonitoring,
    1 => StatisticsReport,
    2 => PeerDownNotification,
    3 => PeerUpNotification,
    4 => InitiationMessage,
    5 => TerminationMessage,
    6 => RouteMirroring,
);


impl<Octets: AsRef<[u8]>> AsRef<[u8]> for InitiationMessage<Octets> {
    fn as_ref(&self) -> &[u8] {
        self.octets.as_ref()
    }
}

impl<Octets: AsRef<[u8]>> AsRef<[u8]> for TerminationMessage<Octets> {
    fn as_ref(&self) -> &[u8] {
        self.octets.as_ref()
    }
}


impl<Octets: AsRef<[u8]>> AsRef<[u8]> for StatisticsReport<Octets> {
    fn as_ref(&self) -> &[u8] {
        self.octets.as_ref()
    }
}

impl<Octets: AsRef<[u8]>> AsRef<[u8]> for PeerUpNotification<Octets> {
    fn as_ref(&self) -> &[u8] {
        self.octets.as_ref()
    }
}

impl<Octets: AsRef<[u8]>> AsRef<[u8]> for PeerDownNotification<Octets> {
    fn as_ref(&self) -> &[u8] {
        self.octets.as_ref()
    }
}

impl<Octets: AsRef<[u8]>> AsRef<[u8]> for RouteMonitoring<Octets> {
    fn as_ref(&self) -> &[u8] {
        self.octets.as_ref()
    }
}
impl<Octets: AsRef<[u8]>> AsRef<[u8]> for RouteMirroring<Octets> {
    fn as_ref(&self) -> &[u8] {
        self.octets.as_ref()
    }
}

//--- Parsing and impl of the Message enum wrapper ---------------------------

impl<Octets: AsRef<[u8]>> Message<Octets> {
    fn parse<R>(parser: &mut Parser<R>) -> Result<Self, ParseError>
    where
        R: OctetsRef<Range = Octets>,
        for<'a> &'a Octets: OctetsRef
    {
        let pos = parser.pos();
        let ch = CommonHeader::parse(parser)?;
        parser.seek(pos)?;
        let res = 
            match ch.msg_type() {
                MessageType::RouteMonitoring =>
                    Message::RouteMonitoring(RouteMonitoring::parse(parser)?),
                MessageType::StatisticsReport =>
                    Message::StatisticsReport(StatisticsReport::parse(parser)?),
                MessageType::PeerDownNotification =>
                    Message::PeerDownNotification(PeerDownNotification::parse(parser)?),
                MessageType::PeerUpNotification =>
                    Message::PeerUpNotification(PeerUpNotification::parse(parser)?),
                MessageType::InitiationMessage =>
                    Message::InitiationMessage(InitiationMessage::parse(parser)?),
                MessageType::TerminationMessage =>
                    Message::TerminationMessage(TerminationMessage::parse(parser)?),
                MessageType::RouteMirroring =>
                    Message::RouteMirroring(RouteMirroring::parse(parser)?),
                MessageType::Unimplemented(_) => {
                    return Err(ParseError::form_error(
                            "Unimplemented BMP message type"
                    ));
                }
            };
        Ok(res)
    }
}

impl<Octets: AsRef<[u8]>> Message<Octets>
where
    for <'a> &'a Octets: OctetsRef,
{
    pub fn check(src: &mut Cursor<&[u8]>) -> Result<u32, MessageError> {
        if src.remaining() >= 5 {
            let _version = src.get_u8();
			let len = src.get_u32();
            if len <= 6 {
                return Err(MessageError::IllegalSize)
            }
            if src.remaining() >= ((len as usize) - 5) {
                return Ok(len);
            }
        }
        Err(MessageError::Incomplete)
    }

    pub fn from_octets<Source: AsRef<[u8]>>(octets: Source)
        -> Result<Message<Octets>, ParseError>
    where
        for <'a> &'a Source: OctetsRef<Range = Octets>,
    {
        let mut parser = Parser::from_ref(&octets);
        Self::parse(&mut parser)
    }
}
impl<Octets: AsRef<[u8]>> Message<Octets>
where
    for <'x> &'x Octets: OctetsRef,
{
    /// Return the [`CommonHeader`] for this message.
    pub fn common_header(&self)
        -> CommonHeader<<&Octets as OctetsRef>::Range>
    //where
    //    &'s Octets: OctetsRef
    {
        match self {
            Message::RouteMonitoring(m) => m.common_header(),
            Message::StatisticsReport(m) => m.common_header(),
            Message::PeerDownNotification(m) => m.common_header(),
            Message::PeerUpNotification(m) => m.common_header(),
            Message::InitiationMessage(m) => m.common_header(),
            Message::TerminationMessage(m) => m.common_header(),
            Message::RouteMirroring(m) => m.common_header(),
        }
        //*CommonHeader::for_message_slice(r)
        //CommonHeader::for_slice(&r.octets.range_to(6))
    }

    /// Return the length of the message, including headers.
	pub fn length(&self) -> u32 {
		self.common_header().length()
	}

    /// Return the BMP version of the message.
	pub fn version(self) -> u8 {
		self.common_header().version()
	}

    /// Return the message type.
    pub fn msg_type(&self) -> MessageType {
        self.common_header().msg_type()
    }
}

impl<Octets: AsRef<[u8]>> Display for Message<Octets> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Message::RouteMonitoring(_) => write!(f, "RouteMonitoring"),
            Message::StatisticsReport(_) => write!(f, "StatisticsReport"),
            Message::PeerDownNotification(_) => write!(f, "PeerDownNotification"),
            Message::PeerUpNotification(_) => write!(f, "PeerUpNotification"),
            Message::InitiationMessage(_) => write!(f, "InitiationMessage"),
            Message::TerminationMessage(_) => write!(f, "TerminationMessage"),
            Message::RouteMirroring(_) => write!(f, "RouteMirroring"),
        }
    }
}

impl<Octets: AsRef<[u8]>> Debug for Message<Octets>
where
    for <'a> &'a Octets: OctetsRef
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let _ = writeln!(f, "{:?} ({})",
            &self.common_header().msg_type(),
            &self.common_header().length()
        );
        write!(f, "{:02x?}", &self.as_ref()[0..self.length() as usize])
    }
}

impl<Octets: AsRef<[u8]>> AsRef<[u8]> for Message<Octets> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Message::RouteMonitoring(m) => m.as_ref(),
            Message::StatisticsReport(m) => m.as_ref(),
            Message::PeerDownNotification(m) => m.as_ref(),
            Message::PeerUpNotification(m) => m.as_ref(),
            Message::InitiationMessage(m) => m.as_ref(),
            Message::TerminationMessage(m) => m.as_ref(),
            Message::RouteMirroring(m) => m.as_ref(),
        }
    }
}

//--- The Common and Per Peer header -----------------------------------------

/// The Common Header of a BMP message.
///
/// Every BMP message type starts with the so called Common Header, providing
/// the BMP version, length, and type of the BMP message.
///
/// For convenience, the fields in the Common Header are available via methods
/// on `Message` directly.
///
//--- BMP Common Header  -----------------------------------------------------
// As per RFC7854:
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+
//  |    Version    |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                        Message Length                         |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |   Msg. Type   |
//  +---------------+

#[derive(Clone, Copy, Debug, Eq, Default, PartialEq)]
pub struct CommonHeader<Octets> {
	octets: Octets
}

impl<Octets: AsRef<[u8]>> CommonHeader<Octets> {
    fn for_slice(s: Octets) -> Self {
        CommonHeader { octets: s }
    }

    //fn for_message_slice(s: &[u8]) -> &Self {
    //    assert!(s.len() >= 6);
    //    unsafe { &*(s.as_ptr() as *const CommonHeader) } // FIXME
    //}

    /// Returns the BMP version of the message.
	pub fn version(self) -> u8 {
		self.octets.as_ref()[0]
	}

    /// Returns the length of the message, including headers.
	pub fn length(&self) -> u32 {
		u32::from_be_bytes(self.octets.as_ref()[1..5].try_into().unwrap())
	}

    /// Returns the message type.
    pub fn msg_type(&self) -> MessageType {
        self.octets.as_ref()[5].into()
    }

}

impl<Octets: AsRef<[u8]>> CommonHeader<Octets> {
    fn parse<R>(parser: &mut Parser<R>) -> Result<Self, ParseError>
    where
        R: OctetsRef<Range = Octets>
    {
        // TODO check validity of version, length and msg type
        Ok (
            CommonHeader {
                octets: parser.parse_octets(6)?
            }
        )
    }
}


/// The Per Peer Header, present in some BMP messages.
///
/// BMP messages often contain encapsulated BGP messages. The Per Peer Header
/// provides information on the peer that sent that encapsulated BGP message,
/// such as the remote address and ASN, the time of receiving, etc.
// As per RFC7854:
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |   Peer Type   |  Peer Flags   |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |         Peer Distinguisher (present based on peer type)       |
//  |                                                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                 Peer Address (16 bytes)                       |
//  ~                                                               ~
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                           Peer AS                             |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                         Peer BGP ID                           |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                    Timestamp (seconds)                        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                  Timestamp (microseconds)                     |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[derive(Clone, Copy, Debug, Eq)]
pub struct PerPeerHeader<Octets: AsRef<[u8]>> {
    //inner: [u8; 42]
    octets: Octets
}

impl<Octets: AsRef<[u8]>> PerPeerHeader<Octets> {

    pub fn for_slice(s: Octets) -> Self {
        PerPeerHeader { octets: s }
    }

	//fn new() -> Self {
    //    PerPeerHeader { inner: [0; 42] }
	//}

    //fn for_message_slice(s: &[u8]) -> &Self {
    //    assert!(s.len() >= 42);
    //    unsafe { &*(s.as_ptr() as *const PerPeerHeader) }
    //}
}

//impl Default for PerPeerHeader {
//    fn default() -> Self {
//        Self::new()
//    }
//}

impl<Octets: AsRef<[u8]>> PerPeerHeader<Octets> {
    /// Returns the peer type as defined in
    /// [RFC7854](https://datatracker.ietf.org/doc/html/rfc7854#section-10.2).
    pub fn peer_type(&self) -> PeerType {
        match self.octets.as_ref()[0] {
            0 => PeerType::GlobalInstance,
            1 => PeerType::RdInstance,
            2 => PeerType::LocalInstance,
            _ => PeerType::Undefined,
        }
    }

    //  0 1 2 3 4 5 6 7
    // +-+-+-+-+-+-+-+-+
    // |V|L|A|O| Rservd|
    // +-+-+-+-+-+-+-+-+
    //
    // V: IP Version,  0 = IPv4, 1 = IPv6
    // L: 0 = pre-policy Adj-RIB-In, 1 = post-policy
    // A: 0 = 4-byte AS_PATH format, 1 = 2-byte legacy format
    // O: 0 = Adj-RIB-In, 1 = Adj-RIB-Out (RFC 8671)

    /// Returns the flags as a byte.
    pub fn flags(&self) -> u8 {
        self.octets.as_ref()[1]
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
            true => RibType::AdjRibOut
        }
    }

    /// Returns the peer distinguisher value in raw form.
    pub fn distinguisher(&'_ self) -> &'_ [u8] {
        &self.octets.as_ref()[2..=9]
    }

    // XXX not happy with this one.. TryInto [u8; n] ?
    /// Returns the remote address of the peer.
    pub fn address(&self) -> IpAddr {
        if self.is_ipv4() {
            IpAddr::V4(Ipv4Addr::from(
                u32::from_be_bytes(self.octets.as_ref()[10+12..=25].try_into().unwrap())
            ))
        } else {
            IpAddr::V6(Ipv6Addr::from(
                u128::from_be_bytes(self.octets.as_ref()[10..=25].try_into().unwrap())
            ))
        }
    }

    /// Returns the ASN of the peer.
    pub fn asn(&self) -> Asn {
        u32::from_be_bytes(self.octets.as_ref()[26..=29].try_into().unwrap()).into()
    }

    /// Returns the BGP Identifier of the peer.
    pub fn bgp_id(&self) -> [u8; 4] {
        self.octets.as_ref()[30..=33].try_into().unwrap()
    }

    fn ts_seconds(&self) -> u32 {
        u32::from_be_bytes(self.octets.as_ref()[34..=37].try_into().unwrap())
    }

    fn ts_micros(&self) -> u32 {
        u32::from_be_bytes(self.octets.as_ref()[38..=41].try_into().unwrap())
    }

    /// Returns the time when the encapsulated message was received.
    pub fn timestamp(&self) -> DateTime<Utc> {
        let s = self.ts_seconds() as i64;
        let us = self.ts_micros();
        Utc.timestamp(s, us*1000)
    }
}

impl<Octets: AsRef<[u8]>> PerPeerHeader<Octets> {
    fn parse<R>(parser: &mut Parser<R>) -> Result<Self, ParseError>
        where
            R: OctetsRef<Range = Octets>
    {
        Ok(
            PerPeerHeader::for_slice(parser.parse_octets(42)?)
        )
    }
}

impl<Octets: AsRef<[u8]>> Display for PerPeerHeader<Octets>
//where
//    for <'a> &'a Octets: OctetsRef
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}/{}/{:02X?}", self.address(), self.asn(), self.bgp_id())
    }
}

impl<Octets: AsRef<[u8]>> Hash for PerPeerHeader<Octets> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.peer_type().hash(state);
        //self.flags().hash(state);
        self.distinguisher().hash(state);
        self.address().hash(state);
        self.asn().hash(state);
        self.bgp_id().hash(state);
    }
}

impl<Octets: AsRef<[u8]>> PartialEq for PerPeerHeader<Octets> {
    fn eq(&self, other: &Self) -> bool {
        self.peer_type() == other.peer_type()
            //&& self.flags() == other.flags()
            && self.distinguisher() == other.distinguisher()
            && self.address() == other.address()
            && self.asn() == other.asn()
            && self.bgp_id() == other.bgp_id()
    }
}

/// The three peer types as defined in
/// [RFC7854](https://datatracker.ietf.org/doc/html/rfc7854#section-4.2).
#[derive(Debug, Hash, Eq, PartialEq)]
pub enum PeerType {
    GlobalInstance,
    RdInstance,
    LocalInstance,
    Undefined,
}

/// Specify which RIB the contents of a message originated from.
pub enum RibType {
    AdjRibIn,
    AdjRibOut,
}


//--- Specific Message types -------------------------------------------------


/// Route Monitoring message.
pub struct RouteMonitoring<Octets: AsRef<[u8]>>
{
    octets: Octets
}

impl<Octets: AsRef<[u8]>> RouteMonitoring<Octets>
where
    for <'a> &'a Octets: OctetsRef
{
    /// Return the [`CommonHeader`] for this message.
    pub fn common_header(&self)
        -> CommonHeader<<&Octets as OctetsRef>::Range> {
        CommonHeader::for_slice(self.octets.range_to(6))
    }

    /// Return the [`PerPeerHeader`] for this message.
    pub fn per_peer_header(&self)
        -> PerPeerHeader<<&Octets as OctetsRef>::Range>
    {
        PerPeerHeader::for_slice(self.octets.range(6,6+42))
    }

    /// Return the encapsulated
    /// [BGP UPDATE message](`crate::bgp::MessageUpdate`).
    pub fn bgp_update(&self, config: SessionConfig)
        -> Result<BgpUpdate<<&Octets as OctetsRef>::Range>, ParseError>
    where
        for <'a> &'a Octets: OctetsRef<Range = Octets>
    {
        let mut parser = Parser::from_ref(
            &self.octets,//.range_from(6+42),
        );
        parser.advance(6+42).expect("parsed before");
        BgpUpdate::parse(&mut parser, config)
    }
}

impl<Octets: AsRef<[u8]>> RouteMonitoring<Octets>
where
{
    fn parse<R>(parser: &mut Parser<R>)
        -> Result<RouteMonitoring<Octets>, ParseError>
    where
        R: OctetsRef<Range = Octets>
    {
        let pos = parser.pos();
        let ch = CommonHeader::parse(parser)?;
        let _pph = PerPeerHeader::parse(parser)?;
        //  If we parse the encapsulated BGP UPDATE here, and it fails, this
        //  entire BMP RouteMonitoring message is lost.
        //  Instead, if we skip the parsing here, and do the parsing in
        //  RouteMonitoring::bgp_update(), we can retry parsing
        //  if we want to.
        //let _bgp_update = BgpUpdate::parse(parser)?;
        parser.seek(pos)?;
        Ok(Self {
            octets: parser.parse_octets(ch.length() as usize)?
        })
    }
}

/// Statistics Report message.
pub struct StatisticsReport<Octets> {
    octets: Octets,
}

impl<Octets: AsRef<[u8]>> StatisticsReport<Octets> {
    // XXX the name for_slice does not make sense anymore
    fn for_slice(s: Octets) -> Self {
        Self {
            octets: s,
        }
    }

    /// Return the [`CommonHeader`] for this message.
    pub fn common_header<'s>(&'s self)
        -> CommonHeader<<&'s Octets as OctetsRef>::Range>
    where
        &'s Octets: OctetsRef
    {
        CommonHeader::for_slice(self.octets.range_to(6))
    }

    /// Return the [`PerPeerHeader`] for this message.
    pub fn per_peer_header<'s>(&'s self)
        -> PerPeerHeader<<&'s Octets as OctetsRef>::Range>
    where
        &'s Octets: OctetsRef
    {
        PerPeerHeader::for_slice(self.octets.range(6,6+42))
    }

    /// Return the number of statistics listed in this report.
    pub fn stats_count(&self) -> u32 {
        u32::from_be_bytes(
            self.octets.as_ref()[COFF..=COFF+3].try_into().expect("parsed before")
        )
    }

    /// Return an iterator over the statistics.
    pub fn stats(&self) -> StatIter {
        StatIter::new(&self.octets.as_ref()[COFF+4..], self.stats_count())
    }

}

impl<Octets: AsRef<[u8]>> StatisticsReport<Octets>
where
{
    fn parse<R>(parser: &mut Parser<R>) -> Result<Self, ParseError>
    where
        R: OctetsRef<Range = Octets>
    {
        let pos = parser.pos();
        let ch = CommonHeader::parse(parser)?;
        let _pph = PerPeerHeader::parse(parser)?;

        let count = parser.parse_u32()?;
        for _ in 0..count {
            let _type = parser.parse_u16()?;
            let len = parser.parse_u16()?;
            parser.advance(len.into())?;
        }

        parser.seek(pos)?;
        Ok(Self::for_slice(parser.parse_octets(ch.length() as usize)?))
    }
}

impl<Octets: AsRef<[u8]>> Debug for StatisticsReport<Octets> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for s in self.stats() {
            let _ = writeln!(f, "{}", s);
        }
        writeln!(f)
    }
}


/// Peer Down Notification.
pub struct PeerDownNotification<Octets: AsRef<[u8]>> {
    octets: Octets,
}

impl<Octets: AsRef<[u8]>> PeerDownNotification<Octets>
where
    for <'a> &'a Octets: OctetsRef
{
    fn for_slice(s: Octets) -> Self {
        Self {
            octets: s 
        }
    }

    /// Return the [`CommonHeader`] for this message.
    pub fn common_header(&self)
        -> CommonHeader<<&Octets as OctetsRef>::Range> {
        CommonHeader::for_slice(self.octets.range_to(6))
    }

    /// Return the [`PerPeerHeader`] for this message.
    pub fn per_peer_header(&self)
        -> PerPeerHeader<<&Octets as OctetsRef>::Range>
    {
        PerPeerHeader::for_slice(self.octets.range(6,6+42))
    }

    /// Return the [`PeerDownReason`] for this message.
    pub fn reason(&self) -> PeerDownReason {
        match self.as_ref()[COFF] {
            0 => PeerDownReason::Reserved,
            1 => PeerDownReason::LocalNotification,
            2 => PeerDownReason::LocalFsm,
            3 => PeerDownReason::RemoteNotification,
            4 => PeerDownReason::RemoteNodata,
            5 => PeerDownReason::PeerDeconfigured,
            _ => PeerDownReason::Unknown,
        }
    }

    /// Return the optional encapsulated [BGP NOTIFICATION
    /// message](`crate::bgp::MessageNotification`), that should be present
    /// for the Local and Remote Notification PeerDownReasons.
    pub fn notification<'s>(&'s self)
        //-> Option<BgpNotification<<&'s Octets as OctetsRef>::Range>>
        -> Option<BgpNotification<Octets>>
        where
            <&'s Octets as OctetsRef>::Range: OctetsRef<Range = Octets>
    {
        if self.reason() == PeerDownReason::LocalNotification ||
           self.reason() == PeerDownReason::RemoteNotification
        {
            // If we are at the end of the message, there is no data and thus
            // no BGP NOTIFICATION.
            if COFF+1 == self.common_header().length() as usize {
                return None
            }
            Some({
                let mut parser = Parser::from_ref(
                    self.octets.range_from(COFF+1)
                );
                BgpNotification::parse(&mut parser).expect("parsed before")
            })
        } else {
            None
        }
    }

    // TODO convert this to a proper enum in bgp.rs
    //pub fn fsm(&self) -> Option(Bgp::FsmEvent) {
    pub fn fsm(&self) -> Option<u16> {
        if self.reason() == PeerDownReason::LocalFsm {
            Some(u16::from_be_bytes(self.as_ref()[1..=2].try_into().unwrap()))
        } else {
            None
        }
    }
}

/// Peer Down notification message reason codes.
#[derive(Debug, Eq, PartialEq)]
pub enum PeerDownReason {
    Reserved,
    LocalNotification,  // reason 1
    LocalFsm,           // reason 2
    RemoteNotification, // reason 3
    RemoteNodata,       // reason 4
    PeerDeconfigured,   // reason 5
    Unknown,
}


impl<Octets: AsRef<[u8]>> PeerDownNotification<Octets>
where
{
    fn parse<R>(parser: &mut Parser<R>) -> Result<Self, ParseError>
    where
        R: OctetsRef<Range = Octets>,
        for <'a> &'a Octets: OctetsRef
    {
        let pos = parser.pos();
        let ch = CommonHeader::parse(parser)?;
        let _pph = PerPeerHeader::parse(parser)?;

        let reason = parser.parse_u8()?;
        match reason {
            1 | 3 => {
                if parser.remaining() == 0 {
                    warn!(
                    "Missing BGP NOTIFICATION in PeerDownNotification"
                    );
                } else {
                    BgpNotification::parse(parser)?;
                }
            }
            2 => { parser.parse_u16()?; } // TODO BGP FSM state code
            4 => { /* remote system closed without NOTIFICATION */ },
            5 => { /* Information stop for this peer */ },
            _ => { warn!("Unknown PeerDownNotification reason"); }
        }

        parser.seek(pos)?;
        Ok(Self::for_slice(parser.parse_octets(ch.length() as usize)?))
    }
}


/// Peer Up Notification.
pub struct PeerUpNotification<Octets: AsRef<[u8]>> {
    octets: Octets,
}

impl<Octets: AsRef<[u8]>> PeerUpNotification<Octets>
where
    for <'a> &'a Octets: OctetsRef
{
    fn for_slice(s: Octets) -> Self {
        Self {
            octets: s
        }
    }

    /// Return the [`CommonHeader`] for this message.
    pub fn common_header(&self)
        -> CommonHeader<<&Octets as OctetsRef>::Range> {
        CommonHeader::for_slice(self.octets.range_to(6))
    }

    /// Return the [`PerPeerHeader`] for this message.
    pub fn per_peer_header(&self)
        -> PerPeerHeader<<&Octets as OctetsRef>::Range>
    {
        PerPeerHeader::for_slice(self.octets.range(6,6+42))
    }

    /// Return the local address used for the BGP session.
    pub fn local_address(&self) -> IpAddr {
        if self.as_ref()[COFF..=COFF+11] == [0; 12] {
            // IPv4
            IpAddr::V4(Ipv4Addr::from(
                u32::from_be_bytes(self.as_ref()[COFF+12..=COFF+15].try_into().unwrap())
            ))
        } else {
            // XXX not tested, need v6 pcap
            IpAddr::V6(Ipv6Addr::from(
                u128::from_be_bytes(self.as_ref()[COFF..=COFF+15].try_into().unwrap())
            ))
        }
    }
    
    /// Return the local port used for the BGP session.
    pub fn local_port(&self) -> u16 {
        u16::from_be_bytes(
            self.as_ref()[COFF+16..=COFF+17].try_into().unwrap()
        )
    }

    /// Return the remote port used for the BGP session.
    pub fn remote_port(&self) -> u16 {
        u16::from_be_bytes(
            self.as_ref()[COFF+18..=COFF+19].try_into().unwrap()
        )
    }

    /// Return the [BGP OPEN message](BgpOpen) sent to the peer.
    pub fn bgp_open_sent<'s>(&'s self)
        -> BgpOpen<Octets>
    where
        <&'s Octets as OctetsRef>::Range: OctetsRef<Range = Octets>
    {
        let mut parser = Parser::from_ref(
            self.octets.range_from(COFF+20)
        );
        BgpOpen::parse(&mut parser).unwrap()
    }

    /// Return the [BGP OPEN message](BgpOpen) received from the peer.
    pub fn bgp_open_rcvd<'s>(&'s self)
        -> BgpOpen<Octets>
    where
        <&'s Octets as OctetsRef>::Range: OctetsRef<Range = Octets>
    {
        let mut pos: usize = 20;
        pos += self.bgp_open_sent().length() as usize;
        let mut parser = Parser::from_ref(
            self.octets.range_from(COFF+pos)
        );
        BgpOpen::parse(&mut parser).unwrap()
    }

    /// Return a tuple of the sent and received BGP OPEN messages.
    ///
    /// This method is more efficient than calling both `bgp_open_sent` and
    /// `bgp_open_rcvd` individually.
    #[allow(clippy::type_complexity)]
    pub fn bgp_open_sent_rcvd<'s>(&'s self)
        -> (
            BgpOpen<Octets>,
            BgpOpen<Octets>
        )
    where
        <&'s Octets as OctetsRef>::Range: OctetsRef<Range = Octets>
    {
        let mut parser = Parser::from_ref(
            self.octets.range_from(COFF+20)
        );
        let sent = BgpOpen::parse(&mut parser).unwrap();
        let rcvd = BgpOpen::parse(&mut parser).unwrap();

        (sent, rcvd) 
    }

    /// Create a [`SessionConfig`] describing the parameters for the BGP
    /// session between the monitored router and the remote peer.
    ///
    /// The information in this `SessionConfig` is necessary for correctly
    /// parsing future messages, specifically BGP UPDATEs carried in
    /// RouteMonitoring BMP messages. See [`SessionConfig`] for an example
    /// using it in that way.
    pub fn session_config<'s>(&'s self) -> SessionConfig
    where
        for <'a> &'a Octets: OctetsRef<Range = Octets>,
        <&'s Octets as OctetsRef>::Range: OctetsRef<Range = Octets>
    {
        let (sent, rcvd) = self.bgp_open_sent_rcvd();
        let mut conf = SessionConfig::modern();

        // The 'modern' SessionConfig has four octet capability set to
        // enabled, so we need to disable it if any of both of the peers do
        // not support it.
        if !sent.four_octet_capable() || !rcvd.four_octet_capable() {
            conf.disable_four_octet_asn();
        }

        if sent.add_path_capable() && rcvd.add_path_capable() {
            conf.enable_addpath()
        }

        conf
    }

    // XXX: 
    pub fn information_tlvs(&self) -> InformationTlvIter
    where
        for <'a> &'a Octets: OctetsRef<Range = Octets>,
    {
        let mut parser = Parser::from_ref(&self.octets);
        parser.advance(6+42).expect("parsed before");
        BgpOpen::parse(&mut parser).expect("parsed before");
        BgpOpen::parse(&mut parser).expect("parsed before");

        InformationTlvIter::new(&self.as_ref()[parser.pos()..])
    }


}

impl<Octets: AsRef<[u8]>> PeerUpNotification<Octets>
where
{
    fn parse<R>(parser: &mut Parser<R>) -> Result<Self, ParseError>
    where
        R: OctetsRef<Range = Octets>,
        for <'a> &'a Octets: OctetsRef,
    {
        let pos = parser.pos();
        let ch = CommonHeader::parse(parser)?;
        let _pph = PerPeerHeader::parse(parser)?;

        let _local_address = parser.advance(16)?;
        let _local_port = parser.parse_u16()?;
        let _remote_port = parser.parse_u16()?;

        // XXX make this similar to the embedded UPDATE in a RouteMonitoring?
        // Thus, not actually parse it here (with a posibility of failing).
        let _bgp_open_sent = BgpOpen::parse(parser)?; 
        let _bgp_open_rcvd = BgpOpen::parse(parser)?; 

        // optional Information
        if ch.length() as usize > parser.pos() - pos {
            // Information TLVs of type 0 (String)
            let _info_type = parser.parse_u16()?;
            // XXX check for _info_type == 0 ?
            let info_len = parser.parse_u16()?;
            parser.advance(info_len.into())?;
        }

        parser.seek(pos)?;
        Ok(Self::for_slice(parser.parse_octets(ch.length() as usize)?))
    }
}


/// Initiation Message.
pub struct InitiationMessage<Octets: AsRef<[u8]>> {
    octets: Octets,
}

impl<Octets: AsRef<[u8]>> InitiationMessage<Octets> {
    fn for_slice(s: Octets) -> Self {
        Self {
            octets: s
        }
    }

    /// Return the [`CommonHeader`] for this message.
    pub fn common_header<'s>(&'s self)
        -> CommonHeader<<&'s Octets as OctetsRef>::Range>
    where
        &'s Octets: OctetsRef
    {
        CommonHeader::for_slice(self.octets.range_to(6))
    }

    /// Return an iterator over the Information TLVs.
    pub fn information_tlvs(&self) -> InformationTlvIter {
        InformationTlvIter::new(&self.as_ref()[
            6
            ..
        ])
    }
}

impl<Octets: AsRef<[u8]>> InitiationMessage<Octets>
where
{
    fn parse<R>(parser: &mut Parser<R>) -> Result<Self, ParseError>
    where
        R: OctetsRef<Range = Octets>
    {
        let pos = parser.pos();
        let ch = CommonHeader::parse(parser)?;
        while parser.remaining() > 0 {
            let _info_type = parser.parse_u16()?;
            let info_len = parser.parse_u16()?;
            parser.advance(info_len.into())?;
        }
        parser.seek(pos)?;
        Ok(Self::for_slice(parser.parse_octets(ch.length() as usize)?))

    }
}


/// Termination message.
pub struct TerminationMessage<Octets: AsRef<[u8]>> {
    octets: Octets,
}

impl<Octets: AsRef<[u8]>> TerminationMessage<Octets> {
    fn for_slice(s: Octets) -> Self {
        Self {
            octets: s
        }
    }

    /// Return the [`CommonHeader`] for this message.
    pub fn common_header<'s>(&'s self)
        -> CommonHeader<<&'s Octets as OctetsRef>::Range>
    where
        &'s Octets: OctetsRef
    {
        CommonHeader::for_slice(self.octets.range_to(6))
    }

    /// Return an iterator over the Information TLVs.
    // XXX D-R-Y with TLVs from InitiationMessage
    pub fn information<'s>(&'s self) -> InformationIter
    where
        &'s Octets: OctetsRef
    {
        InformationIter::new(
            &self.octets.as_ref()[6..],
            self.common_header().length() as usize - 6
        )
    }
}

impl<Octets: AsRef<[u8]>> TerminationMessage<Octets>
where
{
    fn parse<R>(parser: &mut Parser<R>) -> Result<Self, ParseError>
    where
        R: OctetsRef<Range = Octets>
    {
        let pos = parser.pos();
        let ch = CommonHeader::parse(parser)?;
        while parser.remaining() > 0 {
            let _info_type = parser.parse_u16()?;
            let info_len = parser.parse_u16()?;
            parser.advance(info_len.into())?;
        }
        parser.seek(pos)?;
        Ok(Self::for_slice(parser.parse_octets(ch.length() as usize)?))
    }
}


/// RouteMirroring.
///
/// NB: Not well tested/supported at this moment!  
pub struct RouteMirroring<Octets: AsRef<[u8]>> {
    octets: Octets,
}

impl<Octets: AsRef<[u8]>> RouteMirroring<Octets> {
    /// Return the [`CommonHeader`] for this message.
    pub fn common_header<'s>(&'s self)
        -> CommonHeader<<&'s Octets as OctetsRef>::Range>
    where
        &'s Octets: OctetsRef
    {
        CommonHeader::for_slice(self.octets.range_to(6))
    }

    /// Return the [`PerPeerHeader`] for this message.
    pub fn per_peer_header<'s>(&'s self)
        -> PerPeerHeader<<&'s Octets as OctetsRef>::Range>
    where
        &'s Octets: OctetsRef
    {
        PerPeerHeader::for_slice(self.octets.range(6,6+42))
    }
}

impl<Octets: AsRef<[u8]>> RouteMirroring<Octets>
where
{
    fn parse<R>(_parser: &mut Parser<R>) -> Result<Self, ParseError> 
    where
        R: OctetsRef<Range = Octets>
    {
        Err(ParseError::form_error("not implemented yet"))
    }
}





//--- Information TLVs -------------------------------------------------------
//
// Information TLVs are present in the BMP InitiationMessage, and optionally
// in the PeerUpNotification.

/// TLV used in Initiation Message and Peer Up Notification.
#[derive(Debug)]
pub struct InformationTlv<'a> {
    octets: &'a[u8]
}

impl<'a> InformationTlv<'a> {
    fn for_slice(slice: &'a[u8]) -> Self {
        InformationTlv {
            octets: slice,
        }
    }

    /// Returns the `InformationTlvType` for this TLV.
    pub fn typ(&self) -> InformationTlvType {
        match u16::from_be_bytes(self.octets[0..=1].try_into().unwrap()) {
            0 => InformationTlvType::String,
            1 => InformationTlvType::SysDesc,
            2 => InformationTlvType::SysName,
            3 => InformationTlvType::VrfTableName,
            4 => InformationTlvType::AdminLabel,
            u => InformationTlvType::Undefined(u)
        }
    }

    /// Returns the length of the value.
    pub fn length(&self) -> u16 {
        u16::from_be_bytes(self.octets[2..=3].try_into().unwrap())
    }

    /// Returns the value as a slice.
    pub fn value(&self) -> &[u8] {
        &self.octets[4..]
    }
}

impl<'a> Display for InformationTlv<'a> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self.typ() {
            InformationTlvType::String
                | InformationTlvType::SysDesc
                | InformationTlvType::SysName
                => write!(f, "{:?}: {}",
                    self.typ(),
                    String::from_utf8_lossy(self.value())
                    ),
            _ => write!(f, "{:?}", self.typ()), 
        }
    }

}

/// Types of Information TLVs.
///
/// See also
/// <https://www.iana.org/assignments/bmp-parameters/bmp-parameters.xhtml#initiation-peer-up-tlvs>
#[derive(Debug, Eq, PartialEq)]
pub enum InformationTlvType {
    String,         // type 0
    SysDesc,        // type 1
    SysName,        // type 2
    VrfTableName,   // type 3, RFC 9069
    AdminLabel,     // type 4, RFC 8671
    Undefined(u16),
}

/// Iterator over `InformationTlv`'s.
pub struct InformationTlvIter<'a> {
    slice: &'a [u8],
    pos: usize,
}
impl<'a> InformationTlvIter<'a> {
    fn new(slice: &'a [u8]) -> Self {
        InformationTlvIter {
            slice,
            pos: 0,
        }
    }

    fn get_tlv(&mut self) -> InformationTlv<'a> {
        let s = u16::from_be_bytes(self.slice[(self.pos + 2)..=(self.pos + 3)].try_into().unwrap());
        let res = InformationTlv::for_slice(&self.slice[self.pos..self.pos+4+(s as usize)]);
        self.pos += (res.length() + 4) as usize;
        res
    }
}

impl<'a> Iterator for InformationTlvIter<'a> {
    type Item = InformationTlv<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos == self.slice.len() {
            return None;
        }
        Some(self.get_tlv())
    }
}


//--- StatisticsReport -------------------------------------------------------

/// Represents the type and value of statistics in a BMP StatisticsReport.
/// 
/// <https://datatracker.ietf.org/doc/html/rfc7854#section-4.8>
#[derive(Debug, Eq, PartialEq)]
pub enum Stat {
    Type0(u32),
    Type1(u32),
    Type2(u32),
    Type3(u32),
    Type4(u32),
    Type5(u32),
    Type6(u32),
    Type7(u64),
    Type8(u64),
    Type9(AFI,SAFI,u64),
    Type10(AFI,SAFI,u64),
    Type11(u32),
    Type12(u32),
    Type13(u32),
    // RFC 8671, Adj-RIB-Out
    Type14(u64),
    Type15(u64),
    Type16(AFI,SAFI,u64),
    Type17(AFI,SAFI,u64),

    Unimplemented(u16,u16) // type,len
}

impl std::fmt::Display for Stat {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error>{
        use Stat::*;
        match self {
            Type0(v) => write!(f, "rejected-inbound-policy: {}", v),
            Type1(v) => write!(f, "duplicate-prefix-adv: {}", v),
            Type2(v) => write!(f, "duplicate-prefix-wdraw: {}", v),
            Type3(v) => write!(f, "upd-invalid-clusterlist: {}", v),
            Type4(v) => write!(f, "upd-invalid-aspath: {}", v),
            Type5(v) => write!(f, "upd-invalid-originator: {}", v),
            Type6(v) => write!(f, "upd-invalid-asconfed: {}", v),
            Type7(v) => write!(f, "routes-adj-rib-in: {}", v),
            Type8(v) => write!(f, "routes-loc-rib: {}", v),
            Type9(a, s, v) => 
                write!(f, "routes-{}-{}-adj-rib-in: {}", a, s, v),
            Type10(a, s, v) => 
                write!(f, "routes-{}-{}-loc-rib: {}", a, s, v),
            Type11(v) => write!(f, "updates-treat-withdraw: {}", v),
            Type12(v) => write!(f, "prefixes-treat-withdraw: {}", v),
            Type13(v) => write!(f, "duplicate-updates: {}", v),

            Type14(v) => write!(f, "routes-pre-adj-rib-out: {}", v),
            Type15(v) => write!(f, "routes-post-adj-rib-out: {}", v),
            Type16(a, s, v) => 
                write!(f, "routes-{}-{}-pre-adj-rib-out: {}", a, s, v),
            Type17(a, s, v) => 
                write!(f, "routes-{}-{}-post-adj-rib-out: {}", a, s, v),
            Unimplemented(t,_) => write!(f, "unimplemented-stat-type-{}", t),
        }
        
    }
}

/// Iterator over statistics in a Statistics Report message.
pub struct StatIter<'a> {
    octets: &'a [u8],
    pos: usize,
    left: u32,
}

// XXX this can be improved
impl <'a>StatIter<'a> {
    fn new(octets: &'a [u8], left: u32) -> Self {
        StatIter{octets, pos: 0, left}
    }

    fn _take_u32(&mut self) -> u32 {
        let res = u32::from_be_bytes(
            self.octets[(self.pos + 4 .. self.pos + 4 + 4)]
            .try_into().unwrap()
        );
        self.pos += 4 + 4;
        res
    }

    fn _take_u64(&mut self) -> u64 {
        let res = u64::from_be_bytes(
            self.octets[(self.pos + 4 .. self.pos + 4 + 8)]
            .try_into().unwrap()
        );
        self.pos += 4 + 8;
        res
    }

    fn _take_afi_safi_u64(&mut self) -> (AFI, SAFI, u64) {

        let afi: AFI = u16::from_be_bytes(
            self.octets[(self.pos + 4 .. self.pos + 4 + 2)].try_into().unwrap()
        ).into();
        let safi: SAFI = self.octets[self.pos + 4 + 2].into();

        let v = u64::from_be_bytes(
            self.octets[(self.pos + 4 + 3 .. self.pos + 4 + 3 + 8)]
            .try_into().unwrap()
        );
        self.pos += 4 + 2 + 1 + 8;
        (afi, safi, v)
    }

    fn get_stat(&mut self) -> Stat {
        let typ = u16::from_be_bytes(
            self.octets[(self.pos)..=(self.pos + 1)]
            .try_into().unwrap()
        );
        let len = u16::from_be_bytes(
            self.octets[(self.pos + 2)..=(self.pos + 3)]
            .try_into().unwrap()
        );

        self.left -= 1;
        match (typ, len) {
            (0, 4) => Stat::Type0(self._take_u32()),
            (1, 4) => Stat::Type1(self._take_u32()),
            (2, 4) => Stat::Type2(self._take_u32()),
            (3, 4) => Stat::Type3(self._take_u32()),
            (4, 4) => Stat::Type4(self._take_u32()),
            (5, 4) => Stat::Type5(self._take_u32()),
            (6, 4) => Stat::Type6(self._take_u32()),
            (7, 8) => Stat::Type7(self._take_u64()),
            (8, 8) => Stat::Type8(self._take_u64()),
            (9, 11) =>  {
                let (a, s, v) = self._take_afi_safi_u64();
                Stat::Type9(a, s, v)
            }
            (10, 11) =>  {
                let (a, s, v) = self._take_afi_safi_u64();
                Stat::Type10(a, s, v)
            }
            (11, 4) => Stat::Type11(self._take_u32()),
            (12, 4) => Stat::Type12(self._take_u32()),
            (13, 4) => Stat::Type13(self._take_u32()),
            (14, 8) => Stat::Type14(self._take_u64()),
            (15, 8) => Stat::Type15(self._take_u64()),
            (16, 11) =>  {
                let (a, s, v) = self._take_afi_safi_u64();
                Stat::Type16(a, s, v)
            }
            (17, 11) =>  {
                let (a, s, v) = self._take_afi_safi_u64();
                Stat::Type17(a, s, v)
            }

            (_,_) => { 
                self.pos += 4 + len as usize;
                Stat::Unimplemented(typ, len)
            }
        }
    }
}
impl <'a>Iterator for StatIter<'a> {
    type Item = Stat;
    fn next(&mut self) -> Option<Self::Item> {
        if self.left > 0 {
            Some(self.get_stat())
        } else {
            None
        }
    }
}


// Offset of actual payload within message
const COFF: usize = 
        6 + //std::mem::size_of::<CommonHeader>() +
        42 //std::mem::size_of::<PerPeerHeader>()
;



//--- Termination Message ----------------------------------------------------

/// Iterator over TLVs in a Termination message.
pub struct InformationIter<'a> {
    octets: &'a [u8],
    pos: usize,
    end: usize,
}

/// Termination message reason codes.
// XXX convert this to a typeenum! ?
#[derive(Debug, Eq, PartialEq)]
pub enum TerminationInformation {
    CustomString(String),
    AdminClose,             // reason 0
    Unspecified,            // reason 1
    OutOfResources,         // reason 2
    RedundantConnection,    // reason 3
    PermAdminClose,         // reason 4
    Undefined(u16),
}

impl<'a> InformationIter<'a> {
    fn new(octets: &'a [u8], end: usize) -> Self {
       InformationIter {
           octets,
           pos: 0,
           end
       }
    }

    fn get_info(&mut self) -> TerminationInformation {
        let typ = u16::from_be_bytes(self.octets[self.pos..self.pos+2].try_into().unwrap());
        let len = u16::from_be_bytes(self.octets[self.pos+2..self.pos+4].try_into().unwrap());
        if typ == 0 {
            let s = String::from_utf8_lossy(
                &self.octets[self.pos+4..self.pos+4+len as usize]
                )
                .into_owned();
            self.pos += len as usize;
            return TerminationInformation::CustomString(s)
        }
        let val = u16::from_be_bytes(self.octets[self.pos+4..self.pos+4+len as usize].try_into().unwrap());
        self.pos += 4 + len as usize;
        match val {
            0 => TerminationInformation::AdminClose,
            1 => TerminationInformation::Unspecified,
            2 => TerminationInformation::OutOfResources,
            3 => TerminationInformation::RedundantConnection,
            4 => TerminationInformation::PermAdminClose,
            u => TerminationInformation::Undefined(u)
        }

    }
}

impl Iterator for InformationIter<'_> {
    type Item = TerminationInformation;
    fn next(&mut self) -> Option<TerminationInformation> {
        if self.pos == self.end {
            return None
        }
        Some(self.get_info())
    }
}


impl Display for TerminationInformation {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    match self {
            TerminationInformation::CustomString(s) => write!(f, "{}", s),
            TerminationInformation::AdminClose => write!(f, "Session administratively closed"),
            TerminationInformation::Unspecified => write!(f, "Unspecified reason"),
            TerminationInformation::OutOfResources => write!(f, "Out of resources"),
            TerminationInformation::RedundantConnection => write!(f, "Redundant connection"),
            TerminationInformation::PermAdminClose => {
                write!(f, "Session permanently administratively closed")
            }
            TerminationInformation::Undefined(v) => write!(f, "Undefined: {}", v),
        }
    }
}

//--- Route Mirroring --------------------------------------------------------

/// Types of Route Mirroring TLVs.
pub enum RouteMirroringType<Octets: AsRef<[u8]> + OctetsRef> {
    BgpMessage(Result<BgpMsg<Octets>, ParseError>),         // type 0
    InfoErrorPdu,       // type 1 code 0
    InfoMessagesLost,   // type 1 code 1
    Undefined(u16, Octets),     // carries the type
}

/*
/// Iterator over Route Mirroring TLVs.
pub struct RouteMirroringTlvIter<Octets> {
    octets: Octets,
    pos: usize,
}
impl<Octets: AsRef<[u8]>> RouteMirroringTlvIter<Octets>
where
    //Octets: AsRef<[u8]> + OctetsRef//<Range = Octets>
{
    fn get_item(&mut self) -> RouteMirroringType<Octets> {
        let typ = u16::from_be_bytes(
            self.octets.as_ref()[self.pos..self.pos+2].try_into().unwrap()
        );
        let len = u16::from_be_bytes(
            self.octets.as_ref()[self.pos+2..self.pos+4].try_into().unwrap()
        );
        if typ == 0 {
            let res = RouteMirroringType::BgpMessage(
                BgpMsg::from_octets(
                    self.octets.range(self.pos+5,self.pos+5+len as usize)
                )
            );
            self.pos += 4 + len as usize;
            return res;
        }

        // XXX expecting the TLV to be a type 1, revise when we have test data
        // with these asserts, the possible Undefined cases are limited
        assert!(typ == 1);
        assert!(len == 2);
        let val = u16::from_be_bytes(
            self.octets.as_ref()[self.pos+4..self.pos+4+len as usize]
            .try_into().unwrap()
        );
        self.pos += len as usize;

        match val {
            0 => RouteMirroringType::InfoErrorPdu,
            1 => RouteMirroringType::InfoMessagesLost,
            u => RouteMirroringType::Undefined(
                u, self.octets.range(self.pos+4,self.pos+4+len as usize)
            )
        }

    }
}
impl<Octets> Iterator for RouteMirroringTlvIter<Octets>
where
    Octets: AsRef<[u8]> + OctetsRef//<Range = Octets>
{
    type Item = RouteMirroringType<Octets>;
    fn next(&mut self) -> Option<RouteMirroringType<Octets>> {
        if self.pos == self.octets.as_ref().len() {
            return None
        }
        Some(self.get_item())
    }
}
*/


//--- From / Into ------------------------------------------------------------


impl<Octets: AsRef<[u8]>> TryFrom<Message<Octets>> for RouteMonitoring<Octets>
{
    type Error = MessageError;
    fn try_from(msg: Message<Octets>)
        -> Result<RouteMonitoring<Octets>, Self::Error>
    {
        match msg {
            Message::RouteMonitoring(m) => Ok(m),
            _ => Err(MessageError::InvalidMsgType),
        }
    }
}

impl<Octets: AsRef<[u8]>> TryFrom<Message<Octets>> for StatisticsReport<Octets>
{
    type Error = MessageError;
    fn try_from(msg: Message<Octets>)
        -> Result<StatisticsReport<Octets>, Self::Error>
    {
        match msg {
            Message::StatisticsReport(m) => Ok(m),
            _ => Err(MessageError::InvalidMsgType),
        }
    }
}

impl<Octets: AsRef<[u8]>> TryFrom<Message<Octets>> for PeerDownNotification<Octets>
{
    type Error = MessageError;
    fn try_from(msg: Message<Octets>)
        -> Result<PeerDownNotification<Octets>, Self::Error>
    {
        match msg {
            Message::PeerDownNotification(m) => Ok(m),
            _ => Err(MessageError::InvalidMsgType),
        }
    }
}

impl<Octets: AsRef<[u8]>> TryFrom<Message<Octets>> for PeerUpNotification<Octets>
{
    type Error = MessageError;
    fn try_from(msg: Message<Octets>)
        -> Result<PeerUpNotification<Octets>, Self::Error>
    {
        match msg {
            Message::PeerUpNotification(m) => Ok(m),
            _ => Err(MessageError::InvalidMsgType),
        }
    }
}

impl<Octets: AsRef<[u8]>> TryFrom<Message<Octets>> for InitiationMessage<Octets>
{
    type Error = MessageError;
    fn try_from(msg: Message<Octets>)
        -> Result<InitiationMessage<Octets>, Self::Error>
    {
        match msg {
            Message::InitiationMessage(m) => Ok(m),
            _ => Err(MessageError::InvalidMsgType),
        }
    }
}

impl<Octets: AsRef<[u8]>> TryFrom<Message<Octets>> for TerminationMessage<Octets>
{
    type Error = MessageError;
    fn try_from(msg: Message<Octets>)
        -> Result<TerminationMessage<Octets>, Self::Error>
    {
        match msg {
            Message::TerminationMessage(m) => Ok(m),
            _ => Err(MessageError::InvalidMsgType),
        }
    }
}

impl<Octets: AsRef<[u8]>> TryFrom<Message<Octets>> for RouteMirroring<Octets>
{
    type Error = MessageError;
    fn try_from(msg: Message<Octets>)
        -> Result<RouteMirroring<Octets>, Self::Error>
    {
        match msg {
            Message::RouteMirroring(m) => Ok(m),
            _ => Err(MessageError::InvalidMsgType),
        }
    }
}


//--- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use bytes::Bytes;
    use std::str::FromStr;
    use crate::addr::Prefix;
    use crate::bgp::message::{AFI, SAFI,PathAttributeType};
    use crate::bgp::message::SessionConfig;

    // Helper for generating a .pcap, pass output to `text2pcap`.
    #[allow(dead_code)]
    fn print_pcap<T: AsRef<[u8]>>(msg: T) {
        println!();
        print!("000000 ");
        for b in msg.as_ref() {
            print!("{:02x} ", b);
        }
        println!();
    }

    //--- Headers ------------------------------------------------------------
    
    #[test]
    fn common_header_for_slice() {
        let buf = [0x03, 0x0, 0x0, 0x0, 0x6c, 0x04];
		let ch = CommonHeader::<&[u8]>::for_slice(&buf);
        assert_eq!(ch.version(), 3);
        assert_eq!(ch.length(), 108);
        assert_eq!(ch.msg_type(), MessageType::InitiationMessage);
    }

    #[test]
    fn common_header_parse() {
        let buf = vec![0x03, 0x0, 0x0, 0x0, 0x6c, 0x04];
        let mut parser = Parser::from_ref(&buf);
		let ch = CommonHeader::parse(&mut parser).unwrap();
        assert_eq!(ch.version(), 3);
        assert_eq!(ch.length(), 108);
        assert_eq!(ch.msg_type(), MessageType::InitiationMessage);
    }

    #[test]
    fn per_peer_header() {
        let buf = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x0a, 0xff, 0x00, 0x65, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x0a, 0x0a,
            0x01, 0x54, 0xa2, 0x0e, 0x0b, 0x00, 0x0e, 0x0c, 0x20,
        ];

        let pph = PerPeerHeader::for_slice(&buf);
        assert_eq!(pph.peer_type(), PeerType::GlobalInstance);
        assert!(pph.is_ipv4());
        assert_eq!(pph.distinguisher(), [0; 8]);
        assert_eq!(
            pph.address(),
            Ipv4Addr::from_str("10.255.0.101").unwrap()
        );

        assert_eq!(pph.asn(), Asn::from_u32(65536));
        assert_eq!(pph.bgp_id(), [10, 10, 10, 1]);
        assert_eq!(pph.ts_seconds(), 1419906571);
        assert_eq!(pph.ts_micros(), 920608);

        assert_eq!(
            pph.timestamp().to_string(),
            "2014-12-30 02:29:31.920608 UTC"
        );
    }


    //--- Messages -----------------------------------------------------------
    
    // Helper to quickly parse bufs into specific BMP messages.
    //fn parse_msg<T, R>(buf: R) -> T
    //where
    //    T: TryFrom<Message<R>>,
    //    R: AsRef<[u8]> + OctetsRef,
    //    <T as TryFrom<Message<R>>>::Error: Debug
    //{
    //    Message::from_octets(buf).unwrap().try_into().unwrap()
    //}

    #[test]
    fn route_monitoring() {
        // a single BMP Route Monitoring message, containing one BGP UPDATE
        // message with 4 path attributes and 1 IPv4 NLRI
        let buf = vec![
            0x03, 0x00, 0x00, 0x00, 0x67, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x0a, 0xff, 0x00, 0x65,
            0x00, 0x01, 0x00, 0x00, 0x0a, 0x0a, 0x0a, 0x01,
            0x54, 0xa2, 0x0e, 0x0c, 0x00, 0x0e, 0x81, 0x09,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x37, 0x02, 0x00, 0x00, 0x00, 0x1b, 0x40,
            0x01, 0x01, 0x00, 0x40, 0x02, 0x06, 0x02, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x40, 0x03, 0x04, 0x0a,
            0xff, 0x00, 0x65, 0x80, 0x04, 0x04, 0x00, 0x00,
            0x00, 0x01, 0x20, 0x0a, 0x0a, 0x0a, 0x02
        ]; 

        let bb = Bytes::from(buf.clone());
        let bmp: RouteMonitoring<_> = Message::from_octets(&bb).unwrap().try_into().unwrap();
        assert_eq!(
            bmp.common_header().msg_type(),
            MessageType::RouteMonitoring
        );
        assert_eq!(bmp.common_header().length(), 103);

        let config = SessionConfig::modern();
        let bgp_update = bmp.bgp_update(config).unwrap();

        //-- from here on, this actually tests the bgp parsing functionality
        // rather than the bmp one, but let's leave it for now ---------------
        
        assert_eq!(bgp_update.as_ref().len(), 55);
        assert_eq!(bgp_update.withdrawn_routes_len(), 0);
        
        let pas = bgp_update.path_attributes();
        let mut pas = pas.iter();
        let pa1 = pas.next().unwrap();
        assert_eq!(pa1.type_code(), PathAttributeType::Origin);
        assert_eq!(pa1.flags(), 0x40);
        assert!(pa1.is_transitive());
        assert!(!pa1.is_optional());
        //TODO implement enum for Origins
        assert_eq!(pa1.value().as_ref(), [0x00]); 
        
        let pa2 = pas.next().unwrap();
        assert_eq!(pa2.type_code(), PathAttributeType::AsPath);
        assert_eq!(pa2.flags(), 0x40);
        // TODO check actual AS_PATH contents

        let pa3 = pas.next().unwrap();
        assert_eq!(pa3.type_code(), PathAttributeType::NextHop);
        assert_eq!(pa3.flags(), 0x40);
        assert_eq!(pa3.value().as_ref(), [10, 255, 0, 101]); 

        let pa4 = pas.next().unwrap();
        assert_eq!(pa4.type_code(), PathAttributeType::MultiExitDisc);
        assert_eq!(pa4.flags(), 0x80);
        assert!(pa4.is_optional());
        assert_eq!(pa4.value().as_ref(), [0, 0, 0, 1]); 

        assert!(pas.next().is_none());


        // NLRI
        let nlris = bgp_update.nlris();
        let mut nlris = nlris.iter();
        let n1 = nlris.next().unwrap().prefix();
        assert_eq!(n1, Some(Prefix::from_str("10.10.10.2/32").unwrap()));
        assert!(nlris.next().is_none());
    }

    #[test]
    fn statistics_report() {
        // BMP statistics report with 13 stats.
        let buf = vec![
            0x03, 0x00, 0x00, 0x00, 0xba, 0x01, 0x00, 0x80,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x05,
            0x62, 0x50, 0x11, 0x57, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x04,
            0x00, 0x00, 0x00, 0xb0, 0x00, 0x01, 0x00, 0x04,
            0x00, 0x00, 0x04, 0xde, 0x00, 0x02, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x0a, 0x00, 0x05, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x08,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25,
            0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x1c, 0x00, 0x0e, 0x00, 0x08,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x21, 0x14,
            0x00, 0x0f, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02, 0x21, 0x14, 0x00, 0x10, 0x00, 0x0b,
            0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x21, 0x14, 0x00, 0x11, 0x00, 0x0b, 0x00,
            0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            0x21, 0x14
        ];
        let bmp: StatisticsReport<_> = Message::from_octets(&buf).unwrap().try_into().unwrap();
        assert_eq!(bmp.stats_count(), 13);
        assert_eq!(bmp.stats().count(), 13);
        use Stat::*;
        let stats = [
            Type0(176),
            Type1(1246),
            Type2(0),
            Type3(0),
            Type4(10),
            Type5(0),
            Type6(0),
            Type7(37),
            Type8(28),
            Type14(139540),
            Type15(139540),
            Type16(AFI::Ipv6, SAFI::Unicast, 139540),
            Type17(AFI::Ipv6, SAFI::Unicast, 139540),
        ];

        for (s1, s2) in bmp.stats().zip(stats.iter()) {
            assert_eq!(s1, *s2);
        }
    }

    #[test]
    fn peer_down_notification() {
        // BMP PeerDownNotification type 3, containing a BGP NOTIFICATION.
        let buf = vec![
            0x03, 0x00, 0x00, 0x00, 0x46, 0x02, 0x00, 0x80,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x0a,
            0x62, 0x2d, 0xea, 0x80, 0x00, 0x05, 0x58, 0x22,
            0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0x00, 0x15, 0x03, 0x06, 0x02
        ];
        let bmp: PeerDownNotification<_> = Message::from_octets(&buf).unwrap().try_into().unwrap();
        assert_eq!(bmp.reason(), PeerDownReason::RemoteNotification);
        assert!(bmp.notification().is_some());
        assert_eq!(bmp.fsm(), None);

        let bgp_notification = bmp.notification().unwrap();
        assert_eq!(bgp_notification.code(), 6);
        assert_eq!(bgp_notification.subcode(), 2);
    }


    #[test]
    fn peer_down_lacking_notification() {
        // BMP PeerDownNotification with reason LocalNotification, but lacking
        // the BGP NOTIFICATION.
        let buf = vec![
            0x03, 0x00, 0x00, 0x00, 0x31, 0x02, 0x00, 0x80,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x00, 0xac, 0x11, 0x11, 0x0a,
            0x62, 0x2f, 0x06, 0x40, 0x00, 0x08, 0x6c, 0xb2,
            0x01
        ];
        let bmp: PeerDownNotification<_> = Message::from_octets(&buf).unwrap().try_into().unwrap();
        assert_eq!(bmp.reason(), PeerDownReason::LocalNotification);
        assert!(bmp.notification().is_none());
    }


    #[test]
    fn peer_up_notification() {
        // BMP PeerUpNotification, containing two BGP OPEN messages (the Sent
        // OPEN and the Received OPEN), both containing 5 Capabilities in the
        // Optional Parameters.
        // No optional Information field.
        // quoting RFC7854:
        // Inclusion of the Information field is OPTIONAL.  Its presence or
        // absence can be inferred by inspection of the Message Length in the
        // common header. TODO implement this presence check.
        //
		let buf = vec![
			0x03, 0x00, 0x00, 0x00, 0xba, 0x03, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x0a, 0xff, 0x00, 0x65,
			0x00, 0x00, 0xfb, 0xf0, 0x0a, 0x0a, 0x0a, 0x01,
			0x54, 0xa2, 0x0e, 0x0b, 0x00, 0x0e, 0x0c, 0x20,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x0a, 0xff, 0x00, 0x53,
			0x90, 0x6e, 0x00, 0xb3, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0x00, 0x3b, 0x01, 0x04,
			0xfb, 0xff, 0x00, 0xb4, 0x0a, 0x0a, 0x0a, 0x67,
			0x1e, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00,
			0x01, 0x02, 0x02, 0x80, 0x00, 0x02, 0x02, 0x02,
			0x00, 0x02, 0x06, 0x41, 0x04, 0x00, 0x00, 0xfb,
			0xff, 0x02, 0x04, 0x40, 0x02, 0x00, 0x78, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
			0x3b, 0x01, 0x04, 0xfb, 0xf0, 0x00, 0x5a, 0x0a,
			0x0a, 0x0a, 0x01, 0x1e, 0x02, 0x06, 0x01, 0x04,
			0x00, 0x01, 0x00, 0x01, 0x02, 0x02, 0x80, 0x00,
			0x02, 0x02, 0x02, 0x00, 0x02, 0x04, 0x40, 0x02,
			0x00, 0x78, 0x02, 0x06, 0x41, 0x04, 0x00, 0x00,
			0xfb, 0xf0];

        let bmp: PeerUpNotification<_> = Message::from_octets(&buf).unwrap().try_into().unwrap();

        assert_eq!(bmp.common_header().version(), 3);
        assert_eq!(bmp.common_header().length(), 186);
        assert_eq!(
            bmp.common_header().msg_type(),
            MessageType::PeerUpNotification
        );
        assert_eq!(
            bmp.per_peer_header().peer_type(),
            PeerType::GlobalInstance
        );
        assert!(bmp.per_peer_header().is_ipv4());
        assert_eq!(bmp.per_peer_header().distinguisher(), [0; 8]);
        assert_eq!(
            bmp.per_peer_header().address(),
            Ipv4Addr::from_str("10.255.0.101").unwrap()
        );

        assert_eq!(bmp.per_peer_header().asn(), Asn::from_u32(64496));
        assert_eq!(bmp.per_peer_header().bgp_id(), [0x0a, 0x0a, 0x0a, 0x1]);
        assert_eq!(bmp.per_peer_header().ts_seconds(), 1419906571);
        assert_eq!(bmp.per_peer_header().ts_micros(), 920608);

        assert_eq!(
            bmp.per_peer_header().timestamp().to_string(),
            "2014-12-30 02:29:31.920608 UTC"
        );

        // Now the actual PeerUpNotification
        assert_eq!(bmp.local_address(), Ipv4Addr::new(10, 255, 0, 83));
        assert_eq!(bmp.local_port(), 36974);
        assert_eq!(bmp.remote_port(), 179);
        
        // Now, the two variable length BGP OPEN messages
        // first, the sent one
        let bgp_open_sent = bmp.bgp_open_sent();
        assert_eq!(bgp_open_sent.version(), 4);
        assert_eq!(bgp_open_sent.my_asn(), Asn::from_u32(64511));
        assert_eq!(bgp_open_sent.identifier(), [10, 10, 10, 103]);
        assert_eq!(bgp_open_sent.opt_parm_len(), 30);
        assert_eq!(bgp_open_sent.parameters().count(), 5);
        
        // second, the received one
        let bgp_open_rcvd = bmp.bgp_open_rcvd();
        assert_eq!(bgp_open_rcvd.version(), 4);
        assert_eq!(bgp_open_rcvd.my_asn(), Asn::from_u32(64496));
        assert_eq!(bgp_open_rcvd.identifier(), [10, 10, 10, 1]);
        assert_eq!(bgp_open_rcvd.opt_parm_len(), 30);
        assert_eq!(bgp_open_rcvd.parameters().count(), 5);

        let (sent, rcvd) = bmp.bgp_open_sent_rcvd();
        assert_eq!(sent.as_ref(), bgp_open_sent.as_ref());
        assert_eq!(rcvd, bgp_open_rcvd);
    }

    #[test]
    fn initiation_message() {
		// BMP Initiation Messsage with two Information TLVs:
        // sysDesc and sysName
		let buf = vec![
			0x03, 0x00, 0x00, 0x00, 0x6c, 0x04, 0x00, 0x01,
			0x00, 0x5b, 0x43, 0x69, 0x73, 0x63, 0x6f, 0x20,
			0x49, 0x4f, 0x53, 0x20, 0x58, 0x52, 0x20, 0x53,
			0x6f, 0x66, 0x74, 0x77, 0x61, 0x72, 0x65, 0x2c,
			0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
			0x20, 0x35, 0x2e, 0x32, 0x2e, 0x32, 0x2e, 0x32,
			0x31, 0x49, 0x5b, 0x44, 0x65, 0x66, 0x61, 0x75,
			0x6c, 0x74, 0x5d, 0x0a, 0x43, 0x6f, 0x70, 0x79,
			0x72, 0x69, 0x67, 0x68, 0x74, 0x20, 0x28, 0x63,
			0x29, 0x20, 0x32, 0x30, 0x31, 0x34, 0x20, 0x62,
			0x79, 0x20, 0x43, 0x69, 0x73, 0x63, 0x6f, 0x20,
			0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x73, 0x2c,
			0x20, 0x49, 0x6e, 0x63, 0x2e, 0x00, 0x02, 0x00,
			0x03, 0x78, 0x72, 0x33
		];
        let init: InitiationMessage<_> = Message::from_octets(&buf).unwrap().try_into().unwrap();
        assert_eq!(init.information_tlvs().count(), 2);
        let mut tlvs = init.information_tlvs();
        let tlv1 = tlvs.next().unwrap();
        assert_eq!(tlv1.typ(), InformationTlvType::SysDesc);
        assert_eq!(
            String::from_utf8_lossy(tlv1.value()),
            "Cisco IOS XR Software, Version 5.2.2.21I[Default]\
            \nCopyright (c) 2014 by Cisco Systems, Inc."
        );

        let tlv2 = tlvs.next().unwrap();
        assert_eq!(tlv2.typ(), InformationTlvType::SysName);
        assert_eq!(
            String::from_utf8_lossy(tlv2.value()),
            "xr3"
        );

    }

    #[test]
    fn termination_message() {
          // BMP Termination message
        let buf = vec![
            0x03, 0x00, 0x00, 0x00, 0x0C, 0x05, 0x00, 0x01, 0x00,
            0x02, 0x00, 0x03,
        ];
        let bmp: TerminationMessage<_> = Message::from_octets(&buf).unwrap().try_into().unwrap();
        assert_eq!(bmp.information().count(), 1);
        assert_eq!(
            bmp.information().next().unwrap(), 
            TerminationInformation::RedundantConnection,
        );

    }

    // XXX get proper RouteMirroring test data
    #[ignore]
    #[test]
    fn route_mirroring() {
        unimplemented!()
    }

    //--- Misc ---------------------------------------------------------------

    // As we rely on the `size_of` of some header types, make sure their size
    // is indeed what we expect it to be.
    //#[test]
    //fn header_sizes() {
    //    assert_eq!(std::mem::size_of::<CommonHeader>(), 6);
    //    assert_eq!(std::mem::size_of::<PerPeerHeader>(), 42);
    //}
    
}
