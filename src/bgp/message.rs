//! BGP message parsing.
//!
//! This module contains functionality to parse BGP messages from raw bytes,
//! providing access to its contents based on the underlying `bytes` buffer
//! without allocating.

use crate::flowspec::Component;
use log::{warn, error};

use bytes::Bytes;
use crate::asn::{Asn, AsPath, AsPathBuilder, SegmentType};
use crate::addr::{Prefix, PrefixError};
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use std::error::Error;

use crate::util::parser::{Parse, Parser, ParseError, OctetsRef};


use crate::typeenum; // from util::macros


// --- Error stuff, refactor this crate-wide after bgmp is merged ------------

/// Errors related to BGP messages.
#[derive(Debug)]
pub enum MessageError {
    IllegalNlris,
    InvalidMsgType,
}

impl Display for MessageError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        use MessageError::*;
        match self {
            IllegalNlris => write!(f, "illegal NLRIs"),
            InvalidMsgType => write!(f, "invalid Message type"),
        }
    }
}

impl Error for MessageError { }

impl From<PrefixError> for ParseError {
    fn from(_e: PrefixError) -> ParseError {
        ParseError::form_error("failed to parse prefix")
    }
}


// This file is, roughly, ordered in the following way.
//
// First, there is the generic Message type and the header that appears in all
// BGP messages. Then, an impl for each specific Message type with related
// types/iters, in order of RFC 4271. So OPEN, UPDATE, NOTIFICATION,
// KEEPALIVE, ROUTEREFRESH.  Thus, iterators for Path Attributes are in the
// Update part, etc.
//
// Following the impl's and helpers for these specific messages are the
// From/TryFroms for conversion of Generic<-->Specific messages.
//
// Last, some enums used for passing configuration/state.

//--- Generic BGP Message ----------------------------------------------------

/// BGP message enum.
///
/// Represents the full BGP message including the 16 byte marker, the message
/// header and the message payload.
///
/// To distinguish between message types, marker types are used. More details
/// on this can be found in the documentation for
/// [`bmp::Message`][`crate::bmp::Message`].
///
/// The available methods for each of the following message types are listed
/// per `impl` in the [Implementations][Message#implementations] overview.
///
///  * `MessageOpen`
///  * `MessageUpdate`
///  * `MessageNotification`
///  * TODO: `MessageKeepAlive`
///  * TODO: `MessageRouteRefresh`
///
pub enum Message {
    Open(MessageOpen),
    Update(MessageUpdate),
    Notification(MessageNotification),
}

/// BGP OPEN message, variant of the [`Message`] enum.
#[derive(Debug, Eq, PartialEq)]
pub struct MessageOpen {
    octets: Bytes,
}

/// BGP UPDATE message, variant of the [`Message`] enum.
pub struct MessageUpdate {
    octets: Bytes,
    four_octet_asn: FourOctetAsn,
    add_path: AddPath,
}

/// BGP NOTIFICATION message, variant of the [`Message`] enum.
pub struct MessageNotification {
    octets: Bytes,
}

impl Message {
    fn as_ref(&self) -> &[u8] {
        match self {
            Message::Open(m) => m.octets.as_ref(),
            Message::Update(m) => m.octets.as_ref(),
            Message::Notification(m) => m.octets.as_ref(),
        }
    }

    fn header(&self) -> Header {
        Header::for_slice(self.as_ref())
    }

    /// Returns the length in bytes of the entire BGP message.
	pub fn length(&self) -> u16 {
        self.header().length()
	}

    /// Returns the message type.
    pub fn msg_type(&self) -> MsgType {
        self.header().msg_type()
    }
}

impl MessageOpen {
    fn header(&self) -> Header {
        Header::for_slice(self.as_ref())
    }
    /// Returns the length in bytes of the entire BGP message.
	pub fn length(&self) -> u16 {
        self.header().length()
	}

    /// Returns a clone of the inner `Bytes`.
    pub fn bytes(&self) -> Bytes {
        self.octets.clone()
    }
}

impl AsRef<[u8]> for MessageOpen {
    fn as_ref(&self) -> &[u8] {
        self.octets.as_ref()
    }
}

impl MessageUpdate {
    fn header(&self) -> Header {
        Header::for_slice(self.as_ref())
    }
    /// Returns the length in bytes of the entire BGP message.
	pub fn length(&self) -> u16 {
        self.header().length()
	}
}

impl AsRef<[u8]> for MessageUpdate {
    fn as_ref(&self) -> &[u8] {
        self.octets.as_ref()
    }
}

impl MessageNotification {
    fn header(&self) -> Header {
        Header::for_slice(self.as_ref())
    }
    /// Returns the length in bytes of the entire BGP message.
	pub fn length(&self) -> u16 {
        self.header().length()
	}
}

impl AsRef<[u8]> for MessageNotification {
    fn as_ref(&self) -> &[u8] {
        self.octets.as_ref()
    }
}

impl TryFrom<Message> for MessageOpen {
    type Error = MessageError;
    fn try_from(msg: Message) -> Result<Self, Self::Error> {
        match msg {
            Message::Open(u) => Ok(u),
            _ => Err(MessageError::InvalidMsgType),
        }
    }
}

impl TryFrom<Message> for MessageUpdate {
    type Error = MessageError;
    fn try_from(msg: Message) -> Result<Self, Self::Error> {
        match msg {
            Message::Update(u) => Ok(u),
            _ => Err(MessageError::InvalidMsgType),
        }
    }
}

impl TryFrom<Message> for MessageNotification {
    type Error = MessageError;
    fn try_from(msg: Message) -> Result<Self, Self::Error> {
        match msg {
            Message::Notification(u) => Ok(u),
            _ => Err(MessageError::InvalidMsgType),
        }
    }
}


impl Message {
    pub fn from_octets<'a, B>(octets: B) -> Result<Message, ParseError>
    where
        B: 'a + AsRef<[u8]> + OctetsRef<Range = &'a [u8]>,
        //Bytes: From<B>,
    {
        Self::from_octets_with_sc(octets, SessionConfig::default())
    }

    // Pass config/state directly. Only useful for testing, or parsing of
    // stand-alone, individual messages.
    fn from_octets_with_sc<'a, B>(octets: B, config: SessionConfig) -> Result<Message, ParseError>
    where
        B: 'a + AsRef<[u8]> + OctetsRef<Range = &'a [u8]>,
        //Bytes: From<B>,
    {
        let mut parser = Parser::from_ref(octets, config);
        let hdr = Header::parse(&mut parser)?;
        parser.seek(0)?;
        let res = match hdr.msg_type() {
            MsgType::Open => Message::Open(MessageOpen::parse(&mut parser)?),
            MsgType::Update => Message::Update(MessageUpdate::parse(&mut parser)?),
            MsgType::Notification => Message::Notification(MessageNotification::parse(&mut parser)?),
            _ => panic!("not implemented yet")
        };
        Ok(res)
    }

    // XXX the from_octets now only takes a ref (because of associated Range
    // type in the OctetsRef bound), so this function makes no sense yet.
    pub fn from_ref<'a, B>(octets: B) -> Result<Message, ParseError>
    where
        B: 'a + AsRef<[u8]> + OctetsRef<Range = &'a [u8]>,
        //Bytes: From<B>,
    {
        let mut parser = Parser::from_ref(octets, SessionConfig::default());
        let hdr = Header::parse(&mut parser)?;
        parser.seek(0)?;
        Ok(
        match hdr.msg_type() {
            MsgType::Open => Message::Open(MessageOpen::parse(&mut parser)?),
            MsgType::Update => Message::Update(MessageUpdate::parse(&mut parser)?),
            MsgType::Notification => Message::Notification(MessageNotification::parse(&mut parser)?),
            _ => panic!("not implemented yet")
        }
        )
    }
}

//
// As per RFC4271:
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                                                               |
//  +                                                               +
//  |                                                               |
//  +                                                               +
//  |                           Marker                              |
//  +                                                               +
//  |                                                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |          Length               |      Type     |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// Offset of actual payload within message, so we can jump over the
// MessageHeader easily.
const COFF: usize = 19; // XXX replace this with .skip()'s?
        
/// BGP Message header.
#[derive(Clone, Copy, Default)]
pub struct Header<'a> {
    slice: &'a[u8],
}
impl<'a> Header<'a> {
    pub fn for_slice(s: &'a[u8]) -> Self {
        Header { slice: s}
    }

	pub fn length(&self) -> u16 {
		u16::from_be_bytes([self.slice[16], self.slice[17]])
	}

    pub fn msg_type(self) -> MsgType {
        match self.slice[18] {
            1 => MsgType::Open,
            2 => MsgType::Update,
            3 => MsgType::Notification,
            4 => MsgType::KeepAlive,
            5 => MsgType::RouteRefresh,
            u => panic!("illegal Message Type {}", u)
        }
    }
}

impl<'a, R> Parse<R> for Header<'a>
where
    R: AsRef<[u8]> + OctetsRef<Range = &'a[u8]>
{
    fn parse(parser: &mut Parser<R>) -> Result<Self, ParseError> {
        let pos = parser.pos();
        Marker::skip(parser)?;
        let _len = parser.parse_u16()?;
        let _typ = parser.parse_u8()?;
        parser.seek(pos)?;
        let res: &[u8] = parser.parse_octets(19)?;
        Ok(
            Header::for_slice(res)
        )
    }
    fn skip(parser: &mut Parser<R>) -> Result<(), ParseError> {
        Self::parse(parser).map(|_| ())
    }
}


//--- Specific BGP Messages --------------------------------------------------

// ---BGP Open----------------------------------------------------------------

/// BGP OPEN Message.
///
/// Offers methods to access and/or iterate over all the fields, and some
/// additional convenience methods.
///
/// ## Convenience methods
///
/// * [`my_asn()`][`MessageOpen::my_asn`]: returns the 32bit ASN if present,
/// otherwise falls back to the conventional 16bit ASN (though represented as
/// the 32bit [`routecore::asn::Asn`][`Asn`]);
/// * [`multiprotocol_ids()`][`MessageOpen::multiprotocol_ids`]: returns an
/// iterator over all the AFI/SAFI combinations listed as Capability in the
/// Optional Parameters. If this yields an empty iterator, one can assume the
/// default (IPv4/Unicast) can be used, but it is up to the user to handle as
/// such.
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+
//  |    Version    |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     My Autonomous System      |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |           Hold Time           |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                         BGP Identifier                        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  | Opt Parm Len  |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                                                               |
//  |             Optional Parameters (variable)                    |
//  |                                                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
impl MessageOpen {
    fn for_slice(s: &[u8]) -> Self {
        Self {
            octets: Bytes::copy_from_slice(s),
            //add_path: None,
        }
    }

    /// Returns the protocol version number, which should be 4.
    pub fn version(&self) -> u8 {
        self.octets.as_ref()[COFF]
    }

    /// Convenience method: returns the `Asn` from the Capabilities if any,
    /// otherwise the two-octet Asn from the 'My Autonomous System' field.
    pub fn my_asn(&self) -> Asn {
        if let Some(c) = self.capabilities().find(|c|
            c.typ() == CapabilityType::FourOctetAsn
        ) {
            Asn::from(
                u32::from_be_bytes(
                    c.value()
                .try_into().expect("parsed before"))
            )
        } else {
            self._my_asn()
        }
    }

    /// Returns the proposed value for the Hold Timer.
    pub fn holdtime(&self) -> u16 {
        u16::from_be_bytes([
            self.octets.as_ref()[COFF+3],
            self.octets.as_ref()[COFF+4]
        ])
    }

    /// Returns the BGP Identifier in raw format.
    pub fn identifier(&'_ self) -> &'_ [u8] {
        &self.octets.as_ref()[COFF+5..COFF+9]
    }

    /// Returns the length of the Optional Parameters. If 0, there are no
    /// Optional Parameters in this BGP OPEN message.
    pub fn opt_parm_len(&self) -> u8 {
        self.octets.as_ref()[COFF+9]
    }

    /// Returns an iterator over the Optional Parameters.
	pub fn parameters(&'_ self) -> ParameterIter<'_> {
        ParameterIter::new(
            &self.octets.as_ref()[
                COFF+10..COFF+10+self.opt_parm_len() as usize
            ]
        )
	}

    /// Returns an iterator over the Capabilities
    // Multiple Capabilities can be carried in a single Optional Parameter, or
    // multiple individual Optional Parameters can carry a single Capability
    // each. Hence the flatten.
	pub fn capabilities(&'_ self) -> impl Iterator<Item = Capability> {
        self.parameters().filter(|p|
            p.typ() == OptionalParameterType::Capabilities
        ).flat_map(|p|
            CapabilityIter::new(p.value())
        )
	}

    // This is the conventional, two-octet Asn. Possibly, the Capabilities at
    // the end of the OPEN message list the actual (4-byte) ASN.
    // If so, and the 4-byte ASN is non-mappable (i.e it can not be
    // represented in 2 bytes), the ASN field here should contain AS_TRANS.
    // We do however not check or enforce that.
    fn _my_asn(&self) -> Asn {
        Asn::from(
            u16::from_be_bytes([
                self.octets.as_ref()[COFF+1],
                self.octets.as_ref()[COFF+2]
            ]) as u32
        )
    }

    /// Returns true if this message contains the Four-Octet-Capable
    /// capability in the Optional Parameters.
    pub fn four_octet_capable(&self) -> bool {
        self.capabilities().any(|c|
            c.typ() == CapabilityType::FourOctetAsn
        )
    }

    // FIXME this should return a AFI/SAFI combination, not a bool
    pub fn add_path_capable(&self) -> bool {
        self.capabilities().any(|c|
            c.typ() == CapabilityType::AddPath
        )
    }

    /// Returns an iterator over `(AFI, SAFI)` tuples listed as
    /// MultiProtocol Capabilities in the Optional Parameters of this message.
    pub fn multiprotocol_ids(&self) -> impl Iterator<Item = (AFI,SAFI)> + '_ {
        let res = self.capabilities().filter(|c|
            c.typ() == CapabilityType::MultiProtocol
            ).map(|mp_cap| {
            let afi = u16::from_be_bytes([
                mp_cap.value()[0],
                mp_cap.value()[1]
            ]);
            let safi = mp_cap.value()[3];
            (afi.into(), safi.into())
        });
        res
    }

}

impl<'a, R> Parse<R> for MessageOpen
where
    R: 'a + AsRef<[u8]> + OctetsRef<Range = &'a[u8]>
{
    fn parse(parser: &mut Parser<R>) -> Result<Self, ParseError> {
        // parse header
        let pos = parser.pos();
        let hdr = Header::parse(parser)?;

        let _version = parser.parse_u8()?;
        let _my_as = parser.parse_u16()?;
        let _hold_timer = parser.parse_u16()?;
        let _bgp_id = parser.parse_u32()?;

        let mut opt_param_len = parser.parse_u8()? as usize;
        if opt_param_len > parser.remaining() {
            return Err(
                ParseError::ShortInput
            );
        }

        while opt_param_len > 0 {
            let param = Parameter::parse(parser)?;
            opt_param_len -= 2 + param.length() as usize;
        }

        let end = parser.pos();
        if end - pos != hdr.length() as usize {
            return Err(ParseError::form_error(
                "message length and parsed bytes do not match"
            ));
        }
        parser.seek(pos)?;

        Ok(
            Self::for_slice(parser.parse_octets(hdr.length().into())?)
        )

    }

    fn skip(parser: &mut Parser<R>) -> Result<(), ParseError> {
        Self::parse(parser).map(|_| ())
    }
}

impl<'a, R> Parse<R> for Parameter<'a> 
where
    R: 'a + AsRef<[u8]> + OctetsRef<Range = &'a[u8]>
{
    fn parse(parser: &mut Parser<R>) -> Result<Self, ParseError> {
        let pos = parser.pos();
        let typ = parser.parse_u8()?;
        let len = parser.parse_u8()? as usize;
        if typ == 2 {
            // There might be more than Capability within a single Optional
            // Parameter, so we need to loop.
            while parser.pos() < pos + len {
                Capability::parse(parser)?;
            }
        } else {
            warn!("Optional Parameter in BGP OPEN other than Capability: {}",
                typ
            );
        }
        parser.seek(pos)?;
        Ok(
            Self::for_slice(
                parser.parse_octets(2+len)?
            )
        )
    }
    fn skip(parser: &mut Parser<R>) -> Result<(), ParseError> {
        Self::parse(parser).map(|_| ())
    }
}

impl<'a, R> Parse<R> for Capability<'a> 
where
    R: 'a + AsRef<[u8]> + OctetsRef<Range = &'a[u8]>
{
    fn parse(parser: &mut Parser<R>) -> Result<Self, ParseError> {
        let pos = parser.pos();
        let typ = parser.parse_u8()?;
        let len = parser.parse_u8()? as usize;
        match typ.into() {
            CapabilityType::Reserved => {
                warn!("Capability type Reserved");
            },
            CapabilityType::MultiProtocol => {
                let _afi = parser.parse_u16()?;
                let _rsvd = parser.parse_u8()?;
                let _safi = parser.parse_u8()?;
            },
            CapabilityType::RouteRefresh => {
                if len != 0 {
                    return Err(ParseError::form_error(
                            "RouteRefresh Capability with length > 0"
                    ));
                }
            },
            CapabilityType::OutboundRouteFiltering => {
                let _afi = parser.parse_u16()?;
                let _rsvd = parser.parse_u8()?;
                let _safi = parser.parse_u8()?;

                let num_orfs = parser.parse_u8()?;
                for _ in 0..num_orfs {
                    let _orf_type = parser.parse_u8()?;
                    let _send_receive = parser.parse_u8()?;
                }
            },
            CapabilityType::ExtendedNextHop => {
                while parser.pos() < pos + len {
                    let _afi = parser.parse_u16()?;
                    // Note that SAFI is 2 bytes for this Capability.
                    let _safi = parser.parse_u16()?;
                    let _nexthop_afi = parser.parse_u16()?;
                }
            },
            CapabilityType::ExtendedMessage => {
                if len != 0 {
                    return Err(ParseError::form_error(
                            "ExtendedMessage Capability with length > 0"
                    ));
                }
            },
            CapabilityType::MultipleLabels => {
                while parser.pos() < pos + len {
                    let _afi = parser.parse_u16()?;
                    let _safi = parser.parse_u8()?;
                    let _count = parser.parse_u8()?;
                }
            },
            CapabilityType::BgpRole => {
                if len != 1 {
                    return Err(ParseError::form_error(
                            "ExtendedMessage Capability with length != 1"
                    ));
                }
                let _role = parser.parse_u8()?;
            },
            CapabilityType::GracefulRestart => {
                let _restart_flags_and_time = parser.parse_u16()?;
                while parser.pos() < pos + len {
                    let _afi = parser.parse_u16()?;
                    let _safi = parser.parse_u8()?;
                    let _flags = parser.parse_u8()?;
                }
            },
            CapabilityType::FourOctetAsn => {
                let _asn = parser.parse_u32()?;
            },
            CapabilityType::DeprecatedDynamicCapability 
            | CapabilityType::DynamicCapability => {
                for _ in 0..len {
                    let _cap = parser.parse_u8()?;
                }
            },
            CapabilityType::Multisession => {
                let _flags = parser.parse_u8()?;
                for _ in 0..len-1 {
                    let _session_id = parser.parse_u8()?;
                }
            },
            CapabilityType::AddPath => {
                let _afi = parser.parse_u16()?;
                let _safi = parser.parse_u8()?;
                let send_receive = parser.parse_u8()?;
                if send_receive > 3 {
                    return Err(ParseError::form_error(
                            "Capability AddPath send/receive not 1,2 or 3"
                    ))
                }
            },
            CapabilityType::EnhancedRouteRefresh => {
                if len != 0 {
                    return Err(ParseError::form_error(
                            "EnhancedRouteRefresh Capability with length > 0"
                    ));
                }
            },
            CapabilityType::LongLivedGracefulRestart => {
                while parser.pos() < pos + len {
                    let _afi = parser.parse_u16()?;
                    let _safi = parser.parse_u8()?;
                    let _flags = parser.parse_u8()?;
                    // 24 bits of staletime
                    let _ll_staletime_1 = parser.parse_u16()?;
                    let _ll_staletime_2 = parser.parse_u8()?;
                }
            },
            CapabilityType::FQDN => {
                let hostname_len = parser.parse_u8()? as usize;
                parser.advance(hostname_len)?;
                let domain_len = parser.parse_u8()? as usize;
                parser.advance(domain_len)?;
            },
            CapabilityType::PrestandardRouteRefresh => {
                if len > 0 {
                    warn!("PrestandardRouteRefresh with len > 0, capture me for testing purposes!");
                    return Err(ParseError::form_error(
                            "PrestandardRouteRefresh len > 0"
                    ));
                }
                while parser.pos() < pos + len {
                    let _afi = parser.parse_u16()?;
                    let _safi = parser.parse_u8()?;
                    let _flags = parser.parse_u8()?;
                }
            },
            CapabilityType::PrestandardOutboundRouteFiltering => {
                let _afi = parser.parse_u16()?;
                let _rsvd = parser.parse_u8()?;
                let _safi = parser.parse_u8()?;

                let num_orfs = parser.parse_u8()?;
                for _ in 0..num_orfs {
                    let _orf_type = parser.parse_u8()?;
                    let _send_receive = parser.parse_u8()?;
                }
            },
            CapabilityType::PrestandardMultisession => {
                let _flags = parser.parse_u8()?;
                for _ in 0..len-1 {
                    let _session_id = parser.parse_u8()?;
                }
            }
            CapabilityType::Unimplemented(u) => {
                warn!("Unimplemented Capability: {}", u);
            },
        }

        parser.seek(pos)?;
        Ok(
            Self::for_slice(
                parser.parse_octets(2+len)?
            )
        )
    }
    fn skip(parser: &mut Parser<R>) -> Result<(), ParseError> {
        Self::parse(parser).map(|_| ())
    }
}


//--- Helpers / types related to BGP OPEN ------------------------------------

/// BGP Capability Optional parameter.
// As per RFC3392:
//
//  +------------------------------+
//  | Capability Code (1 octet)    |
//  +------------------------------+
//  | Capability Length (1 octet)  |
//  +------------------------------+
//  | Capability Value (variable)  |
//  +------------------------------+
//
// Also see
// <https://www.iana.org/assignments/capability-codes/capability-codes.xhtml>

#[derive(Debug)]
pub struct Capability<'a> {
    octets: &'a [u8],
}
impl <'a>Capability<'a> {
    pub fn for_slice(octets: &'a [u8]) -> Capability<'a> {
        Capability {
            octets
        }
    }

    /// Returns the [`CapabilityType`] of this capability.
    pub fn typ(&self) -> CapabilityType {
        self.octets[0].into()
    }

    pub fn length(&self) -> u8 {
        self.octets[1]
    }

    pub fn value(&'_ self) -> &'_ [u8] {
        &self.octets[2..]
    }
}

/// Iterator for BGP OPEN Capabilities.
pub struct CapabilityIter<'a> {
	octets: &'a [u8],
	pos: usize
}

impl<'a> CapabilityIter<'a> {
    pub fn new(slice: &'a [u8]) -> CapabilityIter<'a>
    {
        CapabilityIter {
            octets: slice,
            pos: 0,
        }
    }

    pub fn get_capability(&mut self) -> Capability<'a> {
        let len = self.octets[self.pos+1] as usize;
        let res = Capability::for_slice(&self.octets[self.pos..(self.pos + 2 + len)]);
        self.pos += 2 + len;
        res
    }
}

impl<'a> Iterator for CapabilityIter<'a> {
    type Item = Capability<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos == self.octets.len() {
            return None;
        }
        Some(self.get_capability())
    }
}

typeenum!(
/// BGP Capability type, as per
/// <https://www.iana.org/assignments/capability-codes/capability-codes.xhtml>.
    CapabilityType, u8,
    0 => Reserved,
    1 => MultiProtocol,
    2 => RouteRefresh,
    3 => OutboundRouteFiltering,
    5 => ExtendedNextHop,
    6 => ExtendedMessage,
    8 => MultipleLabels,
    9 => BgpRole,
    //10..=63 => Unassigned,
    64 => GracefulRestart,
    65 => FourOctetAsn,
    66 => DeprecatedDynamicCapability,
    67 => DynamicCapability,
    68 => Multisession,
    69 => AddPath,
    70 => EnhancedRouteRefresh,
    71 => LongLivedGracefulRestart,
    73 => FQDN,
    128 => PrestandardRouteRefresh,
    130 => PrestandardOutboundRouteFiltering,
    131 => PrestandardMultisession,
);

typeenum!(
/// BGP OPEN Optional Parameter type, as per
/// <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-11>.
    OptionalParameterType, u8,
    0 => Reserved,
    1 => Authentication,
    2 => Capabilities,
    //3..=254 => Unassigned,
    255 => ExtendedLength
);


// Optional Parameter
// 0                   1
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...
// |  Parm. Type   | Parm. Length  |  Parameter Value (variable)
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...
//
// also see
// https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-11
/// BGP OPEN Optional Parameter.
pub struct Parameter<'a> {
    octets: &'a [u8],
}

impl <'a>Parameter<'a> {
    pub fn for_slice(slice: &'a [u8]) -> Parameter<'a> {
        Parameter {
            octets: slice
        }
    }
    pub fn typ(&self) -> OptionalParameterType {
        self.octets[0].into()
    }
    
    pub fn length(&self) -> u8 {
        self.octets[1]
    }

    pub fn value(&self) -> &'a[u8] {
        &self.octets[2..]
    }
}

/// Iterator over BGP OPEN Optional [`Parameter`]s.
pub struct ParameterIter<'a> {
	octets: &'a [u8],
	pos: usize
}

impl<'a> ParameterIter<'a> {
    pub fn new(slice: &'a [u8]) -> ParameterIter<'a>
    {
        ParameterIter {
            octets: slice,
            pos: 0,
        }
    }

    pub fn get_parameter(&mut self) -> Parameter<'a> {
        let len = self.octets[self.pos+1] as usize;
        let res = Parameter::for_slice(&self.octets[self.pos..(self.pos + 2 + len)]);
        self.pos += 2 + len;
        res
    }
}

impl<'a> Iterator for ParameterIter<'a> {
    type Item = Parameter<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos == self.octets.len() {
            return None;
        }
        Some(self.get_parameter())
    }
}



/// BGP UPDATE message.
///
/// Offers methods to access and/or iterate over all the fields, and some
/// additional convenience methods.
///
/// ## Convenience methods
///
/// As the BGP standard has seen updates to support for example 32 bits ASNs
/// and other-than-IPv4 protocol information, some types of information can be
/// found in different places in the UPDATE message. The NLRIs for announced
/// prefixes can be at the end of the message, or in a `MP_REACH_NLRI` path
/// attribute. Similarly, the `NEXT_HOP` path attribute was once mandatory for
/// UPDATEs, but is now also part of the `MP_REACH_NLRI`, if present.
///
/// To accomodate for these hassles, the following methods are provided:
///
/// * [`nlris()`][`MessageUpdate::nlris`] and
/// [`withdrawals()`][`MessageUpdate::withdrawals`],
/// providing iterators over announced and withdrawn prefixes ;
/// * [`next_hop()`][`MessageUpdate::next_hop`], returning the [`NextHop`] ;
/// * [`all_communities()`][`MessageUpdate::all_communities`], returning an
/// optional `Vec` containing all conventional, Extended and Large
/// Communities, wrapped in the [`Community`] enum.
///
/// For the mandatory path attributes, we have:
///
/// * [`origin()`][`MessageUpdate::origin`]
/// * [`aspath()`][`MessageUpdate::aspath`]
///
/// Other path attributes ([`PathAttribute`] of a certain
/// [`PathAttributeType`]) can be access via the iterator provided via
/// [`path_attributes()`][`MessageUpdate::path_attributes`].
///
// ---BGP Update--------------------------------------------------------------
//
//  +-----------------------------------------------------+
//  |   Withdrawn Routes Length (2 octets)                |
//  +-----------------------------------------------------+
//  |   Withdrawn Routes (variable)                       |
//  +-----------------------------------------------------+
//  |   Total Path Attribute Length (2 octets)            |
//  +-----------------------------------------------------+
//  |   Path Attributes (variable)                        |
//  +-----------------------------------------------------+
//  |   Network Layer Reachability Information (variable) |
//  +-----------------------------------------------------+

impl MessageUpdate {
    fn for_slice(s: &[u8], four_octet_asn: FourOctetAsn, add_path: AddPath) -> Self {
        Self {
            octets: Bytes::copy_from_slice(s),
            four_octet_asn,
            add_path,
        }
    }
    /// Print the Message in a `text2pcap` compatible way.
    pub fn print_pcap(&self) {
        print!("000000 ");
        for b in self.octets.as_ref() {
            print!("{:02x} ", b);
        }
        println!();
    }

	pub fn withdrawn_routes_len(&self) -> u16 {
        u16::from_be_bytes([
            self.octets.as_ref()[COFF],
            self.octets.as_ref()[COFF+1]
        ])
	}

    pub fn withdrawals(&self) -> WithdrawalsIterMp<&[u8]> {
        let mut sc = SessionConfig::default();
        if self.add_path == AddPath::Enabled  {
            sc.enable_addpath();
        }
        if let Some(pa) = self.path_attributes().find(|pa|
            pa.type_code() == PathAttributeType::MpUnreachNlri
        ) {
            let mut parser = Parser::from_ref(
                pa.value(),
                sc,
            );
            WithdrawalsIterMp::parse(&mut parser).expect("parsed before")
        } else {
            let len = self.withdrawn_routes_len() as usize;
            let parser = Parser::from_ref(
                &self.as_ref()[COFF+2..COFF+2+len],
                sc,
            );
            WithdrawalsIterMp::new(parser, AFI::Ipv4, SAFI::Unicast)
        }
    }

    // RFC4271: A value of 0 indicates that neither the Network Layer
    // Reachability Information field nor the Path Attribute field is present
    // in this UPDATE message.
	fn total_path_attribute_len(&self) -> u16 {
        let wrl = self.withdrawn_routes_len() as usize;
        u16::from_be_bytes([
            self.octets.as_ref()[COFF+2+wrl],
            self.octets.as_ref()[COFF+2+wrl+1]
        ])
	}

    pub fn path_attributes(&self) -> PathAttributes<&[u8]> {
        let mut sc = SessionConfig::default();
        sc.set_four_octet_asn(self.four_octet_asn);
        sc.set_addpath(self.add_path);

        let wrl = self.withdrawn_routes_len() as usize;
        let tpal = self.total_path_attribute_len() as usize;
        
        let mut parser = Parser::from_ref(
            &self.as_ref()[COFF+2+wrl+2..COFF+2+wrl+2+tpal],
            sc,
        );

        PathAttributes::parse(&mut parser).expect("parsed before")
        // Or for debugging:
        //PathAttributes::parse(&mut parser).map_err(|e| {
        //    self.print_pcap();
        //    e
        //}).unwrap()
    }

    /// Iterator over the reachable NLRIs.
    ///
    /// If present, the NLRIs are taken from the MP_REACH_NLRI path attribute.
    /// Otherwise, they are taken from their conventional place at the end of
    /// the message.
    pub fn nlris(&self) -> NlriIterMp<&[u8]> {
        let mut sc = SessionConfig::default();
        if self.add_path == AddPath::Enabled {
            sc.enable_addpath();
        }
        if let Some(pa) = self.path_attributes().find(|pa|
            pa.type_code() == PathAttributeType::MpReachNlri
        ) {
            let parser = Parser::from_ref(pa.value(), sc);
            NlriIterMp::new(parser)
        } else {

            let wrl = self.withdrawn_routes_len() as usize;
            let tpal = self.total_path_attribute_len() as usize;
             
            let parser = Parser::from_ref(
                &self.as_ref()[COFF+2+wrl+2+tpal..],
                sc,
            );
            NlriIterMp::new_conventional(parser)
        }
    }

    /// Returns `Option<(AFI, SAFI)>` if this UPDATE represents the End-of-RIB
    /// marker for a AFI/SAFI combination.
    pub fn is_eor(&self) -> Option<(AFI, SAFI)> {
        // Conventional BGP
        if self.length() == 23 {
            // minimum length for a BGP UPDATE indicates EOR
            // (no annoucements, no withdrawals)
            return Some((AFI::Ipv4, SAFI::Unicast));
        }

        // Based on MP_UNREACH_NLRI
        if self.total_path_attribute_len() > 0
            &&
                self.path_attributes().all(|pa|
                    pa.type_code() == PathAttributeType::MpUnreachNlri
                    && pa.length() == 3 // only AFI/SAFI, no NLRI
        ) {
                    let pa = self.path_attributes().next().unwrap();
                    return Some((
                            u16::from_be_bytes(
                                [pa.value()[0], pa.value()[1]]
                            ).into(),
                            pa.value()[2].into()
                    ));
        }

        None
    }

    //--- Methods to access mandatory path attributes ------------------------
    // Mandatory path attributes are ORIGIN, AS_PATH and NEXT_HOP
    // Though, in case of MP_REACH_NLRI, NEXT_HOP must be ignored if present.
    //
    // Also note that these are only present in announced routes. A BGP UPDATE
    // with only withdrawals will not have any of these mandatory path
    // attributes present.
    pub fn origin(&self) -> Option<OriginType> {
        self.path_attributes().find(|pa|
            pa.type_code() == PathAttributeType::Origin
        ).map(|pa|
            match pa.value()[0] {
                0 => OriginType::Igp,
                1 => OriginType::Egp,
                2 => OriginType::Incomplete,
                n => OriginType::Unknown(n),
            }
        )
    }

    // Try to determine whether we are dealing with an AS_PATH comprised of
    // two-octet ASNs. As some BMP/BGP implementations seem to be not too
    // strict about these things, we have to make an educated guess.
    //
    // XXX we perhaps should not guess anything, just error out instead
    fn guess_as_octets(pa: &PathAttribute) -> u8 {
        assert!(pa.type_code() == PathAttributeType::AsPath);
        let res = 4;

        let octets = pa.value();
        let mut pos = 0;
        while pos < octets.len() {
            match SegmentType::try_from(octets[pos]) {
                Ok(_) => { /* continue to assume 4 octet ASNs */ },
                Err(_) => { return 2 }
            }
            let segmentlen = octets[pos+1] as usize;
            if segmentlen * 4 > octets.len(){
                return 2;
            }
            // assume we are dealing with 4 octet stuff here
            pos = pos + 2 + segmentlen * 4;
        }

        if pos > octets.len() {
            // Apparently we jumped over the end, so assuming 4 bytes was
            // incorrect. 
            return 2;
        }

        assert!(pos == octets.len());

        res
    }

    pub fn as4path(&self) -> Option<AsPath<Vec<Asn>>> {
        self.path_attributes().find(|pa|
            pa.type_code() == PathAttributeType::As4Path
        ).map(|pa| {
            let asn_size = 4;
            let octets = pa.value();
            let mut aspb = AsPathBuilder::new();

            let mut pos = 0;
            while pos < octets.len() {
                let st = SegmentType::try_from(octets[pos])
                    .expect("parsed before");
                let num_asns = octets[pos+1] as usize;
                aspb.start(st);
                pos += 2;

                for _ in 0..num_asns {
                    let asn = Asn::from(
                        u32::from_be_bytes(
                            octets[pos..pos+asn_size]
                            .try_into().expect("parsed before")
                        )
                    );
                    aspb.push(asn).expect("parsed before");
                    pos += asn_size;
                }
            }
            aspb.finalize()
        })
    }

    pub fn aspath(&self) -> Option<AsPath<Vec<Asn>>> {
        if let Some(as4path) = self.as4path() {
            // In all cases we know of, the AS4_PATH attribute contains
            // the entire AS_PATH with all the 4-octet ASNs. Instead of
            // replacing the AS_TRANS ASNs in AS_PATH, we can simply
            // return the AS4_PATH. 
            // This also saves us from perhaps misguessing the 2-vs-4
            // octet size of the AS_PATH, as the AS4_PATH is always 4-octet
            // anyway.
            return Some(as4path);
        }
        self.path_attributes().find(|pa|
            pa.type_code() == PathAttributeType::AsPath
        ).map(|ref pa| {
            // Check for AS4_PATH
            // Note that all the as4path code in this part is useless because
            // of the early return above, but for now let's leave it here for
            // understanding/reasoning.
            let as4path = self.as4path();


            // Apparently, some BMP exporters do not set the legacy format
            // bit but do emit 2-byte ASNs. 
            let asn_size =
                if self.four_octet_asn == FourOctetAsn::Disabled {
                    let guess = Self::guess_as_octets(pa) as usize;
                    if guess != 2 {
                        warn!("Had to guess ASN size is 4 !");
                    }
                    guess
                } else {
                    4
                };

            let octets = pa.value();
            let mut aspb = AsPathBuilder::new();

            let mut pos = 0;
            let mut segment_idx = 0;
            while pos < octets.len() {
                let st = SegmentType::try_from(octets[pos]).expect("parsed
                    before");
                let num_asns = octets[pos+1] as usize;
                aspb.start(st);
                pos += 2;

                for _ in 0..num_asns {
                    let asn = if asn_size == 4 {
                    Asn::from(
                        u32::from_be_bytes(
                            octets[pos..pos+asn_size]
                            .try_into().expect("parsed before")
                            )
                        )
                    } else {
                    Asn::from(
                        u16::from_be_bytes(
                            octets[pos..pos+asn_size]
                            .try_into().expect("parsed before")
                            ) as u32
                        )
                    };
                    // In a very exotic (and incorrect?) case, we see AS_TRANS
                    // in the AS_PATH, but no AS4_PATH path attribute. For
                    // this reason, we check whether `as4path` actually holds
                    // a value.
                    if as4path.as_ref().is_some()
                        && asn == Asn::from_u32(23456) {
                        // This assert would trip the described exotic case.
                        //assert!(as4path.is_some());
                         
                        // replace this AS_TRANS with the 4-octet value from
                        // AS4_PATH:
                        let seg = as4path.as_ref().expect("parsed before")
                            .iter().nth(segment_idx).expect("parsed before");
                        let new_asn: Asn = seg.elements()[aspb.segment_len()];
                        aspb.push(new_asn).expect("parsed before");
                    } else {
                        aspb.push(asn).expect("parsed before");
                    }
                    pos += asn_size;
                }
                segment_idx += 1;
            }
            aspb.finalize()
        })
    }

    pub fn next_hop(&self) -> Option<NextHop> {
        if let Some(pa) = self.path_attributes().find(|pa|
            pa.type_code() == PathAttributeType::MpReachNlri
        ) {
            let mut parser = Parser::from_ref(
                pa.value(),
                SessionConfig::default()
            );
            let afi: AFI = parser.parse_u16().expect("parsed before").into();
            let safi: SAFI = parser.parse_u8().expect("parsed before").into();

            parser.config_mut().set_afi(afi);
            parser.config_mut().set_safi(safi);

            return Some(NextHop::parse(&mut parser).expect("parsed before"));
        } 

        self.path_attributes().find(|pa|
            pa.type_code() == PathAttributeType::NextHop
        ).map(|pa|
            NextHop::Ipv4(
                Ipv4Addr::new(
                    pa.value()[0],
                    pa.value()[1],
                    pa.value()[2],
                    pa.value()[3],
                )
            )
        )
    }

    //--- Non-mandatory path attribute helpers -------------------------------

    /// Returns the Multi-Exit Discriminator value, if any.
    pub fn multi_exit_desc(&self) -> Option<MultiExitDisc> {
        self.path_attributes().find(|pa|
            pa.type_code() == PathAttributeType::MultiExitDisc
        ).map(|pa|
            MultiExitDisc(u32::from_be_bytes(
                    pa.value()[0..4].try_into().expect("parsed before")
            ))
        )
    }

    /// Returns the Local Preference value, if any.
    pub fn local_pref(&self) -> Option<LocalPref> {
        self.path_attributes().find(|pa|
            pa.type_code() == PathAttributeType::LocalPref
        ).map(|pa|
            LocalPref(u32::from_be_bytes(
                    pa.value()[0..4].try_into().expect("parsed before")
            ))
        )
    }

    /// Returns true if this UPDATE contains the ATOMIC_AGGREGATE path
    /// attribute.
    pub fn is_atomic_aggregate(&self) -> bool {
        self.path_attributes().any(|pa|
            pa.type_code() == PathAttributeType::AtomicAggregate
        )
    }

    // this one originally carried a 2-octet ASN, but now also possibly a
    // 4-octet one (RFC 6793, Four Octet ASN support)
    // furthermore, it was designed to carry a IPv4 address, but that does not
    // seem to have changed with RFC4760 (multiprotocol)
    //
    // As such, we can determine whether there is a 2-octet or 4-octet ASN
    // based on the size of the attribute itself.
    // 
    pub fn aggregator(&self) -> Option<Aggregator> {
        self.path_attributes().find(|pa|
            pa.type_code() == PathAttributeType::Aggregator
        ).map(|pa| {
            let mut sc = SessionConfig::default();
            sc.set_four_octet_asn(self.four_octet_asn);

            let mut p = Parser::from_ref(pa.value(), sc);
            Aggregator::parse(&mut p).expect("parsed before")
        })
    }


    //--- Communities --------------------------------------------------------

    pub fn communities(&self) -> Option<CommunityIter> {
        self.path_attributes().find(|pa|
            pa.type_code() == PathAttributeType::Communities
        ).map(|pa| CommunityIter::new(pa.value())
        )
    }

    pub fn ext_communities(&self) -> Option<ExtCommunityIter> {
        self.path_attributes().find(|pa|
            pa.type_code() == PathAttributeType::ExtendedCommunities
        ).map(|pa| ExtCommunityIter::new(pa.value())
        )
    }

    pub fn large_communities(&self) -> Option<LargeCommunityIter> {
        self.path_attributes().find(|pa|
            pa.type_code() == PathAttributeType::LargeCommunities
        ).map(|pa| LargeCommunityIter::new(pa.value())
        )
    }

    /// Returns an optional `Vec` containing all conventional, Extended and
    /// Large communities, if any, or None if none of the three appear in the
    /// path attributes of this message.
    pub fn all_communities(&self) -> Option<Vec<Community>> {
        let mut res = Vec::<Community>::new();

        // We can use unwrap safely because the is_some check.

        if self.communities().is_some() {
            res.append(&mut self.communities().unwrap().collect::<Vec<_>>());
        }
        if self.ext_communities().is_some() {
            res.append(&mut self.ext_communities().unwrap()
                .map(Community::Extended)
                .collect::<Vec<_>>());
        }
        if self.large_communities().is_some() {
            res.append(&mut self.large_communities().unwrap()
                .map(Community::Large)
                .collect::<Vec<_>>());
        }

        if res.is_empty() {
            None
        } else {
            Some(res)
        }
    }
    
}

struct Marker;
impl<R> Parse<R> for Marker 
where
    R: AsRef<[u8]>
{
    fn parse(parser: &mut Parser<R>) -> Result<Self, ParseError> {
        for _ in 0..4 {
           if parser.parse_u32()? != 0xffffffff {
               return Err(ParseError::form_error("invalid BGP marker"))
           }
        }
       Ok(Marker{})
    }
    fn skip(parser: &mut Parser<R>) -> Result<(), ParseError> {
        Self::parse(parser).map(|_| ())
    }
}

impl<'a, R> Parse<R> for MessageUpdate
where
    R: 'a + AsRef<[u8]> + OctetsRef<Range = &'a[u8]>
{
    fn parse(parser: &mut Parser<R>) -> Result<Self, ParseError> {
        // parse header
        let pos = parser.pos();
        let hdr = Header::parse(parser)?;

        let withdrawn_len = parser.parse_u16()?;
        if withdrawn_len > 0 {
            let mut wdraw_parser = Parser::from_ref(
                parser.parse_octets(withdrawn_len as usize)?,
                parser.config(),
            );
            while wdraw_parser.remaining() > 0 {
                BasicNlri::parse(&mut wdraw_parser)?;
            }
        }
        let total_path_attributes_len = parser.parse_u16()?;
        if total_path_attributes_len > 0 {
            // parse pa's
            let pas = parser.parse_octets(total_path_attributes_len.into())?;
            let mut pas_parser = Parser::from_ref(pas, parser.config());
            <PathAttributes<&[u8]> as Parse<&[u8]>>::skip(&mut pas_parser)?;
        }

        // conventional NLRI, if any
        while parser.remaining() > 0 {
            BasicNlri::parse(parser)?;
        }

        let end = parser.pos();
        if end - pos != hdr.length() as usize {
            return Err(ParseError::form_error(
                "message length and parsed bytes do not match"
            ));
        }
        parser.seek(pos)?;

        Ok(
            Self::for_slice(
                parser.parse_octets(hdr.length().into())?,
                parser.config().four_octet_asn,
                parser.config().add_path,
            )
        )

    }

    fn skip(parser: &mut Parser<R>) -> Result<(), ParseError> {
        Self::parse(parser).map(|_| ())
    }
}

impl Debug for MessageUpdate
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let mut r = write!(f, " AS_PATH: {:?}\n \
                    NEXT_HOP: {:?}\n \
                    ORIGIN: {:?}\n \
                    NLRIs: ",
            &self.aspath(),
            &self.next_hop(),
            &self.origin(),
        );
        let mut first = true;
        for nlri in self.nlris() {
            if first {
                first = false
            } else {
                let _ = write!(f, ", ");
            }
            r = write!(f, "{}", nlri)
        }
        let _ = writeln!(f);
        let _ = write!(f, "Withdraws: ");
        first = true;
        for withdraw in self.withdrawals() {
            if first {
                first = false
            } else {
                let _ = write!(f, ", ");
            }
            r = write!(f, "{}", withdraw)
        }
        r
    }
}

//--- Helpers / types related to BGP UPDATE ----------------------------------
//
// - Path Attributes
// - NLRI
// - Communities

//--- Path Attributes --------------------------------------------------------
//

typeenum!(
/// PathAttributeType
///
/// As per:
/// <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-2>
    PathAttributeType, u8,
    0 => Reserved,
    1 => Origin,
    2 => AsPath,
    3 => NextHop,
    4 => MultiExitDisc,
    5 => LocalPref,
    6 => AtomicAggregate,
    7 => Aggregator,
    8 => Communities,
    9 => OriginatorId,
    10 => ClusterList,
    14 => MpReachNlri,
    15 => MpUnreachNlri,
    16 => ExtendedCommunities,
    17 => As4Path,
    18 => As4Aggregator,
    20 => Connector,
    21 => AsPathLimit,
    22 => PmsiTunnel,
    32 => LargeCommunities,
    128 => AttrSet,
    255 => RsrvdDevelopment,
);

/// Conventional and BGP-MP Next Hop variants.
#[derive(Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum NextHop {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Ipv6LL(Ipv6Addr, Ipv6Addr),
    Ipv4MplsVpnUnicast(RouteDistinguisher, Ipv4Addr),
    Ipv6MplsVpnUnicast(RouteDistinguisher, Ipv6Addr),
    Empty, // FlowSpec
    Unimplemented(AFI, SAFI),
}

/// Iterator over all [`PathAttribute`]s in a BGP UPDATE message.
pub struct PathAttributes<Ref> {
    parser: Parser<Ref>,
}

impl<'a, R> Parse<R> for PathAttributes<R> 
where
    R: 'a + AsRef<[u8]> + Copy + OctetsRef<Range = &'a [u8]>
{
    fn parse(parser: &mut Parser<R>) -> Result<Self, ParseError> {

        let res = *parser;
        
        while parser.remaining() > 0 {
            let _pa = PathAttribute::parse(parser)?;
        }
        Ok(
            PathAttributes {
                parser: res
            }
        )
    }

    fn skip(parser: &mut Parser<R>) -> Result<(), ParseError> {
        Self::parse(parser).map(|_| ())
    }
}

/// BGP Path Attribute, carried in BGP UPDATE messages.
#[derive(Debug, Eq, PartialEq)]
pub struct PathAttribute<'a> {
    slice: &'a[u8],
}

impl<'a> PathAttribute<'a> {

    pub fn for_slice(slice: &'a[u8]) -> Self {
        PathAttribute { slice }
    }

    pub fn flags(&self) -> u8 {
        self.slice[0]
    }

    pub fn is_optional(&self) -> bool {
        self.flags() & 0x80 == 0x80
    }

    pub fn is_transitive(&self) -> bool {
        self.flags() & 0x40 == 0x40
    }
    pub fn is_partial(&self) -> bool {
        self.flags() & 0x20 == 0x20
    }
    pub fn is_extended_length(&self) -> bool {
        self.flags() & 0x10 == 0x10
    }

    pub fn type_code(&self) -> PathAttributeType {
        self.slice[1].into()
    }

    pub fn length(&self) -> u16 {
        match self.is_extended_length() {
            true => u16::from_be_bytes(
                [self.slice[2], self.slice[3]]),
            false => self.slice[2] as u16,
        }
    }

    pub fn value(&self) -> &'a [u8] {
        let start = self.hdr_len();
        let end = start + self.length() as usize;
        &self.slice[start..end]
    }

    fn hdr_len(&self) -> usize {
        match self.is_extended_length() {
            true => 2+2,  // 2 byte flags+codes, 2 byte value length
            false => 2+1, // 2 byte flags+codes, 1 byte value length
        }
    }
}

impl<'a, R> Parse<R> for PathAttribute<'a>
where  R: 'a + AsRef<[u8]> + OctetsRef<Range = &'a [u8]> ,
{
    fn parse(parser: &mut Parser<R>) ->  Result<Self, ParseError> {
        let pos = parser.pos();
        let flags = parser.parse_u8()?;
        let typecode = parser.parse_u8()?;
        let mut headerlen = 3;
        let len = match flags & 0x10 == 0x10 {
            true => {
                headerlen += 1;
                parser.parse_u16()? as usize
            },
            false => parser.parse_u8()? as usize, 
        };

        //parser.seek(pos)?;
        // now, parse the specific type of path attribute
        match typecode.into() {
            PathAttributeType::Origin => {
                if len != 1 {
                    return Err(
                        ParseError::form_error("expected len 1 for Origin pa")
                    );
                }
                let _origin = parser.parse_u8()?;
            },
            PathAttributeType::AsPath => {
                let pa = parser.parse_octets(len)?;
                let mut p = Parser::from_ref(pa, parser.config());
                while p.remaining() > 0 {
                    let _stype = p.parse_u8()?;
                    // segment length describes the number of ASNs
                    let slen = p.parse_u8()?;
                    for _ in 0..slen {
                    match p.config().four_octet_asn {
                        FourOctetAsn::Enabled => { p.parse_u32()?; }
                        FourOctetAsn::Disabled => { p.parse_u16()?; }
                    }
                    }
                }
            },
            PathAttributeType::NextHop => {
                // conventional NEXT_HOP, just an IPv4 address
                if len != 4 {
                    return Err(
                        ParseError::form_error("expected len 4 for NEXT_HOP pa")
                    );
                }
                let _next_hop = Ipv4Addr::parse(parser)?;
            }
            PathAttributeType::MultiExitDisc => {
                if len != 4 {
                    return Err(
                        ParseError::form_error("expected len 4 for MULTI_EXIT_DISC pa")
                    );
                }
                let _med = parser.parse_u32()?;
            }
            PathAttributeType::LocalPref => {
                if len != 4 {
                    return Err(
                        ParseError::form_error("expected len 4 for LOCAL_PREF pa")
                    );
                }
                let _localpref = parser.parse_u32()?;
            },
            PathAttributeType::AtomicAggregate => {
                if len != 0 {
                    return Err(
                        ParseError::form_error("expected len 0 for ATOMIC_AGGREGATE pa")
                    );
                }
            },
            PathAttributeType::Aggregator => {
                let pa = parser.parse_octets(len)?;
                let mut p = Parser::from_ref(pa, parser.config());
                Aggregator::parse(&mut p)?;
            },
            PathAttributeType::Communities => {
                let pos = parser.pos();
                while parser.pos() < pos + len {
                    NormalCommunity::parse(parser)?;
                }
            },
            PathAttributeType::OriginatorId => {
                let _bgp_id = parser.parse_u32()?;
            },
            PathAttributeType::ClusterList => {
                let pos = parser.pos();
                while parser.pos() < pos + len {
                    parser.parse_u32()?;
                }
            },
            PathAttributeType::MpReachNlri => {
                let pa = parser.parse_octets(len)?;
                let mut p = Parser::from_ref(pa, parser.config());
                NlriIterMp::parse(&mut p)?;
            },
            PathAttributeType::MpUnreachNlri => {
                let pa = parser.parse_octets(len)?;
                let mut p = Parser::from_ref(pa, parser.config());
                WithdrawalsIterMp::parse(&mut p)?;
            },
            PathAttributeType::ExtendedCommunities => {
                let pos = parser.pos();
                while parser.pos() < pos + len {
                    ExtendedCommunity::parse(parser)?;
                }
            },
            PathAttributeType::As4Path => {
                let pa = parser.parse_octets(len)?;
                let mut p = Parser::from_ref(pa, parser.config());
                while p.remaining() > 0 {
                    let _stype = p.parse_u8()?;
                    // segment length describes the number of ASNs
                    let slen = p.parse_u8()?;
                    for _ in 0..slen {
                         p.parse_u32()?;
                    }
                }
            }
            PathAttributeType::As4Aggregator => {
                //let pa = parser.parse_octets(len)?;
                //let mut p = Parser::from_ref(pa, parser.config());
                //Aggregator::parse(&mut p)?;
                let _asn = parser.parse_u32()?;
                let _addr = Ipv4Addr::parse(parser)?;
            }
            PathAttributeType::Connector => {
                let _addr = Ipv4Addr::parse(parser);
            },
            PathAttributeType::AsPathLimit => {
                let _limit = parser.parse_u8()?;
                let _asn = parser.parse_u32()?;
            },
            PathAttributeType::PmsiTunnel => {
                let _flags = parser.parse_u8()?;
                let _tunnel_type = parser.parse_u8()?;
                let _mpls_label_1 = parser.parse_u8()?;
                let _mpls_label_2 = parser.parse_u16()?;
                let tunnel_id_len = len - 5;
                parser.advance(tunnel_id_len)?;
            },
            PathAttributeType::LargeCommunities => {
                let pos = parser.pos();
                while parser.pos() < pos + len {
                    LargeCommunity::parse(parser)?;
                }
            },
            PathAttributeType::AttrSet => {
                let _origin_as = parser.parse_u32()?;
                // The remainder of this PA is a list of ... Path Attributes.
                // We simply take all but the first four octets (origin AS)
                // and parse it.
                let mut p = Parser::from_ref(
                    parser.parse_octets(len - 4)?,
                    parser.config()
                    );
                PathAttributes::parse(&mut p)?;
            },
            PathAttributeType::Reserved => {
                warn!("Path Attribute type 0 'Reserved' observed");
            },
            PathAttributeType::RsrvdDevelopment => {
                // This could be anything.
                // As long as we do the resetting seek() + parse_octets()
                // after the match, we do not need to do anything here.
            },
            PathAttributeType::Unimplemented(_) => {
                warn!("Unimplemented PA: {}", typecode);
            },
            //_ => {
            //    panic!("unimplemented: {}", <PathAttributeType as From::<u8>>::from(typecode));
            //},
        }
        
        parser.seek(pos)?;
        let res = parser.parse_octets(headerlen+len)?;

        Ok(PathAttribute::for_slice(res))
    }

    fn skip(parser: &mut Parser<R>) ->  Result<(), ParseError> {
        Self::parse(parser).map(|_| ())
    }
}


// iterator
impl<'a, R> PathAttributes<R>
where R: 'a + AsRef<[u8]> + Copy + OctetsRef<Range = &'a [u8]> 
{
    fn get_path_attribute(&mut self) -> PathAttribute<'a> {
        PathAttribute::parse(&mut self.parser).expect("parsed before")
    }
}

impl<'a, R> Iterator for PathAttributes<R>
where
    R: 'a + AsRef<[u8]> + Copy + OctetsRef<Range = &'a [u8]> 
{
    type Item = PathAttribute<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None
        }
        Some(self.get_path_attribute())
    }
}

//--- NextHop in MP_REACH_NLRI -----------------------------------------------

impl<R> Parse<R> for NextHop 
where
    R: AsRef<[u8]>
{
    fn parse(parser: &mut Parser<R>) -> Result<Self, ParseError> {
        // suppose we have afi(/safi) in parser.config
        let len = parser.parse_u8()?;
        let res = match (len, parser.config().afi(), parser.config().safi()) {
            (16, AFI::Ipv6, SAFI::Unicast | SAFI::MplsUnicast) =>
                NextHop::Ipv6(Ipv6Addr::parse(parser)?),
            (32, AFI::Ipv6, SAFI::Unicast) =>
                NextHop::Ipv6LL(
                    Ipv6Addr::parse(parser)?,
                    Ipv6Addr::parse(parser)?
                ),
            (24, AFI::Ipv6, SAFI::MplsVpnUnicast) =>
                NextHop::Ipv6MplsVpnUnicast(
                    RouteDistinguisher::parse(parser)?,
                    Ipv6Addr::parse(parser)?
                ),
            (4, AFI::Ipv4, SAFI::Unicast | SAFI::MplsUnicast ) =>
                NextHop::Ipv4(Ipv4Addr::parse(parser)?),
            (12, AFI::Ipv4, SAFI::MplsVpnUnicast) =>
                NextHop::Ipv4MplsVpnUnicast(
                    RouteDistinguisher::parse(parser)?,
                    Ipv4Addr::parse(parser)?
                ),
            // RouteTarget is always AFI/SAFI 1/132, so, IPv4,
            // but the Next Hop can be IPv6.
            (4, AFI::Ipv4, SAFI::RouteTarget) =>
                NextHop::Ipv4(Ipv4Addr::parse(parser)?),
            (16, AFI::Ipv4, SAFI::RouteTarget) =>
                NextHop::Ipv6(Ipv6Addr::parse(parser)?),
            (0, AFI::Ipv4, SAFI::FlowSpec) =>
                NextHop::Empty,
            _ => {
                parser.advance(len.into())?;
                NextHop::Unimplemented(
                    parser.config().afi(),
                    parser.config().safi()
                )
            }
        };
        Ok(res)
    }

    fn skip(parser: &mut Parser<R>) -> Result<(), ParseError> {
        Self::parse(parser).map(|_| ())
    }
}


//--- NLRI -------------------------------------------------------------------

/// Path Identifier for BGP Multiple Paths (RFC7911).
///
/// Optionally used in [`BasicNlri`].
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct PathId(u32);

impl<R: AsRef<[u8]>> Parse<R> for PathId {
    fn parse(parser: &mut Parser<R>) -> Result<Self, ParseError>  {
        Ok(PathId(parser.parse_u32()?))
    }
    fn skip(parser: &mut Parser<R>) -> Result<(), ParseError> {
        Self::parse(parser).map(|_| ())
    }
}

/// MPLS labels, part of [`MplsNlri`] and [`MplsVpnNlri`].
#[derive(Copy, Clone, Eq, Debug, PartialEq)]
pub struct Labels<'a>(&'a[u8]);
impl Labels<'_> {
    fn len(&self) -> usize {
        self.0.len()
    }
}
impl<'a, R> Parse<R> for Labels<'a>
where R: 'a + AsRef<[u8]> + OctetsRef<Range = &'a[u8]>
{
    // There are two cases for Labels:
    // - in an announcement, it describes one or more MPLS labels
    // - in a withdrawal, it's a compatibility value without meaning
    // XXX consider splitting up the parsing for this for announcements vs
    // withdrawals? Perhaps via another fields in the (currently so-called)
    // SessionConfig...
    fn parse(parser: &mut Parser<R>) -> Result<Self, ParseError> {
        let pos = parser.pos();
        
        let mut stop = false;
        let mut buf = [0u8; 3];

        while !stop {
            //20bits label + 3bits rsvd + S bit
            parser.parse_buf(&mut buf)?;
            let _lbl =
                (buf[0] as u32) << 12 |
                (buf[1] as u32) << 4  |
                (buf[2] as u32) >> 4;

            if buf[2] & 0x01 == 0x01  || // actual label with stop bit
                buf == [0x80, 0x00, 0x00] || // Compatibility value 
                buf == [0x00, 0x00, 0x00] // or RFC 8277 2.4
            {
                stop = true;
            }
        }

        let len = parser.pos() - pos;
        parser.seek(pos)?;
        let res = parser.parse_octets(len)?;
        Ok(
            Labels(res)
        )
    }

    fn skip(parser: &mut Parser<R>) -> Result<(), ParseError> {
        Self::parse(parser).map(|_| ())
    }
}

/// Route Distinguisher (RD) as defined in RFC4364.
///
/// Used in [`MplsVpnNlri`], [`VplsNlri`] and [`NextHop`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct RouteDistinguisher {
    bytes: [u8; 8]
}

impl<R> Parse<R> for RouteDistinguisher
where R: AsRef<[u8]>
{
    fn parse(parser: &mut Parser<R>) -> Result<Self, ParseError> {
        let mut b = [0u8; 8];
        b[..8].copy_from_slice(parser.peek(8)?);
        parser.advance(8)?;
        Ok(
            RouteDistinguisher{ bytes: b }
        )
    }

    fn skip(parser: &mut Parser<R>) -> Result<(), ParseError> {
        Self::parse(parser).map(|_| ())
    }
}

impl RouteDistinguisher {
    pub fn new(bytes: &[u8]) -> Self {
        RouteDistinguisher { bytes: bytes.try_into().expect("parsed before") }
    }

    pub fn typ(&self) -> RouteDistinguisherType {
        match self.bytes[0..2] {
            [0x00, 0x00] => RouteDistinguisherType::Type0,
            [0x00, 0x01] => RouteDistinguisherType::Type1,
            [0x00, 0x02] => RouteDistinguisherType::Type2,
            _ => RouteDistinguisherType::UnknownType,
        }
    }
    pub fn value(&self) -> [u8; 6] {
        self.bytes[2..8].try_into().expect("parsed before")
    }
}

/// Route Distinguisher types.
#[derive(Eq, PartialEq, Debug)]
pub enum RouteDistinguisherType {
    Type0,
    Type1,
    Type2,
    UnknownType,
}

//--- Refactoring NLRI iters using Parser ------------------------------------

/// NLRI comprised of a [`Prefix`] and an optional [`PathId`].
///
/// The `BasicNlri` is extended in [`MplsNlri`] and [`MplsVpnNlri`].
#[derive(Copy, Clone, Debug)]
pub struct BasicNlri {
    prefix: Prefix,
    path_id: Option<PathId>,
}

/// NLRI comprised of a [`BasicNlri`] and MPLS `Labels`.
#[derive(Debug)]
pub struct MplsNlri<'a> {
    basic: BasicNlri,
    labels: Labels<'a>,
}

/// NLRI comprised of a [`BasicNlri`], MPLS `Labels` and a VPN
/// `RouteDistinguisher`.
#[derive(Debug)]
pub struct MplsVpnNlri<'a> {
    basic: BasicNlri,
    labels: Labels<'a>,
    rd: RouteDistinguisher,
}

/// VPLS Information as defined in RFC4761.
#[derive(Debug)]
pub struct VplsNlri {
    rd: RouteDistinguisher,
    ve_id: u16,
    ve_block_offset: u16,
    ve_block_size: u16,
    raw_label_base: u32,
}

/// NLRI containing a FlowSpec v1 specification.
///
/// Also see [`crate::flowspec`].
#[derive(Debug)]
pub struct FlowSpecNlri<'a> {
    #[allow(dead_code)]
    raw: &'a[u8], 
}

/// NLRI containing a Route Target membership as defined in RFC4684.
///
/// **TODO**: implement accessor methods for the contents of this NLRI.
#[derive(Debug)]
pub struct RouteTargetNlri<'a> {
    #[allow(dead_code)]
    raw: &'a[u8],
}

/// Conventional and BGP-MP NLRI variants.
#[derive(Debug)]
pub enum Nlri<'a> {
    Basic(BasicNlri),
    Mpls(MplsNlri<'a>),
    MplsVpn(MplsVpnNlri<'a>),
    Vpls(VplsNlri),
    FlowSpec(FlowSpecNlri<'a>),
    RouteTarget(RouteTargetNlri<'a>),
}

impl Display for Nlri<'_> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Nlri::Vpls(n) => write!(f, "VPLS-{:?}", n.rd),
            _ => write!(f, "{}", self.prefix().unwrap())
        }
    }
}
impl<'a> Nlri<'a> {
    fn basic(&self) -> Option<BasicNlri> { 
        match self {
            Nlri::Basic(n) => Some(*n),
            Nlri::Mpls(n) => Some(n.basic),
            Nlri::MplsVpn(n) => Some(n.basic),
            Nlri::Vpls(_) => None,
            Nlri::FlowSpec(_) => None,
            Nlri::RouteTarget(_) => None,
        }
    }

    pub fn prefix(&self) -> Option<Prefix> {
        self.basic().map(|b| b.prefix)
    }

    pub fn path_id(&self) -> Option<PathId> {
        if let Some(b) = self.basic() {
            b.path_id
        } else {
            None
        }
    }

    pub fn labels(&self) -> Option<Labels> {
        match self {
            Nlri::Mpls(n) => Some(n.labels),
            Nlri::MplsVpn(n) => Some(n.labels),
            _ => None
        }
    }

    pub fn rd(&self) -> Option<RouteDistinguisher> {
        match self {
            Nlri::MplsVpn(n) => Some(n.rd),
            Nlri::Vpls(n) => Some(n.rd),
            _ => None
        }
    }

    // VPLS specific methods

    pub fn ve_id(&self) -> Option<u16> {
        match self {
            Nlri::Vpls(n) => Some(n.ve_id),
            _ => None
        }

    }

    pub fn ve_block_offset(&self) -> Option<u16> {
        match self {
            Nlri::Vpls(n) => Some(n.ve_block_offset),
            _ => None
        }
    }

    pub fn ve_block_size(&self) -> Option<u16> {
        match self {
            Nlri::Vpls(n) => Some(n.ve_block_size),
            _ => None
        }
    }

    pub fn raw_label_base(&self) -> Option<u32> {
        match self {
            Nlri::Vpls(n) => Some(n.raw_label_base),
            _ => None
        }
    }
}

// Calculate the number of bytes we need to parse for a certain prefix length
// given in bits.
fn prefix_bits_to_bytes(bits: u8) -> usize {
    if bits != 0 {
        (bits as usize - 1) / 8 + 1
    } else {
        0
    }
}

fn parse_prefix<R>(parser: &mut Parser<R>, prefix_bits: u8)
    -> Result<Prefix, ParseError>
where
    R: AsRef<[u8]>
{
    let prefix_bytes = prefix_bits_to_bytes(prefix_bits);
    let prefix = match (parser.config().afi(), prefix_bytes) {
        (AFI::Ipv4, 0) => {
            Prefix::new_v4(0.into(), 0)?
        },
        (AFI::Ipv4, _b @ 5..) => { 
            return Err(ParseError::form_error("illegal byte size for IPv4 NLRI"))
        },
        (AFI::Ipv4, _) => {
            let mut b = [0u8; 4];
            b[..prefix_bytes].copy_from_slice(parser.peek(prefix_bytes)?);
            parser.advance(prefix_bytes)?;
            Prefix::new(IpAddr::from(b), prefix_bits).map_err(|_e| 
                    ParseError::form_error("prefix parsing failed")
            )?
        }
        (AFI::Ipv6, 0) => {
            Prefix::new_v6(0.into(), 0)?
        },
        (AFI::Ipv6, _b @ 17..) => { 
            return Err(ParseError::form_error("illegal byte size for IPv6 NLRI"))
        },
        (AFI::Ipv6, _) => {
            let mut b = [0u8; 16];
            b[..prefix_bytes].copy_from_slice(parser.peek(prefix_bytes)?);
            parser.advance(prefix_bytes)?;
            Prefix::new(IpAddr::from(b), prefix_bits).map_err(|_e| 
                    ParseError::form_error("prefix parsing failed")
            )?
        },
        (_, _) => {
            panic!("unimplemented")
        }
    };
    Ok(prefix)
}

impl<R: AsRef<[u8]>> Parse<R> for BasicNlri {
    fn parse(parser: &mut Parser<R>) -> Result<Self, ParseError> {
        let path_id = match parser.config().add_path {
            AddPath::Enabled => Some(PathId::parse(parser)?),
            _ => None
        };
        let prefix_bits = parser.parse_u8()?;
        let prefix = parse_prefix(parser, prefix_bits)?;
        
        Ok(
            BasicNlri {
                prefix,
                path_id,
            }
        )
    }

    fn skip(parser: &mut Parser<R>) -> Result<(), ParseError> {
        Self::parse(parser).map(|_| ())
    }
}

impl<'a, R> Parse<R> for MplsVpnNlri<'a> 
where R: 'a + AsRef<[u8]> + OctetsRef<Range = &'a[u8]>
{
    fn parse(parser: &mut Parser<R>) -> Result<Self, ParseError> {
        let path_id = match parser.config().add_path {
            AddPath::Enabled => Some(PathId::parse(parser)?),
            _ => None
        };

        let mut prefix_bits = parser.parse_u8()?;
        let labels = Labels::parse(parser)?;

        // Check whether we can safely subtract the labels length from the
        // prefix size. If there is an unexpected path id, we might silently
        // subtract too much, because there is no 'subtract with overflow'
        // warning when built in release mode.
        if 8 * labels.len() as u8 > prefix_bits {
            return Err(ParseError::ShortInput);
        }

        prefix_bits -= 8 * labels.len() as u8;

        let rd = RouteDistinguisher::parse(parser)?;
        prefix_bits -= 8*std::mem::size_of::<RouteDistinguisher>() as u8;

        let prefix = parse_prefix(parser, prefix_bits)?;

        let basic = BasicNlri { prefix, path_id };
        Ok(
            MplsVpnNlri {
                basic,
                labels, 
                rd,
            }
        )
    }

    fn skip(parser: &mut Parser<R>) -> Result<(), ParseError> {
        Self::parse(parser).map(|_| ())
    }
}

impl<'a, R> Parse<R> for MplsNlri<'a>
where R: 'a + AsRef<[u8]> + OctetsRef<Range = &'a[u8]>
{
    fn parse(parser: &mut Parser<R>) -> Result<Self, ParseError> {
        let path_id = match parser.config().add_path {
            AddPath::Enabled => Some(PathId::parse(parser)?),
            _ => None
        };

        let mut prefix_bits = parser.parse_u8()?;
        let labels = Labels::parse(parser)?;

        // Check whether we can safely subtract the labels length from the
        // prefix size. If there is an unexpected path id, we might silently
        // subtract too much, because there is no 'subtract with overflow'
        // warning when built in release mode.
        if 8 * labels.len() as u8 > prefix_bits {
            return Err(ParseError::ShortInput);
        }

        prefix_bits -= 8 * labels.len() as u8;

        let prefix = parse_prefix(parser, prefix_bits)?;
        let basic = BasicNlri { prefix, path_id };
        Ok(
            MplsNlri {
                basic,
                labels, 
            }
        )
    }

    fn skip(parser: &mut Parser<R>) -> Result<(), ParseError> {
        Self::parse(parser).map(|_| ())
    }
}

impl<R: AsRef<[u8]>> Parse<R> for VplsNlri {
    fn parse(parser: &mut Parser<R>) -> Result<Self, ParseError> {
        let _len = parser.parse_u16()?;
        let rd = RouteDistinguisher::parse(parser)?; 
        let ve_id = parser.parse_u16()?;
        let ve_block_offset = parser.parse_u16()?;
        let ve_block_size = parser.parse_u16()?;
        let label_base_1 = parser.parse_u8()? as u32;
        let label_base_2 = parser.parse_u16()? as u32;

        Ok(
            VplsNlri {
                rd,
                ve_id,
                ve_block_offset,
                ve_block_size,
                raw_label_base: label_base_1 << 16 | label_base_2,
            }
        )
    }

    fn skip(parser: &mut Parser<R>) -> Result<(), ParseError> {
        Self::parse(parser).map(|_| ())
    }
}

impl<'a, R> Parse<R> for FlowSpecNlri<'a>
where
    R: 'a + AsRef<[u8]> + OctetsRef<Range = &'a[u8]>
{
    fn parse(parser: &mut Parser<R>) -> Result<Self, ParseError> {
        let pos = parser.pos();
        let len1 = parser.parse_u8()?;
        let len: u16 = if len1 >= 0xf0 {
            let len2 = parser.parse_u8()? as u16;
            (((len1 as u16) << 8) | len2) & 0x0fff
        } else {
            len1 as u16
        };
        while parser.pos() < pos + len as usize {
            Component::parse(parser)?;
        }

        
        let raw_len = parser.pos() - pos;
        parser.seek(pos)?;
        let raw = parser.parse_octets(raw_len)?;

        Ok(
            FlowSpecNlri {
                raw
            }
        )
    }

    fn skip(parser: &mut Parser<R>) -> Result<(), ParseError> {
        Self::parse(parser).map(|_| ())
    }
}

impl<'a, R> Parse<R> for RouteTargetNlri<'a>
where
    R: 'a + AsRef<[u8]> + OctetsRef<Range = &'a[u8]>
{
    fn parse(parser: &mut Parser<R>) -> Result<Self, ParseError> {

        let prefix_bits = parser.parse_u8()?;
        let prefix_bytes = prefix_bits_to_bytes(prefix_bits);
        let raw = parser.parse_octets(prefix_bytes)?;

        Ok(
            RouteTargetNlri {
                raw
            }
        )
    }
    fn skip(parser: &mut Parser<R>) -> Result<(), ParseError> {
        Self::parse(parser).map(|_| ())
    }
}

//-----


/// Iterator over the reachable NLRIs.
///
/// Returns items of the enum [`Nlri`], thus both conventional and
/// BGP MultiProtocol (RFC4760) NLRIs.
pub struct NlriIterMp<Ref> {
    parser: Parser<Ref>,
    afi: AFI,
    safi: SAFI,
}

impl<'a, R: AsRef<[u8]>> NlriIterMp<R>
where R: 'a + OctetsRef<Range = &'a[u8]>
    {
    pub fn new(slice: Parser<R>) -> Self {
        let mut parser = slice;
        let afi: AFI = parser.parse_u16().expect("parsed before").into();
        let safi: SAFI = parser.parse_u8().expect("parsed before").into();

        parser.config_mut().set_afi(afi);
        parser.config_mut().set_safi(safi);

        NextHop::skip(&mut parser).expect("parsed before");
        parser.advance(1).expect("parsed before"); // 1 reserved byte
        Self {
            parser,
            afi,
            safi,
        }
    }

    pub fn new_conventional(slice: Parser<R>) -> Self {
        Self {
            parser: slice,
            afi: AFI::Ipv4,
            safi: SAFI::Unicast
        }
    }

    fn get_nlri(&mut self) -> Nlri<'a> {
        match (self.afi, self.safi) {
            (_, SAFI::MplsVpnUnicast) => {
                Nlri::MplsVpn(MplsVpnNlri::parse(&mut self.parser).expect("parsed before"))
            },
            (_, SAFI::MplsUnicast) => {
                Nlri::Mpls(MplsNlri::parse(&mut self.parser).expect("parsed before"))
            },
            (_, SAFI::Unicast) => {
                Nlri::Basic(BasicNlri::parse(&mut self.parser).expect("parsed before"))
            },
            (AFI::L2Vpn, SAFI::Vpls) => {
                Nlri::Vpls(VplsNlri::parse(&mut self.parser).expect("parsed before"))
            },
            (AFI::Ipv4, SAFI::FlowSpec) => {
                Nlri::FlowSpec(FlowSpecNlri::parse(&mut self.parser).expect("parsed before"))
            },
            (AFI::Ipv4, SAFI::RouteTarget) => {
                Nlri::RouteTarget(RouteTargetNlri::parse(&mut self.parser).expect("parsed before"))
            },
            (_, _) => panic!("unsupported AFI/SAFI in get_nlri(), should not come here")
        }
    }
}

impl<'a, R> Parse<R> for NlriIterMp<R>
where
    R: 'a + AsRef<[u8]> + Copy + OctetsRef<Range = &'a [u8]>
    {
    fn parse(parser: &mut Parser<R>) -> Result<Self, ParseError> {
        // NLRIs from MP_REACH_NLRI.
        // Length is given in the Path Attribute length field.
        // AFI, SAFI, Nexthop are also in this Path Attribute.

        
        let res = *parser; // XXX do we need this?

        let afi: AFI = parser.parse_u16()?.into();
        let safi: SAFI = parser.parse_u8()?.into();
        parser.config_mut().set_afi(afi);
        parser.config_mut().set_safi(safi);

        NextHop::skip(parser)?;
        parser.advance(1)?; // 1 reserved byte


        while parser.remaining() > 0 {
            match (afi, safi) {
                (_, SAFI::MplsVpnUnicast) => { MplsVpnNlri::parse(parser)?;},
                (_, SAFI::MplsUnicast) => { MplsNlri::parse(parser)?;},
                (_, SAFI::Unicast) => { BasicNlri::parse(parser)?; }
                (AFI::L2Vpn, SAFI::Vpls) => { VplsNlri::parse(parser)?; }
                (AFI::Ipv4, SAFI::FlowSpec) => {
                    FlowSpecNlri::parse(parser)?;
                },
                (AFI::Ipv4, SAFI::RouteTarget) => {
                    RouteTargetNlri::parse(parser)?;
                },
                (_, _) => {
                    error!("unknown AFI/SAFI {}/{}", afi, safi);
                    return Err(
                        ParseError::form_error("unimplemented AFI/SAFI")
                    )
                }
            }
        }

        Ok(
            NlriIterMp::new(res)
        )
    }

    fn skip(parser: &mut Parser<R>) -> Result<(), ParseError> {
        Self::parse(parser)?;
        Ok(())
    }
}


impl<'a, R> Iterator for NlriIterMp<R>
where R: 'a + AsRef<[u8]> + OctetsRef<Range = &'a[u8]>
{
    type Item = Nlri<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None;
        }
        Some(self.get_nlri())
    }
}

/// Iterator over the withdrawn NLRIs.
///
/// Returns items of the enum [`Nlri`], thus both conventional and
/// BGP MultiProtocol (RFC4760) withdrawn NLRIs.
pub struct WithdrawalsIterMp<Ref> {
    parser: Parser<Ref>,
    afi: AFI,
    safi: SAFI,
}

impl<'a, R: AsRef<[u8]>> WithdrawalsIterMp<R>
where R: 'a + OctetsRef<Range = &'a[u8]>
    {
    pub fn new(slice: Parser<R>, afi: AFI, safi: SAFI) -> Self {
        let mut parser = slice;
        parser.config_mut().set_afi(afi);
        Self {
            parser,
            afi,
            safi,
        }
    }

    fn get_nlri(&mut self) -> Nlri<'a> {
        match (self.afi, self.safi) {
            (_, SAFI::MplsVpnUnicast) => {
                Nlri::MplsVpn(MplsVpnNlri::parse(&mut self.parser).expect("parsed before"))
            },
            (_, SAFI::MplsUnicast) => {
                Nlri::Mpls(MplsNlri::parse(&mut self.parser).expect("parsed before"))
            },
            (_, SAFI::Unicast) => {
                Nlri::Basic(BasicNlri::parse(&mut self.parser).expect("parsed before"))
            }
            (_, _) => panic!("should not come here")
        }
    }
}

impl<'a, R> Parse<R> for WithdrawalsIterMp<R>
where
    R: 'a + AsRef<[u8]> + Copy + OctetsRef<Range = &'a [u8]>
{
    fn parse(parser: &mut Parser<R>) -> Result<Self, ParseError> {
        // NLRIs from MP_UNREACH_NLRI.
        // Length is given in the Path Attribute length field.
        // AFI, SAFI, are also in this Path Attribute.

        
        let mut res = *parser;

        let afi: AFI = parser.parse_u16()?.into();
        let safi: SAFI = parser.parse_u8()?.into();
        parser.config_mut().set_afi(afi);

        while parser.remaining() > 0 {
            match (afi, safi) {
                (_, SAFI::MplsVpnUnicast) => { MplsVpnNlri::parse(parser)?;},
                (_, SAFI::MplsUnicast) => { MplsNlri::parse(parser)?;},
                (_, SAFI::Unicast) => { BasicNlri::parse(parser)?; }
                (_, _) => { /* return Err(FormError("unimplemented")) */ }
            }
        }

        res.advance(3)?; // jump over the AFI/SAFI
        Ok(
            WithdrawalsIterMp::new(
                res,
                afi,
                safi,
            )
        )
    }

    fn skip(parser: &mut Parser<R>) -> Result<(), ParseError> {
        Self::parse(parser)?;
        Ok(())
    }
}

impl<'a, R> Iterator for WithdrawalsIterMp<R>
where R: 'a + AsRef<[u8]> + OctetsRef<Range = &'a[u8]>
{
    type Item = Nlri<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None;
        }
        Some(self.get_nlri())
    }
}


//--- Communities ------------------------------------------------------------
//


/// Conventional, RFC1997 4-byte community.
#[derive(Debug, Eq, PartialEq)]
pub struct NormalCommunity([u8; 4]);

/// Final two octets of a [`NormalCommunity`], i.e. the 'community number'.
#[derive(Debug, Eq, PartialEq)]
pub struct CommunityTag(u16);

/// Extended Community as defined in RFC4360.
#[derive(Debug, Eq, PartialEq)]
pub struct ExtendedCommunity([u8; 8]);

/// Large Community as defined in RFC8092.
#[derive(Debug, Eq, PartialEq)]
pub struct LargeCommunity([u8; 12]);

/// IANA Policy options for Extended Communities.
pub enum IanaPolicy {
    FCFS,
    StandardsAction,
}

impl NormalCommunity {
    pub fn new(asn: Asn, tag: CommunityTag) -> NormalCommunity {
        let mut buf = [0u8; 4];
        let asn16 = asn.into_u32() as u16;  
        buf[..2].copy_from_slice(&asn16.to_be_bytes());
        buf[2..4].copy_from_slice(&tag.0.to_be_bytes());
        Self(buf)
    }

    pub fn asn(&self) -> Option<Asn> {
        Some(
            Asn::from_u32(
                u16::from_be_bytes([self.0[0], self.0[1]]).into()
            )
        )
    }

    pub fn tag(&self) -> CommunityTag {
        CommunityTag(u16::from_be_bytes([self.0[2], self.0[3]]))
    }
}

impl Display for NormalCommunity {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "{}:{}",
            self.asn().expect("always present in NormalCommunity").into_u32(),
            self.tag().0)
    }
}

impl<R> Parse<R> for NormalCommunity
where
    R: AsRef<[u8]>
{
    fn parse(parser: &mut Parser<R>) -> Result<Self, ParseError> {
        let mut buf = [0u8; 4];
        parser.parse_buf(&mut buf)?;
        Ok( Self(buf) )
    }

    fn skip(parser: &mut Parser<R>) -> Result<(), ParseError> {
        Self::parse(parser).map(|_| ())
    }

}

impl ExtendedCommunity {
    pub fn typ(&self) -> u8 {
        self.0[0]
    }
    pub fn subtyp(&self) -> u8 {
        self.0[1]
    }
    pub fn val_regular(&self) -> [u8; 7] {
        self.0[1..8].try_into().expect("parsed before")
    }
    pub fn val_extended(&self) -> [u8; 6] {
        self.0[2..8].try_into().expect("parsed before")
    }
    pub fn iana_policy(&self) -> IanaPolicy {
        if self.typ() & 0x80 == 0x80 {
            // IANA authority bit is 1
            IanaPolicy::StandardsAction
        } else {
            // IANA authority bit is 0
            IanaPolicy::FCFS
        }
    }
    pub fn is_transitive(&self) -> bool {
        // Transitive bit 0 means the community is transitive 
        self.typ() & 0x40 == 0x00
    }

    /// Returns the `Asn` if this is a Two-Octet AS Specific Extended
    /// Community, or None otherwise.
    pub fn asn(&self) -> Option<Asn> {
        if self.typ() == 0x00 || self.typ() == 0x40 {
            Some(
                Asn::from_u32(
                    u16::from_be_bytes([
                        self.0[2],
                        self.0[3]
                    ]).into()
                )
            )
        } else {
            None
        }
    }
}

impl Display for ExtendedCommunity {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let mut r = write!(f, "0x");
        for i in 0..8 {
            r = write!(f, "{:02X}", self.0[i]);
        }
        r
    }
}

impl<R> Parse<R> for ExtendedCommunity
where
    R: AsRef<[u8]>
{
    fn parse(parser: &mut Parser<R>) -> Result<Self, ParseError> {
        let mut buf = [0u8; 8];
        parser.parse_buf(&mut buf)?;
        Ok( Self(buf) )
    }

    fn skip(parser: &mut Parser<R>) -> Result<(), ParseError> {
        Self::parse(parser).map(|_| ())
    }

}

impl LargeCommunity {
    pub fn global(&self) -> u32 {
        u32::from_be_bytes(self.0[0..4].try_into().expect("parsed before"))
    }

    pub fn local1(&self) -> u32 {
        u32::from_be_bytes(self.0[4..8].try_into().expect("parsed before"))
    }

    pub fn local2(&self) -> u32 {
        u32::from_be_bytes(self.0[8..12].try_into().expect("parsed before"))
    }
}

impl<R> Parse<R> for LargeCommunity
where
    R: AsRef<[u8]>
{
    fn parse(parser: &mut Parser<R>) -> Result<Self, ParseError> {
        let mut buf = [0u8; 12];
        parser.parse_buf(&mut buf)?;
        Ok( Self(buf) )
    }

    fn skip(parser: &mut Parser<R>) -> Result<(), ParseError> {
        Self::parse(parser).map(|_| ())
    }

}

impl Display for LargeCommunity {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}:{}:{}", self.global(), self.local1(), self.local2())
    }

}

/// Conventional and Extended/Large Communities variants.
#[derive(Debug, Eq, PartialEq)]
pub enum Community {
    Normal(NormalCommunity),
    NoExport,           // 0xFFFFFF01
    NoAdvertise,        // 0xFFFFFF02
    NoExportSubconfed,  // 0xFFFFFF03
    Blackhole,          // 0xFFFF029A
    Extended(ExtendedCommunity),
    Large(LargeCommunity)
}

impl Community {
    /// Returns the `Asn` for non well-known community tags, or None
    /// otherwise. 
    pub fn asn(&self) -> Option<Asn> {
        use Community::*;
        match self {
            Normal(nc) => nc.asn(),
            Extended(e) => e.asn(),
            Large(lc) => Some(lc.global().into()),
            _ => None,
        }
    }
}

impl Display for Community {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Community::Normal(nc) => Display::fmt(&nc, f),
            Community::Extended(e) => Display::fmt(&e, f),
            Community::Large(lc) => Display::fmt(&lc, f),
            Community::NoExport => write!(f, "NoExport"),
            Community::NoAdvertise => write!(f, "NoAdvertise"),
            Community::NoExportSubconfed => write!(f, "NoExportSubconfed"),
            Community::Blackhole => write!(f, "Blackhole"),
        }
    }
}


impl From<[u8; 4]> for Community {
    fn from(raw: [u8; 4]) -> Community {
        match raw {
            [0xff, 0xff, 0xff, 0x01] => Community::NoExport,
            [0xff, 0xff, 0xff, 0x02] => Community::NoAdvertise,
            [0xff, 0xff, 0xff, 0x03] => Community::NoExportSubconfed,
            [0xff, 0xff, 0x02, 0x9A] => Community::Blackhole,
            _ => {
                Community::Normal(NormalCommunity(raw))
            }
        }
    }
}

impl From<[u8; 8]> for Community {
    fn from(raw: [u8; 8]) -> Community {
        Community::Extended(ExtendedCommunity(raw))
    }
}

/// Iterator for BGP UPDATE Communities.
///
/// Returns values of enum [`Community`], wrapping [`NormalCommunity`],
/// [`ExtendedCommunity`], [`LargeCommunity`] and well-known communities.
pub struct CommunityIter<'a> {
    slice: &'a [u8],
    pos: usize,
}

impl<'a> CommunityIter<'a> {
    fn new(slice: &[u8]) -> CommunityIter {
        CommunityIter {
            slice,
            pos: 0
        }
    }
    fn get_community(&mut self) -> Community {
        let res = TryInto::<[u8; 4]>::try_into(
            &self.slice[self.pos .. self.pos + 4])
            .expect("parsed before").into();
        self.pos += 4;
        res
    }
}

impl Iterator for CommunityIter<'_> {
    type Item = Community;
    fn next(&mut self) -> Option<Community> {
        if self.pos == self.slice.len() {
            return None
        }
        Some(self.get_community())
    }
}

/// Iterator over [`ExtendedCommunity`]s.
pub struct ExtCommunityIter<'a> {
    slice: &'a [u8],
    pos: usize,
}

impl<'a> ExtCommunityIter<'a> {
    fn new(slice: &'a [u8]) -> ExtCommunityIter {
        ExtCommunityIter {
            slice,
            pos: 0
        }
    }
    fn get_community(&mut self) -> ExtendedCommunity {
        let res = ExtendedCommunity(
            self.slice[self.pos..self.pos+8].try_into().expect("parsed before")
            );
        self.pos += 8;
        res
    }
}

impl Iterator for ExtCommunityIter<'_> {
    type Item = ExtendedCommunity;
    fn next(&mut self) -> Option<ExtendedCommunity> {
        if self.pos == self.slice.len() {
            return None
        }
        Some(self.get_community())
    }
}

/// Iterator over [`LargeCommunity`]s.
pub struct LargeCommunityIter<'a> {
    slice: &'a [u8],
    pos: usize,
}

impl<'a> LargeCommunityIter<'a> {
    fn new(slice: &'a [u8]) -> LargeCommunityIter {
        LargeCommunityIter {
            slice,
            pos: 0
        }
    }
    fn get_community(&mut self) -> LargeCommunity {
        let res = LargeCommunity(
            self.slice[self.pos..self.pos+12].try_into().expect("parsed before")
            );
        self.pos += 12;
        res
    }
}

impl Iterator for LargeCommunityIter<'_> {
    type Item = LargeCommunity;
    fn next(&mut self) -> Option<LargeCommunity> {
        if self.pos == self.slice.len() {
            return None
        }
        Some(self.get_community())
    }
}

//--- Aggregator -------------------------------------------------------------
/// Path Attribute (7).
pub struct Aggregator {
    asn: Asn,
    speaker: Ipv4Addr,
}

impl Aggregator {
    /// Creates a new Aggregator.
    pub fn new(asn: Asn, speaker: Ipv4Addr) -> Self {
        Aggregator{ asn, speaker }
    }

    /// Returns the `Asn`.
    pub fn asn(&self) -> Asn {
        self.asn
    }

    /// Returns the speaker IPv4 address.
    pub fn speaker(&self) -> Ipv4Addr {
        self.speaker
    }
}

impl<R> Parse<R> for Aggregator 
where
    R: AsRef<[u8]>
{
    fn parse(parser: &mut Parser<R>) -> Result<Self, ParseError> {
        let len = parser.remaining();
        match (len, parser.config().four_octet_asn) {
            (8, FourOctetAsn::Enabled) => {
                let asn = Asn::from_u32(parser.parse_u32()?);
                let addr = Ipv4Addr::parse(parser)?;
                Ok(Self::new(asn, addr))

            },
            (6, FourOctetAsn::Disabled) => {
                let asn = Asn::from_u32(parser.parse_u16()?.into());
                let addr = Ipv4Addr::parse(parser)?;
                Ok(Self::new(asn, addr))
            },
            (_, FourOctetAsn::Enabled) => {
                Err(
                    ParseError::form_error("expected len 8 for AGGREGATOR pa")
                )
            },
            (_, FourOctetAsn::Disabled) => {
                Err(
                    ParseError::form_error("expected len 6 for AGGREGATOR pa")
                )
            },
        }

    }
    fn skip(parser: &mut Parser<R>) -> Result<(), ParseError> {
        Self::parse(parser).map(|_| ())
    }

}


//--- Notification -----------------------------------------------------------
// to properly enumify the codes, check:
// RFCs
//  4271
//  4486
//  8203
//  9003

/// BGP NOTIFICATION Message.
///
///
impl MessageNotification {

    fn for_slice(s: &[u8]) -> Self {
        Self {
            octets: Bytes::copy_from_slice(s),
            //add_path: None,
        }
    }
    
    pub fn code(&self) -> u8 {
        self.octets.as_ref()[COFF]
    }

    pub fn subcode(&self) -> u8 {
        self.octets.as_ref()[COFF+1]
    }

    pub fn data(&self) -> Option<&[u8]> {
        if self.length() > 21 {
            Some(&self.as_ref()[21..])
        } else {
            None
        }
    }
}
impl<'a, R> Parse<R> for MessageNotification
where
    R: 'a + AsRef<[u8]> + OctetsRef<Range = &'a[u8]>
{
    fn parse(parser: &mut Parser<R>) -> Result<Self, ParseError> {
        // parse header
        let pos = parser.pos();
        let hdr = Header::parse(parser)?;

        // TODO implement enums for codes/subcodes
        let _code = parser.parse_u8()?;
        let _subcode = parser.parse_u8()?;


        // Now, their might be variable length data from the current position
        // to the end of the message. There is no length field.
        // The data depends on the code/subscode.
        parser.seek(pos)?;

        Ok(
            Self::for_slice(parser.parse_octets(hdr.length().into())?)
        )

    }

    fn skip(parser: &mut Parser<R>) -> Result<(), ParseError> {
        Self::parse(parser).map(|_| ())
    }
}

//--- Types that perhaps should go into routecore ----------------------------

/// BGP Message types.
#[derive(Debug, Eq, PartialEq)]
pub enum MsgType {
    Open,
    Update,
    Notification,
    KeepAlive,
    RouteRefresh, // RFC2918
    //Capability, // draft-ietf-idr-dynamic-cap
}

typeenum!(
/// AFI as used in BGP OPEN and UPDATE messages.
    AFI, u16,
    1 => Ipv4,
    2 => Ipv6,
    25 => L2Vpn,
);

typeenum!(
/// SAFI as used in BGP OPEN and UPDATE messages.
    SAFI, u8,
    1 => Unicast,
    2 => Multicast,
    4 => MplsUnicast,
    65 => Vpls,
    70 => Evpn,
    128 => MplsVpnUnicast,
    132 => RouteTarget,
    133 => FlowSpec,
    134 => FlowSpecVpn,
);

/// BGP Origin types as used in BGP UPDATE messages.
#[derive(Debug)]
pub enum OriginType {
    Igp,
    Egp,
    Incomplete,
    Unknown(u8),
}

//--- Newtypes ---------------------------------------------------------------

/// Wrapper for the 4 byte Multi-Exit Discriminator in path attributes.
#[derive(Debug, Eq, PartialEq)]
pub struct MultiExitDisc(u32);

/// Wrapper for the 4 byte Local Preference value in path attributes.
#[derive(Debug, Eq, PartialEq)]
pub struct LocalPref(u32);


//--- Enums for passing config / state ---------------------------------------

/// Configuration parameters for an established BGP session.
///
/// The `SessionConfig` is a structure holding parameters to parse messages
/// for the particular session. Storing these parameters is necessary because
/// some information crucial to correctly parsing BGP UPDATE messages is not
/// available in the UPDATE messages themselves, but are only exchanged in the
/// BGP OPEN messages when the session was established.
///
#[derive(Copy, Clone, Debug)]
pub struct SessionConfig {
    pub four_octet_asn: FourOctetAsn,
    pub add_path: AddPath,

    pub afi: AFI, // tmp
    pub safi: SAFI, // tmp
}

impl Default for SessionConfig {
    /// The defaults for SessionConfig are Four Octet capable, no AddPath.
    /// This should be a reasonable guess for when no other knowledge about
    /// the session is available, and e.g. a single UPDATE is parsed.
    fn default() -> Self {
        SessionConfig {
            four_octet_asn: FourOctetAsn::Enabled,
            add_path: AddPath::Disabled,
            afi: AFI::Ipv4,
            safi: SAFI::Unicast,
        }
    }
}
impl SessionConfig {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn enable_four_octet_asn(&mut self) {
        self.four_octet_asn = FourOctetAsn::Enabled
    }

    pub fn disable_four_octet_asn(&mut self) {
        self.four_octet_asn = FourOctetAsn::Disabled
    }

    pub fn set_four_octet_asn(&mut self, v: FourOctetAsn) {
        self.four_octet_asn = v;
    }

    pub fn enable_addpath(&mut self) {
        self.add_path = AddPath::Enabled
    }

    pub fn disable_addpath(&mut self) {
        self.add_path = AddPath::Disabled
    }

    pub fn set_addpath(&mut self, v: AddPath) {
        self.add_path = v;
    }

    pub fn afi(&self) -> AFI {
        self.afi
    }

    pub fn set_afi(&mut self, afi: AFI) {
        self.afi = afi;
    }

    pub fn safi(&self) -> SAFI {
        self.safi
    }

    pub fn set_safi(&mut self, safi: SAFI) {
        self.safi = safi;
    }
}

/// Indicates whether this session is Four Octet capable.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FourOctetAsn {
    Enabled,
    Disabled,
}

/// Indicates whether AddPath is enabled for this session.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AddPath {
    Enabled,
    Disabled,
}


//--- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;

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

    // Helpers for quickly parsing bufs into specific BGP messages
    fn bgp_open(buf: &[u8]) -> super::MessageOpen {
        super::Message::from_octets(&buf).unwrap().try_into().unwrap()
    }

    fn bgp_update(buf: &[u8]) -> super::MessageUpdate {
        super::Message::from_octets(&buf).unwrap().try_into().unwrap()
    }
    
    //--- BGP OPEN related tests ---------------------------------------------
    mod open {

        use super::*;

        #[test]
        fn no_optional_parameters() {
            // BGP OPEN message, 2-octet ASN 64496, no opt params
            let buf = vec![
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x1d, 0x01, 0x04, 0xfb, 0xf0, 0x00, 0x5a,
                0xc0, 0x00, 0x02, 0x01, 0x00
            ];

            let open = bgp_open(&buf);

            assert_eq!(open.length(), 29);
            assert_eq!(open.version(), 4);
            assert_eq!(open.my_asn(), Asn::from(64496));
            assert_eq!(open.holdtime(), 90);
            assert_eq!(open.identifier(), &[192, 0, 2, 1]);
            assert_eq!(open.opt_parm_len(), 0);
            assert_eq!(open.parameters().count(), 0);
        }

        #[test]
        fn single_capabilities() {
            // BGP OPEN with 5 optional parameters, all Capability
            let buf = vec![
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x39, 0x01, 0x04, 0x5b, 0xa0, 0x00, 0xb4,
                0x0a, 0x00, 0x00, 0x03, 0x1c, 0x02, 0x06, 0x01,
                0x04, 0x00, 0x01, 0x00, 0x01, 0x02, 0x02, 0x80,
                0x00, 0x02, 0x02, 0x02, 0x00, 0x02, 0x02, 0x46,
                0x00, 0x02, 0x06, 0x41, 0x04, 0x00, 0x64, 0x00,
                0x64
            ];

            let open = bgp_open(&buf);

            assert_eq!(open.capabilities().count(), 5);
            let mut iter = open.capabilities();
            let cap1 = iter.next().unwrap();
            assert_eq!(cap1.typ(), CapabilityType::MultiProtocol);

            let cap2 = iter.next().unwrap();
            assert_eq!(cap2.typ(), CapabilityType::PrestandardRouteRefresh);

            let cap3 = iter.next().unwrap();
            assert_eq!(cap3.typ(), CapabilityType::RouteRefresh);

            let cap4 = iter.next().unwrap();
            assert_eq!(cap4.typ(), CapabilityType::EnhancedRouteRefresh);

            let cap5 = iter.next().unwrap();
            assert_eq!(cap5.typ(), CapabilityType::FourOctetAsn);

            assert!(iter.next().is_none());
        }

        #[test]
        fn multiple_capabilities() {
            // BGP OPEN with one Optional Parameter of type Capability,
            // containing 8 Capabilities.
            let buf = vec![
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x51, 0x01, 0x04, 0xfb, 0xf0, 0x00, 0xb4,
                0xc0, 0x00, 0x02, 0x01, 0x34, 0x02, 0x32, 0x02,
                0x00, 0x46, 0x00, 0x41, 0x04, 0x00, 0x00, 0xfb,
                0xf0, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x01,
                0x04, 0x00, 0x02, 0x00, 0x04, 0x08, 0x04, 0x00,
                0x02, 0x04, 0x0d, 0x40, 0x0a, 0xc0, 0x78, 0x00,
                0x01, 0x01, 0x00, 0x00, 0x02, 0x04, 0x00, 0x45,
                0x08, 0x00, 0x01, 0x01, 0x01, 0x00, 0x02, 0x04,
                0x01
            ];

            let open = bgp_open(&buf);

            assert_eq!(open.capabilities().count(), 8);
            let types = [
                CapabilityType::RouteRefresh,
                CapabilityType::EnhancedRouteRefresh,
                CapabilityType::FourOctetAsn,
                CapabilityType::MultiProtocol,
                CapabilityType::MultiProtocol,
                CapabilityType::MultipleLabels,
                CapabilityType::GracefulRestart,
                CapabilityType::AddPath,
            ];
            for (cap, cap_type) in open.capabilities().zip(types.iter()) {
                assert_eq!(cap.typ(), *cap_type);
            }

            open.capabilities().zip(types.iter()).for_each(|(cap, cap_type)|{
                assert_eq!(cap.typ(), *cap_type);
            });

        }

        #[test]
        fn multiple_multiprotocol() {
            // BGP OPEN message with 15 Multiprotocol capabilities
            let buf = vec![
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x9d, 0x01, 0x04, 0x5b, 0xa0, 0x00, 0xb4,
                0xc0, 0x00, 0x02, 0x02, 0x80, 0x02, 0x06, 0x01,
                0x04, 0x00, 0x01, 0x00, 0x01, 0x02, 0x06, 0x01,
                0x04, 0x00, 0x01, 0x00, 0x02, 0x02, 0x06, 0x01,
                0x04, 0x00, 0x01, 0x00, 0x04, 0x02, 0x06, 0x01,
                0x04, 0x00, 0x01, 0x00, 0x80, 0x02, 0x06, 0x01,
                0x04, 0x00, 0x01, 0x00, 0x84, 0x02, 0x06, 0x01,
                0x04, 0x00, 0x01, 0x00, 0x85, 0x02, 0x06, 0x01,
                0x04, 0x00, 0x01, 0x00, 0x86, 0x02, 0x06, 0x01,
                0x04, 0x00, 0x02, 0x00, 0x01, 0x02, 0x06, 0x01,
                0x04, 0x00, 0x02, 0x00, 0x02, 0x02, 0x06, 0x01,
                0x04, 0x00, 0x02, 0x00, 0x04, 0x02, 0x06, 0x01,
                0x04, 0x00, 0x02, 0x00, 0x80, 0x02, 0x06, 0x01,
                0x04, 0x00, 0x02, 0x00, 0x85, 0x02, 0x06, 0x01,
                0x04, 0x00, 0x02, 0x00, 0x86, 0x02, 0x06, 0x01,
                0x04, 0x00, 0x19, 0x00, 0x41, 0x02, 0x06, 0x01,
                0x04, 0x00, 0x19, 0x00, 0x46, 0x02, 0x06, 0x41,
                0x04, 0x00, 0x01, 0x00, 0x00
                    ];

            let open = bgp_open(&buf);

            assert_eq!(open.multiprotocol_ids().count(), 15);
            let protocols = [
                (AFI::Ipv4, SAFI::Unicast),
                (AFI::Ipv4, SAFI::Multicast),
                (AFI::Ipv4, SAFI::MplsUnicast),
                (AFI::Ipv4, SAFI::MplsVpnUnicast),
                (AFI::Ipv4, SAFI::RouteTarget),
                (AFI::Ipv4, SAFI::FlowSpec),
                (AFI::Ipv4, SAFI::FlowSpecVpn),
                (AFI::Ipv6, SAFI::Unicast),
                (AFI::Ipv6, SAFI::Multicast),
                (AFI::Ipv6, SAFI::MplsUnicast),
                (AFI::Ipv6, SAFI::MplsVpnUnicast),
                (AFI::Ipv6, SAFI::FlowSpec),
                (AFI::Ipv6, SAFI::FlowSpecVpn),
                (AFI::L2Vpn, SAFI::Vpls),
                (AFI::L2Vpn, SAFI::Evpn),
            ];

            for (id, protocol) in open.multiprotocol_ids().zip(
                protocols.iter()
            ){
                assert_eq!(id, *protocol);
            }

        }
    }

    //--- BGP UPDATE related tests -------------------------------------------
    mod update {

        use super::*;
        use std::str::FromStr;

        //TODO:
        // X generic
        // - incomplete msg
        // - path attributes:
        //   - aspath
        //   - attributeset
        // - announcements:
        //   X single conventional
        //   X multiple conventional 
        //   x bgp-mp
        // - withdrawals
        //   - single conventional
        //   X multiple conventional
        //   x bgp-mp
        // - communities
        //   - normal
        //   - extended
        //   - large
        //   - chained iter
        // - MP NLRI types:
        //   announcements:
        //   - v4 mpls unicast
        //   - v4 mpls unicast unreach **missing**
        //   - v4 mpls vpn unicast
        //   - v6 mpls unicast addpath 
        //   - v6 mpls vpn unicast
        //   - multicast **missing
        //   - vpls
        //   - flowspec
        //   - routetarget
        //   withdrawals:
        //   - v4 mpls vpn unicast unreach
        //   - v6 mpls unicast addpath unreach
        //   - v6 mpls vpn unicast
        //
        //
        // x legacy stuff:
        //    as4path
        //


        #[test]
        fn incomplete_msg() {
            let buf = vec![
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x88, 0x02, 
            ];
            assert!(Message::from_octets(&buf).is_err());
        }

        #[test]
        fn conventional() {
            let buf = vec![
                // BGP UPDATE, single conventional announcement, MultiExitDisc
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x37, 0x02,
                0x00, 0x00, 0x00, 0x1b, 0x40, 0x01, 0x01, 0x00, 0x40, 0x02,
                0x06, 0x02, 0x01, 0x00, 0x01, 0x00, 0x00, 0x40, 0x03, 0x04,
                0x0a, 0xff, 0x00, 0x65, 0x80, 0x04, 0x04, 0x00, 0x00, 0x00,
                0x01, 0x20, 0x0a, 0x0a, 0x0a, 0x02
            ];

            let update = bgp_update(&buf);

            assert_eq!(update.length(), 55);
            assert_eq!(update.total_path_attribute_len(), 27);

            let mut pa_iter = update.path_attributes();

            let pa1 = pa_iter.next().unwrap();
            assert_eq!(pa1.type_code(), PathAttributeType::Origin);
            assert_eq!(pa1.flags(), 0x40);
            assert!(!pa1.is_optional());
            assert!(pa1.is_transitive());
            assert!(!pa1.is_partial());
            assert!(!pa1.is_extended_length());

            assert_eq!(pa1.length(), 1);
            assert_eq!(pa1.value(), &[0x00]); // TODO enumify Origin types

            let pa2 = pa_iter.next().unwrap();
            assert_eq!(pa2.type_code(), PathAttributeType::AsPath);
            assert_eq!(pa2.flags(), 0x40);
            assert_eq!(pa2.length(), 6);

            let asp = pa2.value();
            assert_eq!(asp, [0x02, 0x01, 0x00, 0x01, 0x00, 0x00]);

            let mut pb = AsPathBuilder::new();
            pb.push(Asn::from_u32(65536)).unwrap();
            let asp: AsPath<Vec<Asn>> = pb.finalize();

            assert_eq!(update.aspath().unwrap(), asp);

            let pa3 = pa_iter.next().unwrap();
            assert_eq!(pa3.type_code(), PathAttributeType::NextHop);
            assert_eq!(pa3.flags(), 0x40);
            assert_eq!(pa3.length(), 4);
            assert_eq!(pa3.value(), &[10, 255, 0, 101]);
            assert_eq!(
                update.next_hop(),
                Some(NextHop::Ipv4(Ipv4Addr::new(10, 255, 0, 101)))
            );

            let pa4 = pa_iter.next().unwrap();
            assert_eq!(pa4.type_code(), PathAttributeType::MultiExitDisc);
            assert_eq!(pa4.flags(), 0x80);
            assert!(pa4.is_optional());
            assert!(!pa4.is_transitive());
            assert!(!pa4.is_partial());
            assert!(!pa4.is_extended_length());
            assert_eq!(pa4.length(), 4);
            assert_eq!(pa4.value(), &[0x00, 0x00, 0x00, 0x01]);
            assert_eq!(update.multi_exit_desc(), Some(MultiExitDisc(1)));

            assert!(pa_iter.next().is_none());

            let mut nlri_iter = update.nlris();
            let nlri1 = nlri_iter.next().unwrap();
            assert!(matches!(nlri1, Nlri::Basic(_)));
            assert_eq!(
                nlri1.prefix(),
                Some(Prefix::from_str("10.10.10.2/32").unwrap())
            );
            assert!(nlri_iter.next().is_none());
        }

        #[test]
        fn conventional_multiple_nlri() {
            let buf = vec![
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x3c, 0x02, 0x00, 0x00, 0x00, 0x1b, 0x40,
                0x01, 0x01, 0x00, 0x40, 0x02, 0x06, 0x02, 0x01,
                0x00, 0x01, 0x00, 0x00, 0x40, 0x03, 0x04, 0x0a,
                0xff, 0x00, 0x65, 0x80, 0x04, 0x04, 0x00, 0x00,
                0x07, 0x6c, 0x20, 0x0a, 0x0a, 0x0a, 0x09, 0x1e,
                0xc0, 0xa8, 0x61, 0x00
            ];

            let update = bgp_update(&buf);

            assert_eq!(update.total_path_attribute_len(), 27);
            assert_eq!(update.nlris().count(), 2);

            let prefixes = ["10.10.10.9/32", "192.168.97.0/30"].map(|p|
                Prefix::from_str(p).unwrap()
            );

            for (nlri, prefix) in update.nlris().zip(prefixes.iter()) {
                assert_eq!(nlri.prefix(), Some(*prefix))
            }
        }

        #[test]
        fn multiple_mp_reach() {
            // BGP UPDATE message containing MP_REACH_NLRI path attribute,
            // comprising 5 IPv6 NLRIs
            let buf = vec![
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x88, 0x02, 0x00, 0x00, 0x00, 0x71, 0x80,
                0x0e, 0x5a, 0x00, 0x02, 0x01, 0x20, 0xfc, 0x00,
                0x00, 0x10, 0x00, 0x01, 0x00, 0x10, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0xfe, 0x80,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80,
                0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
                0x40, 0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00,
                0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff,
                0x00, 0x01, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0xff,
                0xff, 0x00, 0x02, 0x40, 0x20, 0x01, 0x0d, 0xb8,
                0xff, 0xff, 0x00, 0x03, 0x40, 0x01, 0x01, 0x00,
                0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0x00,
                0xc8, 0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00
            ];
            let update = bgp_update(&buf);

            assert_eq!(update.withdrawn_routes_len(), 0);
            assert_eq!(update.total_path_attribute_len(), 113);

            assert_eq!(update.nlris().count(), 5);

            let prefixes = [
                "fc00::10/128",
                "2001:db8:ffff::/64",
                "2001:db8:ffff:1::/64",
                "2001:db8:ffff:2::/64",
                "2001:db8:ffff:3::/64",
            ].map(|p|
                Prefix::from_str(p).unwrap()
            );

            for (nlri, prefix) in update.nlris().zip(prefixes.iter()) {
                assert_eq!(nlri.prefix(), Some(*prefix))
            }

        }

        #[test]
        fn conventional_withdrawals() {
            // BGP UPDATE with 12 conventional withdrawals
            let buf = vec![
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x53, 0x02, 0x00, 0x3c, 0x20, 0x0a, 0x0a,
                0x0a, 0x0a, 0x1e, 0xc0, 0xa8, 0x00, 0x1c, 0x20,
                0x0a, 0x0a, 0x0a, 0x65, 0x1e, 0xc0, 0xa8, 0x00,
                0x18, 0x20, 0x0a, 0x0a, 0x0a, 0x09, 0x20, 0x0a,
                0x0a, 0x0a, 0x08, 0x1e, 0xc0, 0xa8, 0x61, 0x00,
                0x20, 0x0a, 0x0a, 0x0a, 0x66, 0x1e, 0xc0, 0xa8,
                0x00, 0x20, 0x1e, 0xc0, 0xa8, 0x62, 0x00, 0x1e,
                0xc0, 0xa8, 0x00, 0x10, 0x1e, 0xc0, 0xa8, 0x63,
                0x00, 0x00, 0x00
            ];
            let update = bgp_update(&buf);

            assert_eq!(update.withdrawals().count(), 12);

            let ws = [
                "10.10.10.10/32",
                "192.168.0.28/30",
                "10.10.10.101/32",
                "192.168.0.24/30",
                "10.10.10.9/32",
                "10.10.10.8/32",
                "192.168.97.0/30",
                "10.10.10.102/32",
                "192.168.0.32/30",
                "192.168.98.0/30",
                "192.168.0.16/30",
                "192.168.99.0/30",
            ].map(|w|
                Prefix::from_str(w).unwrap()
            );

            for (nlri, w) in update.withdrawals().zip(ws.iter()) {
                assert_eq!(nlri.prefix(), Some(*w))
            }

        }

        #[test]
        fn multiple_mp_unreach() {
            // BGP UPDATE with 4 MP_UNREACH_NLRI
            let buf = vec![
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x41, 0x02, 0x00, 0x00, 0x00, 0x2a, 0x80,
                0x0f, 0x27, 0x00, 0x02, 0x01, 0x40, 0x20, 0x01,
                0x0d, 0xb8, 0xff, 0xff, 0x00, 0x00, 0x40, 0x20,
                0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x01, 0x40,
                0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x02,
                0x40, 0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00,
                0x03
            ];
            let update = bgp_update(&buf);

            assert_eq!(update.withdrawals().count(), 4);
            
            let ws = [
                "2001:db8:ffff::/64",
                "2001:db8:ffff:1::/64",
                "2001:db8:ffff:2::/64",
                "2001:db8:ffff:3::/64",
            ].map(|w|
                Prefix::from_str(w).unwrap()
            );

            for (nlri, w) in update.withdrawals().zip(ws.iter()) {
                assert_eq!(nlri.prefix(), Some(*w))
            }
        }

        //--- Path Attributes ------------------------------------------------
        
        #[test]
        fn local_pref_multi_exit_disc() {
            // BGP UPDATE with 5 conventional announcements, MULTI_EXIT_DISC
            // and LOCAL_PREF path attributes
            let buf = vec![
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x60, 0x02, 0x00, 0x00, 0x00, 0x30, 0x40,
                0x01, 0x01, 0x00, 0x40, 0x02, 0x14, 0x03, 0x01,
                0x00, 0x00, 0xfd, 0xea, 0x02, 0x03, 0x00, 0x00,
                0x01, 0x90, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x00,
                0x01, 0xf4, 0x40, 0x03, 0x04, 0x0a, 0x04, 0x05,
                0x05, 0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00,
                0x40, 0x05, 0x04, 0x00, 0x00, 0x00, 0x64, 0x20,
                0x0a, 0x00, 0x00, 0x09, 0x1a, 0xc6, 0x33, 0x64,
                0x00, 0x1a, 0xc6, 0x33, 0x64, 0x40, 0x1a, 0xc6,
                0x33, 0x64, 0x80, 0x1a, 0xc6, 0x33, 0x64, 0xc0
            ];
            let update = bgp_update(&buf);
            assert_eq!(update.multi_exit_desc(), Some(MultiExitDisc(0)));
            assert_eq!(update.local_pref(), Some(LocalPref(100)));
        }

        #[test]
        fn atomic_aggregate() {
            // BGP UPDATE with AGGREGATOR and ATOMIC_AGGREGATE
            let buf = vec![
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x44, 0x02, 0x00, 0x00, 0x00, 0x29, 0x40,
                0x01, 0x01, 0x00, 0x40, 0x02, 0x06, 0x02, 0x01,
                0x00, 0x00, 0x00, 0x65, 0xc0, 0x07, 0x08, 0x00,
                0x00, 0x00, 0x65, 0xc6, 0x33, 0x64, 0x01, 0x40,
                0x06, 0x00, 0x40, 0x03, 0x04, 0x0a, 0x01, 0x02,
                0x01, 0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00,
                0x18, 0xc6, 0x33, 0x64
            ];
            let update = bgp_update(&buf);
            let aggr = update.aggregator().unwrap();

            assert!(update.is_atomic_aggregate());
            assert_eq!(aggr.asn(), Asn::from(101));
            assert_eq!(
                aggr.speaker(),
                Ipv4Addr::from_str("198.51.100.1").unwrap()
            );
        }

        #[test]
        fn as4path() {
            // BGP UPDATE with AS_PATH and AS4_PATH, both containing one
            // SEQUENCE of length 10. First four in AS_PATH are actual ASNs,
            // last six are AS_TRANS.
            let buf = vec![
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x6e, 0x02, 0x00, 0x00, 0x00, 0x53, 0x40,
                0x01, 0x01, 0x00, 0x50, 0x02, 0x00, 0x16, 0x02,
                0x0a, 0xfb, 0xf0, 0xfb, 0xf1, 0xfb, 0xf2, 0xfb,
                0xf3, 0x5b, 0xa0, 0x5b, 0xa0, 0x5b, 0xa0, 0x5b,
                0xa0, 0x5b, 0xa0, 0x5b, 0xa0, 0x40, 0x03, 0x04,
                0xc0, 0xa8, 0x01, 0x01, 0xd0, 0x11, 0x00, 0x2a,
                0x02, 0x0a, 0x00, 0x00, 0xfb, 0xf0, 0x00, 0x00,
                0xfb, 0xf1, 0x00, 0x00, 0xfb, 0xf2, 0x00, 0x00,
                0xfb, 0xf3, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
                0x00, 0x0a, 0x16, 0x0a, 0x01, 0x04
            ];
            // TODO create test helper for specific SessionConfigs
            let mut sc = SessionConfig::new(); sc.disable_four_octet_asn();
            let update: MessageUpdate = Message::from_octets_with_sc(&buf, sc)
                .unwrap().try_into().unwrap();

            if let Some(aspath) = update.path_attributes().find(|pa|
                pa.type_code() == PathAttributeType::AsPath
            ){
                assert_eq!(aspath.flags(), 0x50);
                assert!(aspath.is_transitive());
                assert!(aspath.is_extended_length());
                assert_eq!(aspath.length(), 22);
                //TODO check actual aspath
            } else {
                panic!("ASPATH path attribute not found")
            }

            if let Some(as4path) = update.path_attributes().find(|pa|
                pa.type_code() == PathAttributeType::As4Path
            ){
                assert_eq!(as4path.flags(), 0xd0);
                assert_eq!(as4path.length(), 42);
                //TODO check actual aspath
            } else {
                panic!("AS4PATH path attribute not found")
            }

        }

    }


    //--- BGP NOTIFICATION related tests -------------------------------------
    mod notification {
        //TODO
    }


    //--- BGP KEEPAlIVE related tests ----------------------------------------
    mod keepalive {
        //TODO
    }


    //--- BGP ROUTEREFRESH related tests -------------------------------------
    mod routerefresh {
        //TODO
    }


}
