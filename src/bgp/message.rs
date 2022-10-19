//! BGP message parsing.
//!
//! This module contains functionality to parse BGP messages from raw bytes,
//! providing access to its contents based on the underlying `bytes` buffer
//! without allocating.

use crate::flowspec::Component;
use log::{warn, error};

use crate::asn::{Asn, AsPath, AsPathBuilder, SegmentType};
use crate::addr::{Prefix, PrefixError};
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use std::error::Error;

use crate::util::parser::{parse_ipv4addr, parse_ipv6addr, ParseError};
use octseq::{OctetsRef, Parser};

use super::communities::{
    Community, StandardCommunity,
    ExtendedCommunity, Ipv6ExtendedCommunity, 
    LargeCommunity
};

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
///  * `OpenMessage`
///  * `UpdateMessage`
///  * `NotificationMessage`
///  * `KeepAliveMessage`
///  * TODO: `RouteRefreshMessage`
///
pub enum Message<Octets> {
    Open(OpenMessage<Octets>),
    Update(UpdateMessage<Octets>),
    Notification(NotificationMessage<Octets>),
    KeepAlive(KeepAliveMessage<Octets>),
}

/// BGP OPEN message, variant of the [`Message`] enum.
#[derive(Debug, Eq, PartialEq)]
pub struct OpenMessage<Octets> {
    octets: Octets,
}

/// BGP UPDATE message, variant of the [`Message`] enum.
pub struct UpdateMessage<Octets> {
    octets: Octets,
    session_config: SessionConfig,
}

/// BGP NOTIFICATION message, variant of the [`Message`] enum.
pub struct NotificationMessage<Octets> {
    octets: Octets
}

/// BGP KeepAlive message, variant of the [`Message`] enum.
pub struct KeepAliveMessage<Octets> {
    octets: Octets
}

impl<Octets: AsRef<[u8]>> AsRef<[u8]> for Message<Octets>
{
    fn as_ref(&self) -> &[u8] {
        match self {
            Message::Open(m) => m.octets.as_ref(),
            Message::Update(m) => m.octets.as_ref(),
            Message::Notification(m) => m.octets.as_ref(),
            Message::KeepAlive(m) => m.octets.as_ref(),
        }
    }
}

impl<Octets: AsRef<[u8]>> Message<Octets>
{
    fn octets(&self) -> &Octets {
        match self {
            Message::Open(m) => &m.octets,
            Message::Update(m) => &m.octets,
            Message::Notification(m) => &m.octets,
            Message::KeepAlive(m) => &m.octets,
        }
    }
}

impl<Octets: AsRef<[u8]>> Message<Octets>
where
    for <'a> &'a Octets: OctetsRef
{
    fn header(&self) -> Header<<&Octets as OctetsRef>::Range> {
        Header::for_slice(self.octets().range_to(19))
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

impl<Octets: AsRef<[u8]>> OpenMessage<Octets>
where
    for <'a> &'a Octets: OctetsRef
{
    /// Returns the [`Header`] for this message.
    pub fn header(&self) -> Header<<&Octets as OctetsRef>::Range> {
        Header::for_slice(self.octets.range_to(19))
    }
    
    /// Returns the length in bytes of the entire BGP message.
	pub fn length(&self) -> u16 {
        self.header().length()
	}
}

impl<Octets: AsRef<[u8]>> AsRef<[u8]> for OpenMessage<Octets> {
    fn as_ref(&self) -> &[u8] {
        self.octets.as_ref()
    }
}

impl<Octets: AsRef<[u8]>> UpdateMessage<Octets> {
    /// Returns the [`Header`] for this message.
    pub fn header(&self) -> Header<&Octets> {
        Header::for_slice(&self.octets)
    }

    /// Returns the length in bytes of the entire BGP message.
	pub fn length(&self) -> u16 {
        self.header().length()
	}
}

impl<Octets: AsRef<[u8]>> AsRef<[u8]> for UpdateMessage<Octets> {
    fn as_ref(&self) -> &[u8] {
        self.octets.as_ref()
    }
}

impl<Octets: AsRef<[u8]>> NotificationMessage<Octets>
where
    for <'a> &'a Octets: OctetsRef
{
    /// Returns the [`Header`] for this message.
    pub fn header(&self) -> Header<<&Octets as OctetsRef>::Range>
    {
        Header::for_slice(self.octets.range_to(19))
    }

    /// Returns the length in bytes of the entire BGP message.
	pub fn length(&self) -> u16 {
        self.header().length()
	}
}

impl<Octets: AsRef<[u8]>> AsRef<[u8]> for NotificationMessage<Octets> {
    fn as_ref(&self) -> &[u8] {
        self.octets.as_ref()
    }
}

impl<Octets: AsRef<[u8]>>TryFrom<Message<Octets>> for OpenMessage<Octets> {
    type Error = MessageError;

    fn try_from(msg: Message<Octets>) -> Result<Self, Self::Error> {
        match msg {
            Message::Open(u) => Ok(u),
            _ => Err(MessageError::InvalidMsgType),
        }
    }
}

impl<Octets: AsRef<[u8]>>TryFrom<Message<Octets>> for UpdateMessage<Octets> {
    type Error = MessageError;

    fn try_from(msg: Message<Octets>) -> Result<Self, Self::Error> {
        match msg {
            Message::Update(u) => Ok(u),
            _ => Err(MessageError::InvalidMsgType),
        }
    }
}

impl<Octets: AsRef<[u8]>> TryFrom<Message<Octets>> for NotificationMessage<Octets> {
    type Error = MessageError;

    fn try_from(msg: Message<Octets>) -> Result<Self, Self::Error> {
        match msg {
            Message::Notification(u) => Ok(u),
            _ => Err(MessageError::InvalidMsgType),
        }
    }
}


impl<Octets: AsRef<[u8]>> Message<Octets>
where
    for<'b> &'b Octets: OctetsRef
{
    /// Create a Message from an octets sequence.
    pub fn from_octets(octets: Octets, config: Option<SessionConfig>)
        -> Result<Message<Octets>, ParseError>
    {
        let mut parser = Parser::from_ref(&octets);
        let hdr = Header::parse(&mut parser)?;
        parser.seek(0)?;
        match hdr.msg_type() {
            MsgType::Open =>
                Ok(Message::Open(OpenMessage::from_octets(octets)?)),
            MsgType::Update => {
                let config = if let Some(c) = config {
                    c
                } else {
                    return Err(ParseError::StateRequired)
                };
                Ok(Message::Update(
                        UpdateMessage::from_octets(octets, config)?
                ))
            },
            MsgType::Notification =>
                Ok(Message::Notification(
                    NotificationMessage::from_octets(octets)?
                )),
            MsgType::KeepAlive =>
                Ok(Message::KeepAlive(
                        KeepAliveMessage::from_octets(octets)?
                )),
            t => panic!("not implemented yet: {:?}", t)
        }
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
pub struct Header<Octets>(Octets);

impl<Octets: AsRef<[u8]>> Header<Octets> {

    /// Create a Header from an Octets.
    pub fn for_slice(s: Octets) -> Self {
        Header(s)
    }

    /// Returns the value of the length field in this header.
	pub fn length(&self) -> u16 {
		u16::from_be_bytes([self.0.as_ref()[16], self.0.as_ref()[17]])
	}

    /// Returns the value of the message type field in this header.
    pub fn msg_type(self) -> MsgType {
        match self.0.as_ref()[18] {
            1 => MsgType::Open,
            2 => MsgType::Update,
            3 => MsgType::Notification,
            4 => MsgType::KeepAlive,
            5 => MsgType::RouteRefresh,
            u => panic!("illegal Message Type {}", u)
        }
    }
}

impl<Octets: AsRef<[u8]>> Header<Octets> {
    fn parse<R>(parser: &mut Parser<R>) -> Result<Self, ParseError>
    where
        R: OctetsRef<Range = Octets>
    {
        let pos = parser.pos();
        Marker::check(parser)?;
        let _len = parser.parse_u16()?;
        let _typ = parser.parse_u8()?;
        parser.seek(pos)?;
        let res = parser.parse_octets(19)?;
        Ok(Header(res))
    }

    fn check<Ref: OctetsRef>(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        Marker::check(parser)?;
        let len = parser.parse_u16()? as usize;
        if len != parser.len() {
            return Err(ParseError::form_error("invalid length"));
        }
        // jump over type 
        // XXX should we check whether type is in our enum?
        parser.advance(1)?;
        Ok(())
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
/// * [`my_asn()`][`OpenMessage::my_asn`]: returns the 32bit ASN if present,
/// otherwise falls back to the conventional 16bit ASN (though represented as
/// the 32bit [`routecore::asn::Asn`][`Asn`]);
/// * [`multiprotocol_ids()`][`OpenMessage::multiprotocol_ids`]: returns an
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
impl<Octets: AsRef<[u8]>> OpenMessage<Octets> {
    pub fn for_slice(s: Octets) -> Self {
        OpenMessage { octets: s }
    }
}

impl<Octets: AsRef<[u8]>> OpenMessage<Octets> {
    /// Returns the protocol version number, which should be 4.
    pub fn version(&self) -> u8 {
        self.octets.as_ref()[COFF]
    }

    /// Convenience method: returns the `Asn` from the Capabilities if any,
    /// otherwise the two-octet Asn from the 'My Autonomous System' field.
    pub fn my_asn(&self) -> Asn 
    where
        for<'a> &'a Octets: OctetsRef,
    {
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
    pub fn identifier(&self) -> &[u8] {
        &self.octets.as_ref()[COFF+5..COFF+9]
    }

    /// Returns the length of the Optional Parameters. If 0, there are no
    /// Optional Parameters in this BGP OPEN message.
    pub fn opt_parm_len(&self) -> u8 {
        self.octets.as_ref()[COFF+9]
    }

    /// Returns an iterator over the Optional Parameters.
    pub fn parameters(&self) -> ParametersParser<&Octets> {
        self.parameters_iter()
    }

    fn parameters_iter(&self) -> ParametersParser<&Octets> {
        let mut p = Parser::from_ref(&self.octets); 
        p.advance(COFF+10).unwrap();

        ParametersParser {
            parser: p.parse_parser(self.opt_parm_len() as usize).unwrap()
        }
    }

    /// Returns an iterator over the Capabilities
    // Multiple Capabilities can be carried in a single Optional Parameter, or
    // multiple individual Optional Parameters can carry a single Capability
    // each. Hence the flatten.
	pub fn capabilities(&'_ self)
        -> impl Iterator<Item = Capability<<&'_ Octets as OctetsRef>::Range>>
    where
        for <'a> &'a Octets: OctetsRef,
    {
        self.parameters_iter().filter(|p|
            p.typ() == OptionalParameterType::Capabilities
        ).flat_map(|p|
            p.into_capability_iter()
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
    pub fn four_octet_capable(&self) -> bool
    where
        for<'a> &'a Octets: OctetsRef,
    {
        self.capabilities().any(|c|
            c.typ() == CapabilityType::FourOctetAsn
        )
    }

    // FIXME this should return a AFI/SAFI combination, not a bool
    pub fn add_path_capable(&self) -> bool
    where
        for<'a> &'a Octets: OctetsRef,
    {
        self.capabilities().any(|c|
            c.typ() == CapabilityType::AddPath
        )
    }

    /// Returns an iterator over `(AFI, SAFI)` tuples listed as
    /// MultiProtocol Capabilities in the Optional Parameters of this message.
    pub fn multiprotocol_ids(&self) -> impl Iterator<Item = (AFI,SAFI)> + '_ 
    where
        for <'a> &'a Octets: OctetsRef,
    {
        self.capabilities().filter(|c|
            c.typ() == CapabilityType::MultiProtocol
        ).map(|mp_cap| {
            let afi = u16::from_be_bytes([
                mp_cap.value()[0],
                mp_cap.value()[1]
            ]);
            let safi = mp_cap.value()[3];
            (afi.into(), safi.into())
        })
    }

}

impl<Octets: AsRef<[u8]>> OpenMessage<Octets> {
    /// Create an OpenMessage from an octets sequence.
    pub fn from_octets(octets: Octets) -> Result<Self, ParseError>
    where
        for <'a> &'a Octets: OctetsRef
    {
        Self::check(&octets)?;
        Ok( OpenMessage { octets } )
    }

    fn check(octets: &Octets) -> Result<(), ParseError>
    where
        for <'a> &'a Octets: OctetsRef
    {
        let mut parser = Parser::from_ref(octets);
        Header::<Octets>::check(&mut parser)?;
        // jump over version, 2-octet ASN, Hold timer and BGP ID
        parser.advance(1 + 2 + 2 + 4)?;
        let opt_param_len = parser.parse_u8()? as usize;
        let mut param_parser = parser.parse_parser(opt_param_len)?;

        while param_parser.remaining() > 0 {
            Parameter::<Octets>::check(&mut param_parser)?;
        }

        if parser.remaining() > 0 {
            return Err(ParseError::form_error("trailing bytes"));
        }

        Ok(())

    }

    pub fn parse<R>(parser: &mut Parser<R>) -> Result<Self, ParseError>
    where
        R: OctetsRef<Range = Octets>,
    {
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
            Self { octets: parser.parse_octets(hdr.length().into())? }
        )

    }
}

impl<Octets: AsRef<[u8]>> Parameter<Octets> {
    fn parse<Ref>(parser: &mut Parser<Ref>) -> Result<Self, ParseError>
    where
        Ref: OctetsRef<Range = Octets>
    {
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

    fn check<Ref: OctetsRef>(parser: &mut Parser<Ref>)
        -> Result<(), ParseError>
    {
        let typ = parser.parse_u8()?;
        let len = parser.parse_u8()? as usize;
        if typ == 2 {
            // There might be more than Capability within a single Optional
            // Parameter, so we need to loop.
            let mut caps_parser = parser.parse_parser(len)?;
            while caps_parser.remaining() > 0 {
                Capability::<Octets>::check(&mut caps_parser)?;
            }
        } else {
            warn!("Optional Parameter in BGP OPEN other than Capability: {}",
                typ
            );
        }
        Ok(())
    }
}

impl<Octets: AsRef<[u8]>> Capability<Octets> {
    fn check<Ref: OctetsRef>(parser: &mut Parser<Ref>)
        -> Result<(), ParseError>
    {
        let _typ = parser.parse_u8()?;
        let len = parser.parse_u8()? as usize;
        parser.advance(len)?;
        Ok(())
    }

    fn parse<Ref>(parser: &mut Parser<Ref>) -> Result<Self, ParseError>
    where
        Ref: OctetsRef<Range = Octets>
    {
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
pub struct Capability<Octets> {
    octets: Octets,
}

impl<Octets: AsRef<[u8]>> Capability<Octets> {
    fn for_slice(octets: Octets) -> Capability<Octets> {
        Capability { octets }
    }

    /// Returns the [`CapabilityType`] of this capability.
    pub fn typ(&self) -> CapabilityType {
        self.octets.as_ref()[0].into()
    }

    pub fn length(&self) -> u8 {
        self.octets.as_ref()[1]
    }

    pub fn value(&'_ self) -> &'_ [u8] {
        &self.octets.as_ref()[2..]
    }
}

/// Iterator for BGP OPEN Capabilities.
pub struct CapabilitiesIter<Ref> {
    parser: Parser<Ref>,
}

impl<Ref: OctetsRef> Iterator for CapabilitiesIter<Ref> {
    type Item = Capability<Ref::Range>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None;
        }
        Some(Capability::parse(&mut self.parser).unwrap())
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
pub struct Parameter<Octets> {
    octets: Octets,
}

/// Iterator over BGP OPEN Optional [`Parameter`]s.
pub struct ParametersParser<Ref> {
    parser: Parser<Ref>
}

pub struct ParameterParser<Ref> {
    typ: OptionalParameterType,
    parser: Parser<Ref>
}

impl<Ref> ParameterParser<Ref> {
    fn into_capability_iter(self) -> CapabilitiesIter<Ref> {
        CapabilitiesIter { parser: self.parser }
    }

    /// Returns the parameter type.
    pub fn typ(&self) -> OptionalParameterType {
        self.typ
    }
}

impl<Octets: AsRef<[u8]>> Parameter<Octets> {
    /// Returns the parameter type.
    pub fn typ(&self) -> OptionalParameterType {
        self.octets.as_ref()[0].into()
    }
    
    /// Returns the parameter length.
    pub fn length(&self) -> u8 {
        self.octets.as_ref()[1]
    }
}

impl<Octets: AsRef<[u8]>> Parameter<Octets> {
    fn for_slice(slice: Octets) -> Self {
        Parameter { octets: slice }
    }
}

impl<Octets: AsRef<[u8]>> Parameter<Octets>
where
    for <'a> &'a Octets: OctetsRef<Range = Octets>
{
    /// Returns the raw value of the parameter.
    pub fn value(&self) -> <&Octets as OctetsRef>::Range {
        self.octets.range_from(2)
    }
}

impl<Ref: OctetsRef> Iterator for ParametersParser<Ref> {
    type Item = ParameterParser<Ref>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None;
        }
        let typ: OptionalParameterType = self.parser.parse_u8().unwrap().into();
        let len = self.parser.parse_u8().unwrap();
        Some(ParameterParser {
                typ,
                parser: self.parser.parse_parser(len as usize).unwrap()
            })
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
/// * [`nlris()`][`UpdateMessage::nlris`] and
/// [`withdrawals()`][`UpdateMessage::withdrawals`],
/// providing iterators over announced and withdrawn prefixes ;
/// * [`next_hop()`][`UpdateMessage::next_hop`], returning the [`NextHop`] ;
/// * [`all_communities()`][`UpdateMessage::all_communities`], returning an
/// optional `Vec` containing all conventional, Extended and Large
/// Communities, wrapped in the [`Community`] enum.
///
/// For the mandatory path attributes, we have:
///
/// * [`origin()`][`UpdateMessage::origin`]
/// * [`aspath()`][`UpdateMessage::aspath`]
///
/// Other path attributes ([`PathAttribute`] of a certain
/// [`PathAttributeType`]) can be access via the iterator provided via
/// [`path_attributes()`][`UpdateMessage::path_attributes`].
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

impl<Octets: AsRef<[u8]>> UpdateMessage<Octets> {
    fn for_slice(s: Octets, config: SessionConfig) -> Self {
        Self {
            octets: s,
            session_config: config
        }
    }
}

impl<Octets: AsRef<[u8]>> UpdateMessage<Octets> {
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
}

impl<'s, Octets: 's + AsRef<[u8]>> UpdateMessage<Octets>
where
    &'s Octets: OctetsRef,
    for<'a> &'a<&'s Octets as OctetsRef>::Range: OctetsRef,
    for<'a> &'a<&'s Octets as OctetsRef>::Range: OctetsRef<Range = <&'s Octets as OctetsRef>::Range>
{
    pub fn withdrawals(&'s self)
        -> Withdrawals<<&'s Octets as OctetsRef>::Range>
    {
        if let Some(pa) = self.path_attributes().iter().find(|pa|
            pa.type_code() == PathAttributeType::MpUnreachNlri
        ) {
            let v = pa.value();
            let mut parser = Parser::from_ref(&v);
            Withdrawals::parse(&mut parser, self.session_config).expect("parsed before")

        } else {
            let len = self.withdrawn_routes_len() as usize;
            let r = (self).octets.range(COFF+2,COFF+2+len);
            let mut parser = Parser::from_ref(&r);
            Withdrawals::parse_conventional(&mut parser, self.session_config).expect("parsed before")
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

    pub fn path_attributes(&'s self)
        -> PathAttributes<<&'s Octets as OctetsRef>::Range>
    {
        let wrl = self.withdrawn_routes_len() as usize;
        let tpal = self.total_path_attribute_len() as usize;
        
        let mut parser = Parser::from_ref(&self.octets);
        parser.advance(COFF+2+wrl+2).unwrap();

        PathAttributes {
            octets: self.octets.range(COFF+2+wrl+2, COFF+2+wrl+2+tpal),
            session_config: self.session_config
        }
    }

    /// Iterator over the reachable NLRIs.
    ///
    /// If present, the NLRIs are taken from the MP_REACH_NLRI path attribute.
    /// Otherwise, they are taken from their conventional place at the end of
    /// the message.
    pub fn nlris(&'s self)
        -> Nlris<<&'s Octets as OctetsRef>::Range>
    {
        if let Some(pa) = self.path_attributes().iter().find(|pa|
            pa.type_code() == PathAttributeType::MpReachNlri
        ) {
            let v = pa.value();
            let mut parser = Parser::from_ref(&v);
            Nlris::parse(&mut parser, self.session_config).expect("parsed before")
        } else {
            let wrl = self.withdrawn_routes_len() as usize;
            let tpal = self.total_path_attribute_len() as usize;
            let r = self.octets.range_from(COFF+2+wrl+2+tpal);
            let mut parser = Parser::from_ref(&r);
            Nlris::parse_conventional(&mut parser, self.session_config).expect("parsed before")
        }
    }

    /// Returns `Option<(AFI, SAFI)>` if this UPDATE represents the End-of-RIB
    /// marker for a AFI/SAFI combination.
    pub fn is_eor(&'s self) -> Option<(AFI, SAFI)> {
        // Conventional BGP
        if self.length() == 23 {
            // minimum length for a BGP UPDATE indicates EOR
            // (no annoucements, no withdrawals)
            return Some((AFI::Ipv4, SAFI::Unicast));
        }

        // Based on MP_UNREACH_NLRI
        if self.total_path_attribute_len() > 0
            && self.path_attributes().iter().all(|pa|
                pa.type_code() == PathAttributeType::MpUnreachNlri
                && pa.length() == 3 // only AFI/SAFI, no NLRI
            ) {
                let pa = self.path_attributes().iter().next().unwrap();
                return Some((
                    u16::from_be_bytes(
                            [pa.value().as_ref()[0], pa.value().as_ref()[1]]
                    ).into(),
                    pa.value().as_ref()[2].into()
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
    pub fn origin(&'s self) -> Option<OriginType> {
        self.path_attributes().iter().find(|pa|
            pa.type_code() == PathAttributeType::Origin
        ).map(|pa|
            match pa.value().as_ref()[0] {
                0 => OriginType::Igp,
                1 => OriginType::Egp,
                2 => OriginType::Incomplete,
                n => OriginType::Unknown(n),
            }
        )
    }

    pub fn as4path(&'s self) -> Option<AsPath<Vec<Asn>>> {
        self.path_attributes().iter().find(|pa|
            pa.type_code() == PathAttributeType::As4Path
        ).map(|pa| {
            let asn_size = 4;
            let octets = pa.value();
            let mut aspb = AsPathBuilder::new();

            let mut pos = 0;
            while pos < octets.as_ref().len() {
                let st = SegmentType::try_from(octets.as_ref()[pos])
                    .expect("parsed before");
                let num_asns = octets.as_ref()[pos+1] as usize;
                aspb.start(st);
                pos += 2;

                for _ in 0..num_asns {
                    let asn = Asn::from(
                        u32::from_be_bytes(
                            octets.as_ref()[pos..pos+asn_size]
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

    /// Returns the AS_PATH path attribute.
    pub fn aspath(&'s self) -> Option<AsPath<Vec<Asn>>> {
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
        self.path_attributes().iter().find(|pa|
            pa.type_code() == PathAttributeType::AsPath
        ).map(|ref pa| {
            // Check for AS4_PATH
            // Note that all the as4path code in this part is useless because
            // of the early return above, but for now let's leave it here for
            // understanding/reasoning.
            let as4path = self.as4path();

            // Apparently, some BMP exporters do not set the legacy format
            // bit but do emit 2-byte ASNs. 
            let asn_size = match self.session_config.four_octet_asn { 
                FourOctetAsn::Enabled => 4,
                FourOctetAsn::Disabled => 2,
            };

            let octets = pa.value();
            let mut aspb = AsPathBuilder::new();

            let mut pos = 0;
            let mut segment_idx = 0;
            while pos < octets.as_ref().len() {
                let st = SegmentType::try_from(octets.as_ref()[pos]).expect("parsed
                    before");
                let num_asns = octets.as_ref()[pos+1] as usize;
                aspb.start(st);
                pos += 2;

                for _ in 0..num_asns {
                    let asn = if asn_size == 4 {
                    Asn::from(
                        u32::from_be_bytes(
                            octets.as_ref()[pos..pos+asn_size]
                            .try_into().expect("parsed before")
                            )
                        )
                    } else {
                    Asn::from(
                        u16::from_be_bytes(
                            octets.as_ref()[pos..pos+asn_size]
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

    /// Returns the NEXT_HOP path attribute, or the equivalent from
    /// MP_REACH_NLRI.
    pub fn next_hop(&'s self) -> Option<NextHop> {
        if let Some(pa) = self.path_attributes().iter().find(|pa|
            pa.type_code() == PathAttributeType::MpReachNlri
        ) {
            let mut parser = Parser::from_ref(pa.value());
            let afi: AFI = parser.parse_u16().expect("parsed before").into();
            let safi: SAFI = parser.parse_u8().expect("parsed before").into();

            return Some(NextHop::parse(&mut parser, afi, safi).expect("parsed before"));
        } 

        self.path_attributes().iter().find(|pa|
            pa.type_code() == PathAttributeType::NextHop
        ).map(|pa|
            NextHop::Ipv4(
                Ipv4Addr::new(
                    pa.value().as_ref()[0],
                    pa.value().as_ref()[1],
                    pa.value().as_ref()[2],
                    pa.value().as_ref()[3],
                )
            )
        )
    }

    //--- Non-mandatory path attribute helpers -------------------------------

    /// Returns the Multi-Exit Discriminator value, if any.
    pub fn multi_exit_desc(&'s self) -> Option<MultiExitDisc> {
        self.path_attributes().iter().find(|pa|
            pa.type_code() == PathAttributeType::MultiExitDisc
        ).map(|pa|
            MultiExitDisc(u32::from_be_bytes(
                    pa.value().as_ref()[0..4].try_into()
                        .expect("parsed before")
            ))
        )
    }

    /// Returns the Local Preference value, if any.
    pub fn local_pref(&'s self) -> Option<LocalPref> {
        self.path_attributes().iter().find(|pa|
            pa.type_code() == PathAttributeType::LocalPref
        ).map(|pa|
            LocalPref(u32::from_be_bytes(
                    pa.value().as_ref()[0..4].try_into()
                    .expect("parsed before")
            ))
        )
    }

    /// Returns true if this UPDATE contains the ATOMIC_AGGREGATE path
    /// attribute.
    pub fn is_atomic_aggregate(&'s self) -> bool {
        self.path_attributes().iter().any(|pa|
            pa.type_code() == PathAttributeType::AtomicAggregate
        )
    }

    /// Returns the AGGREGATOR path attribute, if any.
    // this one originally carried a 2-octet ASN, but now also possibly a
    // 4-octet one (RFC 6793, Four Octet ASN support)
    // furthermore, it was designed to carry a IPv4 address, but that does not
    // seem to have changed with RFC4760 (multiprotocol)
    //
    // As such, we can determine whether there is a 2-octet or 4-octet ASN
    // based on the size of the attribute itself.
    // 
    pub fn aggregator(&'s self) -> Option<Aggregator> {
        self.path_attributes().iter().find(|pa|
            pa.type_code() == PathAttributeType::Aggregator
        ).map(|pa| {
            let mut p = Parser::from_ref(pa.value());
            Aggregator::parse(&mut p, self.session_config).expect("parsed before")
        })
    }


    //--- Communities --------------------------------------------------------

    /// Returns an iterator over Standard Communities (RFC1997), if any.
    pub fn communities(&'s self)
        -> Option<CommunityIter<<&'s Octets as OctetsRef>::Range>>
    {
        self.path_attributes().iter().find(|pa|
            pa.type_code() == PathAttributeType::Communities
        ).map(|ref pa| CommunityIter::new(pa.value())
        )
    }

    /// Returns an iterator over Extended Communities (RFC4360), if any.
    pub fn ext_communities(&'s self)
        -> Option<ExtCommunityIter<<&'s Octets as OctetsRef>::Range>>
    {
        self.path_attributes().iter().find(|pa|
            pa.type_code() == PathAttributeType::ExtendedCommunities
        ).map(|pa| ExtCommunityIter::new(pa.value())
        )
    }

    /// Returns an iterator over Large Communities (RFC8092), if any.
    pub fn large_communities(&'s self)
        -> Option<LargeCommunityIter<<&'s Octets as OctetsRef>::Range>>
    {
        self.path_attributes().iter().find(|pa|
            pa.type_code() == PathAttributeType::LargeCommunities
        ).map(|pa| LargeCommunityIter::new(pa.value())
        )
    }

    /// Returns an optional `Vec` containing all conventional, Extended and
    /// Large communities, if any, or None if none of the three appear in the
    /// path attributes of this message.
    pub fn all_communities(&'s self) -> Option<Vec<Community>> {
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
impl Marker {
    fn check<Ref: OctetsRef>(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        let mut buf = [0u8; 16];
        parser.parse_buf(&mut buf)?;
        if buf != [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        ] {
            return Err(ParseError::form_error("invalid BGP marker"))
        }
        Ok(())
    }
}

impl<Octets: AsRef<[u8]>> UpdateMessage<Octets> {
    /// Create an UpdateMessage from an octets sequence.
    ///
    /// As parsing of BGP UPDATE messages requires stateful information
    /// signalled by the BGP OPEN messages, this function requires a
    /// [`SessionConfig`].
    pub fn from_octets(octets: Octets, config: SessionConfig)
        -> Result<Self, ParseError>
    where
        for <'a> &'a Octets: OctetsRef
   {
        Self::check(&octets, config)?;
        Ok(UpdateMessage {
            octets,
            session_config: config
        })
    }

    fn check(octets: &Octets, config: SessionConfig) -> Result<(), ParseError>
    where
        for <'a> &'a Octets: OctetsRef
    {
        let mut parser = Parser::from_ref(octets);
        Header::<Octets>::check(&mut parser)?;

        let withdrawals_len = parser.parse_u16()?;
        if withdrawals_len > 0 {
            let mut wdraw_parser = parser.parse_parser(
                withdrawals_len.into()
            )?;
            while wdraw_parser.remaining() > 0 {
                // conventional withdrawals are always IPv4
                BasicNlri::check(&mut wdraw_parser, config, AFI::Ipv4)?;
            }
        }

        let path_attributes_len = parser.parse_u16()?;
        if path_attributes_len > 0 {
            let mut pas_parser = parser.parse_parser(
                path_attributes_len.into()
            )?;
            PathAttributes::check(&mut pas_parser, config)?;
        }

        while parser.remaining() > 0 {
            // conventional announcements are always IPv4
            BasicNlri::check(&mut parser, config, AFI::Ipv4)?;
        }

        Ok(())
    }

    // XXX can we replace this with a from_octets now?
    // or rewrite this to check() + UpdateMessage { parse_octets() } or something?
    pub fn parse<R>(parser: &mut Parser<R>, config: SessionConfig)
        -> Result<Self, ParseError>
    where
        R: OctetsRef<Range = Octets>,
    {
        // parse header
        let pos = parser.pos();
        let hdr = Header::parse(parser)?;

        let withdrawn_len = parser.parse_u16()?;
        if withdrawn_len > 0 {
            let mut wdraw_parser = parser.parse_parser(withdrawn_len.into())?;
            while wdraw_parser.remaining() > 0 {
                // conventional withdrawals are always IPv4
                BasicNlri::parse(&mut wdraw_parser, config, AFI::Ipv4)?;
            }
        }
        let total_path_attributes_len = parser.parse_u16()?;
        if total_path_attributes_len > 0 {
            let mut pas_parser = parser.parse_parser(total_path_attributes_len.into())?;
            PathAttributes::parse(&mut pas_parser, config)?;
        }

        // conventional NLRI, if any
        while parser.remaining() > 0 {
            // conventional announcements are always IPv4
            BasicNlri::parse(parser, config, AFI::Ipv4)?;
        }

        let end = parser.pos();
        if end - pos != hdr.length() as usize {
            return Err(ParseError::form_error(
                "message length and parsed bytes do not match"
            ));
        }
        parser.seek(pos)?;

        Ok(Self::for_slice(
                parser.parse_octets(hdr.length().into())?,
                config
        ))
    }
}

/*
impl<Octets: AsRef<[u8]>> Debug for UpdateMessage<Octets>
where
    //for<'s> Octets: 's,
    //for<'s> &'s Octets: OctetsRef<Range = bool>, //XXX <- HOW can this compile?
    for<'s> &'s Octets: OctetsRef,
    for<'s, 'a> &'s<&'a Octets as OctetsRef>::Range: OctetsRef,
    //for<'a> &'a<<&'a Octets as OctetsRef>::Range as OctetsRef>::Range: OctetsRef, // compiler hint
    for<'s, 'a> &'s<&'a Octets as OctetsRef>::Range: OctetsRef<Range = <&'s Octets as OctetsRef>::Range>,
    //for<'a> <&'a <&'a Octets as OctetsRef>::Range as OctetsRef>::Range = <&'a Octets as OctetsRef>::Range
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult
    {
        let mut r = write!(f, " AS_PATH: {:?}\n \
                    NEXT_HOP: {:?}\n \
                    ORIGIN: {:?}\n \
                    NLRIs: ",
            &self.aspath(),
            &self.next_hop(),
            &self.origin(),
        );
        /*
        let mut first = true;
        for nlri in self.nlris().iter() {
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
        for withdraw in self.withdrawals().iter() {
            if first {
                first = false
            } else {
                let _ = write!(f, ", ");
            }
            r = write!(f, "{}", withdraw)
        }
        */
        r
    }
}
*/

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
    25 => Ipv6ExtendedCommunities,
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

// XXX do we want an intermediary struct PathAttributes with an fn iter() to
// return a PathAttributesIter ?
pub struct PathAttributes<Octets> {
    octets: Octets,
    session_config: SessionConfig,
}

impl<Octets: AsRef<[u8]>> PathAttributes<Octets> {
    pub fn iter<'s>(&'s self) -> PathAttributesIter<&Octets>
    where
        &'s Octets: OctetsRef
    {
        PathAttributesIter::new(&self.octets, self.session_config)
    }
}

/// Iterator over all [`PathAttribute`]s in a BGP UPDATE message.
pub struct PathAttributesIter<Ref> {
    parser: Parser<Ref>,
    session_config: SessionConfig,
}

impl<Ref: OctetsRef> PathAttributesIter<Ref>{
    fn new(path_attributes: Ref, config: SessionConfig) -> Self {
        PathAttributesIter { 
            parser: Parser::from_ref(path_attributes),
            session_config: config,
        }
    }
}

impl<Octets: AsRef<[u8]>> PathAttributes<Octets> {
    fn check<R>(parser: &mut Parser<R>, config: SessionConfig)
        -> Result<(), ParseError>
    where
        R: OctetsRef<Range = Octets>,
    {
        while parser.remaining() > 0 {
            PathAttribute::<Octets>::check(parser, config)?;
        }

        Ok(())
    }

    fn parse<R>(parser: &mut Parser<R>, config: SessionConfig)
        -> Result<Self, ParseError>
    where
        R: OctetsRef<Range = Octets>,
    {
        let pos = parser.pos();
        while parser.remaining() > 0 {
            let _pa = PathAttribute::parse(parser, config)?;
        }
        let end = parser.pos();
        parser.seek(pos)?;

        Ok(PathAttributes {
            octets: parser.parse_octets(end - pos).unwrap(),
            session_config: config
        })
    }
}

/// BGP Path Attribute, carried in BGP UPDATE messages.
#[derive(Debug, Eq, PartialEq)]
pub struct PathAttribute<Octets> {
    octets: Octets,
}

impl<Octets: AsRef<[u8]>> PathAttribute<Octets> {
    /// Returns the flags as a raw byte.
    pub fn flags(&self) -> u8 {
        self.octets.as_ref()[0]
    }

    /// Returns true if the optional flag is set.
    pub fn is_optional(&self) -> bool {
        self.flags() & 0x80 == 0x80
    }

    /// Returns true if the transitive bit is set.
    pub fn is_transitive(&self) -> bool {
        self.flags() & 0x40 == 0x40
    }

    /// Returns true if the partial flag is set.
    pub fn is_partial(&self) -> bool {
        self.flags() & 0x20 == 0x20
    }

    /// Returns true if the extended length flag is set.
    pub fn is_extended_length(&self) -> bool {
        self.flags() & 0x10 == 0x10
    }

    /// Returns the type of this path attribute.
    pub fn type_code(&self) -> PathAttributeType {
        self.octets.as_ref()[1].into()
    }

    /// Returns the length of the value of this path attribute.
    pub fn length(&self) -> u16 {
        match self.is_extended_length() {
            true => u16::from_be_bytes(
                [self.octets.as_ref()[2], self.octets.as_ref()[3]]),
            false => self.octets.as_ref()[2] as u16,
        }
    }

    fn hdr_len(&self) -> usize {
        match self.is_extended_length() {
            true => 2+2,  // 2 byte flags+codes, 2 byte value length
            false => 2+1, // 2 byte flags+codes, 1 byte value length
        }
    }
}

impl<Octets: AsRef<[u8]>> PathAttribute<Octets> {
    /// Returns the raw value of this path attribute.
    pub fn value<'s>(&'s self) -> <&'s Octets as OctetsRef>::Range
    where
        &'s Octets: OctetsRef
    {
        let start = self.hdr_len();
        let end = start + self.length() as usize;
        self.octets.range(start,end)
    }
}

impl<Octets: AsRef<[u8]>> PathAttribute<Octets> {
    fn check<R>(parser: &mut Parser<R>, config: SessionConfig)
        ->  Result<(), ParseError>
    where
        R: OctetsRef
    {
        let flags = parser.parse_u8()?;
        let typecode = parser.parse_u8()?;
        let len = match flags & 0x10 == 0x10 {
            true => {
                parser.parse_u16()? as usize
            },
            false => parser.parse_u8()? as usize, 
        };

        // now, check the specific type of path attribute
        match typecode.into() {
            PathAttributeType::Origin => {
                if len != 1 {
                    return Err(
                        ParseError::form_error("expected len 1 for Origin pa")
                    );
                }
                parser.advance(1)?;
            },
            PathAttributeType::AsPath => {
                let mut pp = parser.parse_parser(len)?;
                while pp.remaining() > 0 {
                    // segment type
                    pp.advance(1)?;
                    // segment length describes the number of ASNs
                    let slen = pp.parse_u8()?;
                    for _ in 0..slen {
                        match config.four_octet_asn {
                            FourOctetAsn::Enabled => { pp.advance(4)?; }
                            FourOctetAsn::Disabled => { pp.advance(2)?; }
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
                parser.advance(4)?;
            }
            PathAttributeType::MultiExitDisc => {
                if len != 4 {
                    return Err(
                        ParseError::form_error("expected len 4 for MULTI_EXIT_DISC pa")
                    );
                }
                parser.advance(4)?;
            }
            PathAttributeType::LocalPref => {
                if len != 4 {
                    return Err(
                        ParseError::form_error("expected len 4 for LOCAL_PREF pa")
                    );
                }
                parser.advance(4)?;
            },
            PathAttributeType::AtomicAggregate => {
                if len != 0 {
                    return Err(
                        ParseError::form_error("expected len 0 for ATOMIC_AGGREGATE pa")
                    );
                }
            },
            PathAttributeType::Aggregator => {
                let mut pp = parser.parse_parser(len)?;
                Aggregator::check(&mut pp, config)?;
            },
            PathAttributeType::Communities => {
                let mut pp = parser.parse_parser(len)?;
                while pp.remaining() > 0 {
                    StandardCommunity::check(&mut pp)?;
                }
            },
            PathAttributeType::OriginatorId => {
                parser.advance(4)?;
            },
            PathAttributeType::ClusterList => {
                let mut pp = parser.parse_parser(len)?;
                while pp.remaining() > 0 {
                    pp.advance(4)?;
                }
            },
            PathAttributeType::MpReachNlri => {
                let mut pp = parser.parse_parser(len)?;
                Nlris::<Octets>::check(&mut pp, config)?;
            },
            PathAttributeType::MpUnreachNlri => {
                let mut pp = parser.parse_parser(len)?;
                Withdrawals::<Octets>::check(&mut pp, config)?;
            },
            PathAttributeType::ExtendedCommunities => {
                let mut pp = parser.parse_parser(len)?;
                while pp.remaining() > 0 {
                    ExtendedCommunity::check(&mut pp)?;
                }
            },
            PathAttributeType::As4Path => {
                let mut pp = parser.parse_parser(len)?;
                while pp.remaining() > 0 {
                    let _stype = pp.parse_u8()?;
                    // segment length describes the number of ASNs
                    let slen = pp.parse_u8()?;
                    for _ in 0..slen {
                         pp.advance(4)?;
                    }
                }
            }
            PathAttributeType::As4Aggregator => {
                // Asn + Ipv4Addr
                parser.advance(4 + 4)?;
            }
            PathAttributeType::Connector => {
                // Should be an Ipv4Addr according to
                // https://www.rfc-editor.org/rfc/rfc6037.html#section-5.2.1
                if len != 4 {
                    warn!(
                        "Connector PA, expected len == 4 but found {}",
                        len
                    );
                }
                parser.advance(len)?;
            },
            PathAttributeType::AsPathLimit => {
                // u8 limit + Ipv4Addr
                parser.advance(5)?;
            },
            PathAttributeType::PmsiTunnel => {
                let _flags = parser.parse_u8()?;
                let _tunnel_type = parser.parse_u8()?;
                let _mpls_label_1 = parser.parse_u8()?;
                let _mpls_label_2 = parser.parse_u16()?;
                let tunnel_id_len = len - 5;
                parser.advance(tunnel_id_len)?;
            },
            PathAttributeType::Ipv6ExtendedCommunities => {
                let mut pp = parser.parse_parser(len)?;
                while pp.remaining() > 0 {
                    Ipv6ExtendedCommunity::check(&mut pp)?;
                }
            },
            PathAttributeType::LargeCommunities => {
                let mut pp = parser.parse_parser(len)?;
                while pp.remaining() > 0 {
                    LargeCommunity::check(&mut pp)?;
                }
            },
            PathAttributeType::AttrSet => {
                parser.advance(4)?;
                let mut pp = parser.parse_parser(len - 4)?;
                PathAttributes::check(&mut pp, config)?;
            },
            PathAttributeType::Reserved => {
                warn!("Path Attribute type 0 'Reserved' observed");
            },
            PathAttributeType::RsrvdDevelopment => {
                // This could be anything.
                // As long as we do the resetting seek() + parse_octets()
                // after the match, we do not need to do anything here.
                parser.advance(len)?;
            },
            PathAttributeType::Unimplemented(_) => {
                warn!("Unimplemented PA: {}", typecode);
                parser.advance(len)?;
            },
            //_ => {
            //    panic!("unimplemented: {}", <PathAttributeType as From::<u8>>::from(typecode));
            //},
        }
        
        Ok(())
    }

    fn parse<'s, R>(parser: &mut Parser<R>, config: SessionConfig)
        ->  Result<PathAttribute<Octets>, ParseError>
    where
        R: OctetsRef<Range = Octets>,
        Octets: 's, 
    {
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
                let mut p = Parser::from_ref(pa);
                while p.remaining() > 0 {
                    let _stype = p.parse_u8()?;
                    // segment length describes the number of ASNs
                    let slen = p.parse_u8()?;
                    for _ in 0..slen {
                        match config.four_octet_asn {
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
                let _next_hop = parse_ipv4addr(parser)?;
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
                let mut p = Parser::from_ref(pa);
                Aggregator::parse(&mut p, config)?;
            },
            PathAttributeType::Communities => {
                let pos = parser.pos();
                while parser.pos() < pos + len {
                    StandardCommunity::parse(parser)?;
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
                let mut pa_parser = parser.parse_parser(len)?;
                Nlris::parse(&mut pa_parser, config)?;
            },
            PathAttributeType::MpUnreachNlri => {
                let mut pa_parser = parser.parse_parser(len)?;
                Withdrawals::parse(&mut pa_parser, config)?;
            },
            PathAttributeType::ExtendedCommunities => {
                let pos = parser.pos();
                while parser.pos() < pos + len {
                    ExtendedCommunity::parse(parser)?;
                }
            },
            PathAttributeType::As4Path => {
                let mut pa_parser = parser.parse_parser(len)?;
                while pa_parser.remaining() > 0 {
                    let _stype = pa_parser.parse_u8()?;
                    // segment length describes the number of ASNs
                    let slen = pa_parser.parse_u8()?;
                    for _ in 0..slen {
                         pa_parser.parse_u32()?;
                    }
                }
            }
            PathAttributeType::As4Aggregator => {
                let _asn = parser.parse_u32()?;
                let _addr = parse_ipv4addr(parser)?;
            }
            PathAttributeType::Connector => {
                //let _addr = parse_ipv4addr(parser)?;
                // based on
                // https://www.rfc-editor.org/rfc/rfc6037.html#section-5.2.1
                // we expect an IPv4 address. We have seen contents of length
                // 14 instead of 4 though, so let's be lenient for now.
                parser.advance(len)?;
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
            PathAttributeType::Ipv6ExtendedCommunities => {
                let mut pp = parser.parse_parser(len)?;
                while pp.remaining() > 0 {
                    Ipv6ExtendedCommunity::parse(&mut pp)?;
                }
            },
            PathAttributeType::LargeCommunities => {
                let pos = parser.pos();
                while parser.pos() < pos + len {
                    LargeCommunity::parse(parser)?;
                }
            },
            PathAttributeType::AttrSet => {
                let _origin_as = parser.parse_u32()?;
                let mut set_parser = parser.parse_parser(len - 4)?;
                //while set_parser.remaining() > 0 {
                //    PathAttribute::parse(&mut set_parser)?;
                //}
                PathAttributes::parse(&mut set_parser, config)?;
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
                parser.advance(len)?;
            },
            //_ => {
            //    panic!("unimplemented: {}", <PathAttributeType as From::<u8>>::from(typecode));
            //},
        }
        
        parser.seek(pos)?;
        let res = parser.parse_octets(headerlen+len)?;

        Ok(PathAttribute { octets: res })
    }
}


impl<Ref: OctetsRef> Iterator for PathAttributesIter<Ref>
where
    for <'a> &'a<Ref as OctetsRef>::Range: OctetsRef,
    for<'a> &'a<Ref as OctetsRef>::Range: OctetsRef<Range = <Ref as OctetsRef>::Range>
{
    type Item = PathAttribute<Ref::Range>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None
        }
        Some(
            PathAttribute::parse(&mut self.parser, self.session_config)
            .expect("parsed before")
        )
    }
}

//--- NextHop in MP_REACH_NLRI -----------------------------------------------

impl NextHop {
    fn check<R: AsRef<[u8]>>(parser: &mut Parser<R>, afi: AFI, safi: SAFI)
        -> Result<(), ParseError>
    {
        let len = parser.parse_u8()?;
        match (len, afi, safi) {
            (16, AFI::Ipv6, SAFI::Unicast | SAFI::MplsUnicast) =>
                //NextHop::Ipv6
                parser.advance(16)?,
            (32, AFI::Ipv6, SAFI::Unicast) =>
                //NextHop::Ipv6LL
                parser.advance(16 + 16)?,
            (24, AFI::Ipv6, SAFI::MplsVpnUnicast) =>
                //NextHop::Ipv6MplsVpnUnicast
                parser.advance(8 + 16)?,
            (4, AFI::Ipv4, SAFI::Unicast | SAFI::MplsUnicast ) =>
                //NextHop::Ipv4
                parser.advance(4)?,
            (12, AFI::Ipv4, SAFI::MplsVpnUnicast) =>
                //NextHop::Ipv4MplsVpnUnicast
                parser.advance(8 + 4)?,
            // RouteTarget is always AFI/SAFI 1/132, so, IPv4,
            // but the Next Hop can be IPv6.
            (4, AFI::Ipv4, SAFI::RouteTarget) =>
                //NextHop::Ipv4
                parser.advance(4)?,
            (16, AFI::Ipv4, SAFI::RouteTarget) =>
                //NextHop::Ipv6
                parser.advance(16)?,
            (0, AFI::Ipv4, SAFI::FlowSpec) =>
                //NextHop::Empty
                { },
            _ => {
                parser.advance(len.into())?;
                warn!("Unimplemented NextHop AFI/SAFI {}/{}", afi, safi);
            }
        }

        Ok(())
    }

    fn parse<R: AsRef<[u8]>>(parser: &mut Parser<R>, afi: AFI, safi: SAFI)
        -> Result<Self, ParseError>
    {
        let len = parser.parse_u8()?;
        let res = match (len, afi, safi) {
            (16, AFI::Ipv6, SAFI::Unicast | SAFI::MplsUnicast) =>
                NextHop::Ipv6(parse_ipv6addr(parser)?),
            (32, AFI::Ipv6, SAFI::Unicast) =>
                NextHop::Ipv6LL(
                    parse_ipv6addr(parser)?,
                    parse_ipv6addr(parser)?
                ),
            (24, AFI::Ipv6, SAFI::MplsVpnUnicast) =>
                NextHop::Ipv6MplsVpnUnicast(
                    RouteDistinguisher::parse(parser)?,
                    parse_ipv6addr(parser)?
                ),
            (4, AFI::Ipv4, SAFI::Unicast | SAFI::MplsUnicast ) =>
                NextHop::Ipv4(parse_ipv4addr(parser)?),
            (12, AFI::Ipv4, SAFI::MplsVpnUnicast) =>
                NextHop::Ipv4MplsVpnUnicast(
                    RouteDistinguisher::parse(parser)?,
                    parse_ipv4addr(parser)?
                ),
            // RouteTarget is always AFI/SAFI 1/132, so, IPv4,
            // but the Next Hop can be IPv6.
            (4, AFI::Ipv4, SAFI::RouteTarget) =>
                NextHop::Ipv4(parse_ipv4addr(parser)?),
            (16, AFI::Ipv4, SAFI::RouteTarget) =>
                NextHop::Ipv6(parse_ipv6addr(parser)?),
            (0, AFI::Ipv4, SAFI::FlowSpec) =>
                NextHop::Empty,
            _ => {
                parser.advance(len.into())?;
                NextHop::Unimplemented( afi, safi)
            }
        };
        Ok(res)
    }

    fn skip<R: AsRef<[u8]>>(parser: &mut Parser<R>)
        -> Result<(), ParseError>
    {
        let len = parser.parse_u8()?;
        parser.advance(len.into())?;
        Ok(())
    }
}


//--- NLRI -------------------------------------------------------------------

/// Path Identifier for BGP Multiple Paths (RFC7911).
///
/// Optionally used in [`BasicNlri`].
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct PathId(u32);

impl PathId {
    fn check<R: AsRef<[u8]>>(parser: &mut Parser<R>)
        -> Result<(), ParseError> 
    {
        parser.advance(4)?;
        Ok(())
    }

    fn parse<R: AsRef<[u8]>>(parser: &mut Parser<R>)
        -> Result<Self, ParseError> 
    {
        Ok(PathId(parser.parse_u32()?))
    }
}

/// MPLS labels, part of [`MplsNlri`] and [`MplsVpnNlri`].
#[derive(Copy, Clone, Eq, Debug, PartialEq)]
pub struct Labels<Octets> {
    octets: Octets
}

impl<Octets: AsRef<[u8]>> Labels<Octets> {
    fn len(&self) -> usize {
        self.octets.as_ref().len()
    }
}

impl<Octets: AsRef<[u8]>> Labels<Octets> {
    // XXX check all this Label stuff again
    fn _check<R>(parser: &mut Parser<R>) -> Result<(), ParseError>
        where R: OctetsRef<Range = Octets>
    {
        let mut stop = false;
        let mut buf = [0u8; 3];

        while !stop {
            //20bits label + 3bits rsvd + S bit
            parser.parse_buf(&mut buf)?;

            if buf[2] & 0x01 == 0x01  || // actual label with stop bit
                buf == [0x80, 0x00, 0x00] || // Compatibility value 
                buf == [0x00, 0x00, 0x00] // or RFC 8277 2.4
            {
                stop = true;
            }
        }

        Ok(())
    }
    // There are two cases for Labels:
    // - in an announcement, it describes one or more MPLS labels
    // - in a withdrawal, it's a compatibility value without meaning
    // XXX consider splitting up the parsing for this for announcements vs
    // withdrawals? Perhaps via another fields in the (currently so-called)
    // SessionConfig...
    fn parse<Ref>(parser: &mut Parser<Ref>) -> Result<Self, ParseError>
        where Ref: OctetsRef<Range = Octets>
    {
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
            Labels { octets: res }
        )
    }
}

/// Route Distinguisher (RD) as defined in RFC4364.
///
/// Used in [`MplsVpnNlri`], [`VplsNlri`] and [`NextHop`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct RouteDistinguisher {
    bytes: [u8; 8]
}

impl RouteDistinguisher {
    fn check<R: AsRef<[u8]>>(parser: &mut Parser<R>)
        -> Result<(), ParseError>
    {
        parser.advance(8)?;
        Ok(())
    }
    fn parse<R: AsRef<[u8]>>(parser: &mut Parser<R>)
        -> Result<Self, ParseError>
    {
        let mut b = [0u8; 8];
        b[..8].copy_from_slice(parser.peek(8)?);
        parser.advance(8)?;
        Ok(
            RouteDistinguisher{ bytes: b }
        )
    }
}

impl RouteDistinguisher {
    /// Create a new RouteDistinguisher from a slice.
    pub fn new(bytes: &[u8]) -> Self {
        RouteDistinguisher { bytes: bytes.try_into().expect("parsed before") }
    }

    /// Returns the type this RouteDistinguisher.
    pub fn typ(&self) -> RouteDistinguisherType {
        match self.bytes[0..2] {
            [0x00, 0x00] => RouteDistinguisherType::Type0,
            [0x00, 0x01] => RouteDistinguisherType::Type1,
            [0x00, 0x02] => RouteDistinguisherType::Type2,
            _ => RouteDistinguisherType::UnknownType,
        }
    }

    /// Returns the raw value of this RouteDistinguisher.
    pub fn value(&self) -> [u8; 6] {
        self.bytes[2..8].try_into().expect("parsed before")
    }
}

/// Route Distinguisher types as defined in RFC4364.
#[derive(Eq, PartialEq, Debug)]
pub enum RouteDistinguisherType {
    Type0,
    Type1,
    Type2,
    UnknownType,
}

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
pub struct MplsNlri<Octets> {
    basic: BasicNlri,
    labels: Labels<Octets>,
}

/// NLRI comprised of a [`BasicNlri`], MPLS `Labels` and a VPN
/// `RouteDistinguisher`.
#[derive(Debug)]
pub struct MplsVpnNlri<Octets> {
    basic: BasicNlri,
    labels: Labels<Octets>,
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
pub struct FlowSpecNlri<Octets> {
    #[allow(dead_code)]
    raw: Octets,
}

/// NLRI containing a Route Target membership as defined in RFC4684.
///
/// **TODO**: implement accessor methods for the contents of this NLRI.
#[derive(Debug)]
pub struct RouteTargetNlri<Octets> {
    #[allow(dead_code)]
    raw: Octets,
}

/// Conventional and BGP-MP NLRI variants.
#[derive(Debug)]
pub enum Nlri<Octets> {
    Basic(BasicNlri),
    Mpls(MplsNlri<Octets>),
    MplsVpn(MplsVpnNlri<Octets>),
    Vpls(VplsNlri),
    FlowSpec(FlowSpecNlri<Octets>),
    RouteTarget(RouteTargetNlri<Octets>),
}

impl<Octets> Display for Nlri<Octets> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Nlri::Vpls(n) => write!(f, "VPLS-{:?}", n.rd),
            _ => write!(f, "{}", self.prefix().unwrap())
        }
    }
}
impl<Octets> Nlri<Octets> {
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

    /// Returns the [`Prefix`] for this NLRI, if any.
    ///
    /// Since the NLRI in Multiprotocol BGP can contain many different types
    /// of information depending on the AFI/SAFI, there might be no prefix at
    /// all.
    pub fn prefix(&self) -> Option<Prefix> {
        self.basic().map(|b| b.prefix)
    }

    /// Returns the PathId for AddPath enabled prefixes.
    pub fn path_id(&self) -> Option<PathId> {
        if let Some(b) = self.basic() {
            b.path_id
        } else {
            None
        }
    }

    /// Returns the MPLS [`Labels`], if any.
    ///
    /// Applicable to MPLS and MPLS-VPN NLRI.
    pub fn labels(&self) -> Option<&Labels<Octets>> {
        match &self {
            Nlri::Mpls(n) => Some(&n.labels),
            Nlri::MplsVpn(n) => Some(&n.labels),
            _ => None
        }
    }

    /// Returns the RouteDistinguisher, if any.
    ///
    /// Applicable to MPLS VPN and VPLS NLRI.
    pub fn rd(&self) -> Option<RouteDistinguisher> {
        match self {
            Nlri::MplsVpn(n) => Some(n.rd),
            Nlri::Vpls(n) => Some(n.rd),
            _ => None
        }
    }

    // VPLS specific methods

    /// Returns the VPLS VE ID.
    pub fn ve_id(&self) -> Option<u16> {
        match self {
            Nlri::Vpls(n) => Some(n.ve_id),
            _ => None
        }

    }

    /// Returns the VPLS VE Block Offset.
    pub fn ve_block_offset(&self) -> Option<u16> {
        match self {
            Nlri::Vpls(n) => Some(n.ve_block_offset),
            _ => None
        }
    }

    /// Returns the VPLS VE Block Size.
    pub fn ve_block_size(&self) -> Option<u16> {
        match self {
            Nlri::Vpls(n) => Some(n.ve_block_size),
            _ => None
        }
    }

    /// Returns the VPLS Label Base.
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

fn check_prefix<R: AsRef<[u8]>>(
    parser: &mut Parser<R>,
    prefix_bits: u8,
    afi: AFI
) -> Result<(), ParseError> {
    let prefix_bytes = prefix_bits_to_bytes(prefix_bits);
    match (afi, prefix_bytes) {
        (AFI::Ipv4, 0) => { },
        (AFI::Ipv4, _b @ 5..) => { 
            return Err(
                ParseError::form_error("illegal byte size for IPv4 NLRI")
            )
        },
        (AFI::Ipv4, _) => { parser.advance(prefix_bytes)?; }
        (AFI::Ipv6, 0) => { },
        (AFI::Ipv6, _b @ 17..) => { 
            return Err(
                ParseError::form_error("illegal byte size for IPv6 NLRI")
            )
        },
        (AFI::Ipv6, _) => { parser.advance(prefix_bytes)?; },
        (_, _) => {
            panic!("unimplemented")
        }
    };

    Ok(())
}

fn parse_prefix<R>(parser: &mut Parser<R>, prefix_bits: u8, afi: AFI)
    -> Result<Prefix, ParseError>
where
    R: AsRef<[u8]>
{
    let prefix_bytes = prefix_bits_to_bytes(prefix_bits);
    let prefix = match (afi, prefix_bytes) {
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

impl BasicNlri {
    fn check<R: AsRef<[u8]>>(
        parser: &mut Parser<R>,
        config: SessionConfig,
        afi: AFI
    ) -> Result<(), ParseError> {
        if config.add_path == AddPath::Enabled {
            PathId::check(parser)?
        }

        let prefix_bits = parser.parse_u8()?;
        check_prefix(parser, prefix_bits, afi)?;
        
        Ok(())
    }

    fn parse<R: AsRef<[u8]>>(
        parser: &mut Parser<R>,
        config: SessionConfig,
        afi: AFI
    ) -> Result<Self, ParseError> {
        let path_id = match config.add_path {
            AddPath::Enabled => Some(PathId::parse(parser)?),
            _ => None
        };
        let prefix_bits = parser.parse_u8()?;
        let prefix = parse_prefix(parser, prefix_bits, afi)?;
        
        Ok(
            BasicNlri {
                prefix,
                path_id,
            }
        )
    }
}

impl<Octets: AsRef<[u8]>> MplsVpnNlri<Octets> {
    fn check<R>(parser: &mut Parser<R>, config: SessionConfig, afi: AFI)
        -> Result<(), ParseError>
    where
        R: OctetsRef
    {
        if config.add_path == AddPath::Enabled {
            parser.advance(4)?;
        }

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

        RouteDistinguisher::check(parser)?;
        prefix_bits -= 8 * 8_u8;

        check_prefix(parser, prefix_bits, afi)?;

        Ok(())
    }

    fn parse<Ref>(parser: &mut Parser<Ref>, config: SessionConfig, afi: AFI)
        -> Result<Self, ParseError>
    where
        Ref: OctetsRef<Range = Octets>
    {
        let path_id = match config.add_path {
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

        let prefix = parse_prefix(parser, prefix_bits, afi)?;

        let basic = BasicNlri{ prefix, path_id };
        Ok(MplsVpnNlri{ basic, labels, rd })
    }
}

impl<Octets: AsRef<[u8]>> MplsNlri<Octets> {
    fn check<R>(parser: &mut Parser<R>, config: SessionConfig, afi: AFI)
        -> Result<(), ParseError>
    where
        R: OctetsRef
    {
        if config.add_path == AddPath::Enabled {
            parser.advance(4)?;
        }

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
        check_prefix(parser, prefix_bits, afi)?;
        Ok(())
    }
    fn parse<Ref>(parser: &mut Parser<Ref>, config: SessionConfig, afi: AFI) -> Result<Self, ParseError>
    where
        Ref: OctetsRef<Range = Octets>
    {
        let path_id = match config.add_path {
            AddPath::Enabled => Some(PathId::parse(parser)?),
            _ => None
        };

        let mut prefix_bits = parser.parse_u8()?;
        let labels = Labels::<Octets>::parse(parser)?;

        // Check whether we can safely subtract the labels length from the
        // prefix size. If there is an unexpected path id, we might silently
        // subtract too much, because there is no 'subtract with overflow'
        // warning when built in release mode.
        if 8 * labels.len() as u8 > prefix_bits {
            return Err(ParseError::ShortInput);
        }

        prefix_bits -= 8 * labels.len() as u8;

        let prefix = parse_prefix(parser, prefix_bits, afi)?;
        let basic = BasicNlri { prefix, path_id };
        Ok(
            MplsNlri {
                basic,
                labels, 
            }
        )
    }
}

impl VplsNlri {
    fn check<R>(parser: &mut Parser<R>) -> Result<(), ParseError>
    where
        R: OctetsRef
    {
        parser.advance(2)?; // length, u16
        RouteDistinguisher::check(parser)?; 
        // ve id/block offset/block size, label base
        parser.advance(2 + 2 + 2 + 1 + 2)?;
        
        Ok(())
    }

    fn parse<Ref>(parser: &mut Parser<Ref>) -> Result<Self, ParseError>
    where
        Ref: OctetsRef
    {
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
}

impl<Octets: AsRef<[u8]>> FlowSpecNlri<Octets> {
    fn check<R>(parser: &mut Parser<R>) -> Result<(), ParseError>
    where
        R: OctetsRef
    {
        let len1 = parser.parse_u8()?;
        let len: u16 = if len1 >= 0xf0 {
            let len2 = parser.parse_u8()? as u16;
            (((len1 as u16) << 8) | len2) & 0x0fff
        } else {
            len1 as u16
        };
        let pp = parser.parse_parser(len.into())?;
        while pp.remaining() > 0 {
            // TODO implement Component::check()
            Component::parse(parser)?;
        }

        Ok(())
    }

    fn parse<Ref>(parser: &mut Parser<Ref>) -> Result<Self, ParseError>
    where
        Ref: OctetsRef<Range = Octets>
    {
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
}

impl<Octets: AsRef<[u8]>> RouteTargetNlri<Octets> {
    fn check<R>(parser: &mut Parser<R>) -> Result<(), ParseError>
    where
        R: OctetsRef
    {
        let prefix_bits = parser.parse_u8()?;
        let prefix_bytes = prefix_bits_to_bytes(prefix_bits);
        parser.advance(prefix_bytes)?;

        Ok(())
    }

    fn parse<Ref>(parser: &mut Parser<Ref>) -> Result<Self, ParseError>
    where
        Ref: OctetsRef<Range = Octets>
    {
        let prefix_bits = parser.parse_u8()?;
        let prefix_bytes = prefix_bits_to_bytes(prefix_bits);
        let raw = parser.parse_octets(prefix_bytes)?;

        Ok(
            RouteTargetNlri {
                raw
            }
        )
    }
}

/// Represents the announced NLRI in a BGP UPDATE message.
pub struct Nlris<Octets> {
    octets: Octets,
    session_config: SessionConfig,
    afi: AFI,
    safi: SAFI,
}

impl<Octets: AsRef<[u8]>> Nlris<Octets> {
    pub fn iter<'s>(&'s self) -> NlriIterMp<&Octets>
    where
        &'s Octets: OctetsRef
    {
        NlriIterMp::new(
            &self.octets,
            self.session_config,
            self.afi,
            self.safi,
        )
    }

    /// Returns the AFI for these NLRI.
    pub fn afi(&self) -> AFI {
        self.afi
    }

    /// Returns the SAFI for these NLRI.
    pub fn safi(&self) -> SAFI {
        self.safi
    }
}

/// Iterator over the reachable NLRIs.
///
/// Returns items of the enum [`Nlri`], thus both conventional and
/// BGP MultiProtocol (RFC4760) NLRIs.
pub struct NlriIterMp<Ref> {
    parser: Parser<Ref>,
    session_config: SessionConfig,
    afi: AFI,
    safi: SAFI,
}

impl<Ref: OctetsRef> NlriIterMp<Ref> {
    fn new(octets: Ref, config: SessionConfig, afi: AFI, safi: SAFI) -> Self {
        let parser = Parser::from_ref(octets);
        Self { parser, session_config: config, afi, safi }
    }

    // XXX obsolete now?
    //fn new_conventional(octets: Ref, config: SessionConfig) -> Self {
    //    let parser = Parser::from_ref(octets);
    //    Self {
    //        parser,
    //        session_config: config,
    //        afi: AFI::Ipv4,
    //        safi: SAFI::Unicast,
    //    }
    //}

    fn get_nlri(&mut self) -> Nlri<Ref::Range> {
        match (self.afi, self.safi) {
            (_, SAFI::MplsVpnUnicast) => {
                Nlri::MplsVpn(MplsVpnNlri::parse(&mut self.parser, self.session_config, self.afi).expect("parsed before"))
            },
            (_, SAFI::MplsUnicast) => {
                Nlri::Mpls(MplsNlri::parse(&mut self.parser, self.session_config, self.afi).expect("parsed before"))
            },
            (_, SAFI::Unicast) => {
                Nlri::Basic(BasicNlri::parse(&mut self.parser, self.session_config, self.afi).expect("parsed before"))
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

impl<Octets: AsRef<[u8]>> Nlris<Octets> {
    fn parse_conventional<R>(parser: &mut Parser<R>, config: SessionConfig) -> Result<Self, ParseError>
    where
        R: OctetsRef<Range = Octets>
    {
        let pos = parser.pos();
        while parser.remaining() > 0 {
            BasicNlri::parse(parser, config, AFI::Ipv4)?;
        }
        let len = parser.pos() - pos;
        parser.seek(pos)?;
        Ok(
            Nlris {
                octets: parser.parse_octets(len)?,
                session_config: config,
                afi: AFI::Ipv4,
                safi: SAFI::Unicast,
            }
        )
    }

    fn check<R>(parser: &mut Parser<R>, config: SessionConfig) -> Result<(), ParseError>
        where
            R: OctetsRef
    {
        let afi: AFI = parser.parse_u16()?.into();
        let safi: SAFI = parser.parse_u8()?.into();

        NextHop::check(parser, afi, safi)?;
        parser.advance(1)?; // 1 reserved byte

        while parser.remaining() > 0 {
            match (afi, safi) {
                (_, SAFI::MplsVpnUnicast) => { MplsVpnNlri::<Octets>::check(parser, config, afi)?;},
                (_, SAFI::MplsUnicast) => { MplsNlri::<Octets>::check(parser, config, afi)?;},
                (_, SAFI::Unicast) => { BasicNlri::check(parser, config, afi)?; }
                (AFI::L2Vpn, SAFI::Vpls) => { VplsNlri::check(parser)?; }
                (AFI::Ipv4, SAFI::FlowSpec) => {
                    FlowSpecNlri::<Octets>::check(parser)?;
                },
                (AFI::Ipv4, SAFI::RouteTarget) => {
                    RouteTargetNlri::<Octets>::check(parser)?;
                },
                (_, _) => {
                    error!("unknown AFI/SAFI {}/{}", afi, safi);
                    return Err(
                        ParseError::form_error("unimplemented AFI/SAFI")
                    )
                }
            }
        }

        Ok(())
    }
    fn parse<R>(parser: &mut Parser<R>, config: SessionConfig) -> Result<Self, ParseError>
    where
        R: OctetsRef<Range = Octets>
    {
        // NLRIs from MP_REACH_NLRI.
        // Length is given in the Path Attribute length field.
        // AFI, SAFI, Nexthop are also in this Path Attribute.

        let afi: AFI = parser.parse_u16()?.into();
        let safi: SAFI = parser.parse_u8()?.into();

        NextHop::skip(parser)?;
        parser.advance(1)?; // 1 reserved byte

        let pos = parser.pos();

        while parser.remaining() > 0 {
            match (afi, safi) {
                (_, SAFI::MplsVpnUnicast) => { MplsVpnNlri::parse(parser, config, afi)?;},
                (_, SAFI::MplsUnicast) => { MplsNlri::parse(parser, config, afi)?;},
                (_, SAFI::Unicast) => { BasicNlri::parse(parser, config, afi)?; }
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

        let len = parser.pos() - pos;
        parser.seek(pos)?;
        Ok(
            Nlris {
                octets: parser.parse_octets(len)?,
                session_config: config,
                afi,
                safi,
            }

        )
    }
}


impl<Ref: OctetsRef> Iterator for NlriIterMp<Ref> {
    type Item = Nlri<Ref::Range>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None;
        }
        Some(self.get_nlri())
    }
}

pub struct Withdrawals<Octets> {
    octets: Octets,
    session_config: SessionConfig,
    afi: AFI,
    safi: SAFI,
}

impl<Octets: AsRef<[u8]>> Withdrawals<Octets> {
    pub fn iter<'s>(&'s self) -> WithdrawalsIterMp<&Octets>
        where &'s Octets: OctetsRef
    {
        WithdrawalsIterMp::new(&self.octets, self.session_config, self.afi, self.safi)
    }
}

/// Iterator over the withdrawn NLRIs.
///
/// Returns items of the enum [`Nlri`], thus both conventional and
/// BGP MultiProtocol (RFC4760) withdrawn NLRIs.
pub struct WithdrawalsIterMp<Ref> {
    parser: Parser<Ref>,
    session_config: SessionConfig,
    afi: AFI,
    safi: SAFI,
}

impl<Ref: OctetsRef> WithdrawalsIterMp<Ref> {
    pub fn new(octets: Ref, config: SessionConfig, afi: AFI, safi: SAFI) -> Self {
        let parser = Parser::from_ref(octets);
        Self {
            parser,
            session_config: config,
            afi,
            safi,
        }
    }

    fn get_nlri(&mut self) -> Nlri<Ref::Range> {
        match (self.afi, self.safi) {
            (_, SAFI::MplsVpnUnicast) => {
                Nlri::MplsVpn(MplsVpnNlri::parse(&mut self.parser, self.session_config, self.afi).expect("parsed before"))
            },
            (_, SAFI::MplsUnicast) => {
                Nlri::Mpls(MplsNlri::parse(&mut self.parser, self.session_config, self.afi).expect("parsed before"))
            },
            (_, SAFI::Unicast) => {
                Nlri::Basic(BasicNlri::parse(&mut self.parser, self.session_config, self.afi).expect("parsed before"))
            }
            (_, _) => panic!("should not come here")
        }
    }
}

impl<Octets: AsRef<[u8]>> Withdrawals<Octets> {
    fn parse_conventional<R>(parser: &mut Parser<R>, config: SessionConfig)
        -> Result<Self, ParseError>
    where
        R: OctetsRef<Range = Octets>
    {
        let pos = parser.pos();
        while parser.remaining() > 0 {
            BasicNlri::parse(parser, config, AFI::Ipv4)?;
        }
        let len = parser.pos() - pos;
        parser.seek(pos)?;
        Ok(
            Withdrawals {
                octets: parser.parse_octets(len)?,
                session_config: config,
                afi: AFI::Ipv4,
                safi: SAFI::Unicast,
            }
        )
    }

    fn check<R>(parser: &mut Parser<R>,  config: SessionConfig)
        -> Result<(), ParseError>
    where
        R: OctetsRef
    {
        // NLRIs from MP_UNREACH_NLRI.
        // Length is given in the Path Attribute length field.
        // AFI, SAFI, are also in this Path Attribute.

        let afi: AFI = parser.parse_u16()?.into();
        let safi: SAFI = parser.parse_u8()?.into();

        while parser.remaining() > 0 {
            match (afi, safi) {
                (_, SAFI::MplsVpnUnicast) => { MplsVpnNlri::<Octets>::check(parser, config, afi)?;},
                (_, SAFI::MplsUnicast) => { MplsNlri::<Octets>::check(parser, config, afi)?;},
                (_, SAFI::Unicast) => { BasicNlri::check(parser, config, afi)?; }
                (_, _) => { /* return Err(FormError("unimplemented")) */ }
            }
        }

        Ok(())
    }
    fn parse<R>(parser: &mut Parser<R>,  config: SessionConfig) -> Result<Self, ParseError>
    where
        R: OctetsRef<Range = Octets>
    {
        // NLRIs from MP_UNREACH_NLRI.
        // Length is given in the Path Attribute length field.
        // AFI, SAFI, are also in this Path Attribute.

        let afi: AFI = parser.parse_u16()?.into();
        let safi: SAFI = parser.parse_u8()?.into();
        let pos = parser.pos();

        while parser.remaining() > 0 {
            match (afi, safi) {
                (_, SAFI::MplsVpnUnicast) => { MplsVpnNlri::parse(parser, config, afi)?;},
                (_, SAFI::MplsUnicast) => { MplsNlri::parse(parser, config, afi)?;},
                (_, SAFI::Unicast) => { BasicNlri::parse(parser, config, afi)?; }
                (_, _) => { /* return Err(FormError("unimplemented")) */ }
            }
        }

        let len = parser.pos() - pos;
        parser.seek(pos)?;
        Ok(
            Withdrawals {
                octets: parser.parse_octets(len)?,
                session_config: config,
                afi,
                safi,
            }
        )
    }
}

impl<Ref: OctetsRef> Iterator for WithdrawalsIterMp<Ref> {
    type Item = Nlri<Ref::Range>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None;
        }
        Some(self.get_nlri())
    }
}


//--- Communities ------------------------------------------------------------
//

impl StandardCommunity {
    fn check<R: AsRef<[u8]>>(parser: &mut Parser<R>)
        -> Result<(), ParseError>
    {
        parser.advance(4)?;
        Ok(())
    }

    fn parse<R: AsRef<[u8]>>(parser: &mut Parser<R>)
        -> Result<Self, ParseError>
    {
        let mut buf = [0u8; 4];
        parser.parse_buf(&mut buf)?;
        Ok( Self::from_raw(buf) )
    }
}

impl ExtendedCommunity {
    fn check<R: AsRef<[u8]>>(parser: &mut Parser<R>)
        -> Result<(), ParseError>
    {
        parser.advance(8)?;
        Ok(())
    }

    fn parse<R: AsRef<[u8]>>(parser: &mut Parser<R>)
        -> Result<Self, ParseError>
    {
        let mut buf = [0u8; 8];
        parser.parse_buf(&mut buf)?;
        Ok( Self::from_raw(buf) )
    }
}

impl Ipv6ExtendedCommunity {
    fn check<R: AsRef<[u8]>>(parser: &mut Parser<R>)
        -> Result<(), ParseError>
    {
        parser.advance(20)?;
        Ok(())
    }

    fn parse<R: AsRef<[u8]>>(parser: &mut Parser<R>)
        -> Result<Self, ParseError>
    {
        let mut buf = [0u8; 20];
        parser.parse_buf(&mut buf)?;
        Ok( Self::from_raw(buf) )
    }
}

impl LargeCommunity {
    fn check<R: AsRef<[u8]>>(parser: &mut Parser<R>)
        -> Result<(), ParseError>
    {
        parser.advance(12)?;
        Ok(())
    }
    fn parse<R: AsRef<[u8]>>(parser: &mut Parser<R>)
        -> Result<Self, ParseError>
    {
        let mut buf = [0u8; 12];
        parser.parse_buf(&mut buf)?;
        Ok( Self::from_raw(buf) )
    }
}


/// Iterator for BGP UPDATE Communities.
///
/// Returns values of enum [`Community`], wrapping [`StandardCommunity`],
/// [`ExtendedCommunity`], [`LargeCommunity`] and well-known communities.
pub struct CommunityIter<Octets> {
    slice: Octets,
    pos: usize,
}

impl<Octets: AsRef<[u8]>> CommunityIter<Octets> {
    fn new(slice: Octets) -> Self {
        CommunityIter {
            slice,
            pos: 0
        }
    }
    fn get_community(&mut self) -> Community {
        let mut buf = [0u8; 4];
        buf[..].copy_from_slice(&self.slice.as_ref()[self.pos..self.pos+4]);
        self.pos += 4;
        buf.into()
    }
}

impl<Octets: AsRef<[u8]>> Iterator for CommunityIter<Octets> {
    type Item = Community;
    fn next(&mut self) -> Option<Community> {
        if self.pos == self.slice.as_ref().len() {
            return None
        }
        Some(self.get_community())
    }
}

/// Iterator over [`ExtendedCommunity`]s.
pub struct ExtCommunityIter<Octets> {
    slice: Octets,
    pos: usize,
}

impl<Octets: AsRef<[u8]>> ExtCommunityIter<Octets> {
    fn new(slice: Octets) -> Self {
        ExtCommunityIter {
            slice,
            pos: 0
        }
    }
    fn get_community(&mut self) -> ExtendedCommunity {
        let res = ExtendedCommunity::from_raw(
            self.slice.as_ref()[self.pos..self.pos+8].try_into().expect("parsed before")
            );
        self.pos += 8;
        res
    }
}

impl<Octets: AsRef<[u8]>> Iterator for ExtCommunityIter<Octets> {
    type Item = ExtendedCommunity;
    fn next(&mut self) -> Option<ExtendedCommunity> {
        if self.pos == self.slice.as_ref().len() {
            return None
        }
        Some(self.get_community())
    }
}

/// Iterator over [`LargeCommunity`]s.
pub struct LargeCommunityIter<Octets> {
    slice: Octets,
    pos: usize,
}

impl<Octets: AsRef<[u8]>> LargeCommunityIter<Octets> {
    fn new(slice: Octets) -> Self {
        LargeCommunityIter {
            slice,
            pos: 0
        }
    }
    fn get_community(&mut self) -> LargeCommunity {
        let res = LargeCommunity::from_raw(
            self.slice.as_ref()[self.pos..self.pos+12].try_into().expect("parsed before")
            );
        self.pos += 12;
        res
    }
}

impl<Octets: AsRef<[u8]>> Iterator for LargeCommunityIter<Octets> {
    type Item = LargeCommunity;
    fn next(&mut self) -> Option<LargeCommunity> {
        if self.pos == self.slice.as_ref().len() {
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

impl Aggregator {
    fn check<R: AsRef<[u8]>>(parser: &mut Parser<R>, config: SessionConfig)
        -> Result<(), ParseError>
    {
        let len = parser.remaining(); // XXX is this always correct?
        match (len, config.four_octet_asn) {
            (8, FourOctetAsn::Enabled) => {
                Ok(())
            },
            (6, FourOctetAsn::Disabled) => {
                Ok(())
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

    fn parse<R: AsRef<[u8]>>(parser: &mut Parser<R>, config: SessionConfig)
        -> Result<Self, ParseError>
    {
        let len = parser.remaining(); // XXX is this always correct?
        match (len, config.four_octet_asn) {
            (8, FourOctetAsn::Enabled) => {
                let asn = Asn::from_u32(parser.parse_u32()?);
                let addr = parse_ipv4addr(parser)?;
                Ok(Self::new(asn, addr))
            },
            (6, FourOctetAsn::Disabled) => {
                let asn = Asn::from_u32(parser.parse_u16()?.into());
                let addr = parse_ipv4addr(parser)?;
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
impl<Octets: AsRef<[u8]>> NotificationMessage<Octets> {

    fn for_slice(s: Octets) -> Self {
        Self {
            octets: s
        }
    }
    
    pub fn code(&self) -> u8 {
        self.octets.as_ref()[COFF]
    }

    pub fn subcode(&self) -> u8 {
        self.octets.as_ref()[COFF+1]
    }

    pub fn data(&self) -> Option<&[u8]> {
        if self.as_ref().len() > 21 {
            Some(&self.as_ref()[21..])
        } else {
            None
        }
    }
}
impl<Octets: AsRef<[u8]>> NotificationMessage<Octets> {
    pub fn from_octets(octets: Octets) -> Result<Self, ParseError> {
        Ok(NotificationMessage { octets })
    }

    // TODO impl fn check()

    pub fn parse<Ref>(parser: &mut Parser<Ref>) -> Result<Self, ParseError>
    where
        Ref: OctetsRef<Range = Octets>
    {
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
}

impl<Octets: AsRef<[u8]>> KeepAliveMessage<Octets>
where
    for <'a> &'a Octets: OctetsRef
{
    pub fn from_octets(octets: Octets) -> Result<Self, ParseError> {
        Self::check(&octets)?;
        Ok(KeepAliveMessage { octets })
    }

    pub fn check(octets: &Octets) -> Result<(), ParseError>
    {
        let mut parser = Parser::from_ref(octets);
        Header::<Octets>::check(&mut parser)?;
        if parser.remaining() > 0 {
            return Err(ParseError::form_error("KEEPALIVE of >19 bytes"));
        }
        Ok(())
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
}

impl SessionConfig {
    pub fn new(four_octet_asn: FourOctetAsn, add_path: AddPath) -> Self {
        Self { four_octet_asn, add_path }
    }

    pub fn modern() -> Self {
        Self {
            four_octet_asn: FourOctetAsn::Enabled,
            add_path: AddPath::Disabled,
        }
    }
    pub fn legacy() -> Self {
        Self {
            four_octet_asn: FourOctetAsn::Disabled,
            add_path: AddPath::Disabled,
        }
    }

    pub fn modern_addpath() -> Self {
        Self {
            four_octet_asn: FourOctetAsn::Enabled,
            add_path: AddPath::Enabled,
        }
    }

    pub fn legacy_addpath() -> Self {
        Self {
            four_octet_asn: FourOctetAsn::Disabled,
            add_path: AddPath::Enabled,
        }
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

    // Helper to quickly parse bufs into specific BGP messages.
    #[allow(dead_code)]
    fn parse_msg<T, R: AsRef<[u8]>>(_buf: R) -> T
    where
        //T: TryFrom<Message<R>>,
        //for <'a> &'a R: OctetsRef<Range = R>,
        //<T as TryFrom<Message<R>>>::Error: Debug
    {
        todo!()
        //Message::from_octets(buf).unwrap().try_into().unwrap()
    }

    
    /*
    fn parse_open<Source, Octets>(buf: Source) -> OpenMessage<Octets>
    where
        for <'b> &'b Source: OctetsRef<Range = Octets>,
        //for <'b> &'b <Source as OctetsRef>::Range: OctetsRef
    {
        Message::from_octets(buf).unwrap().try_into().unwrap()
    }
    */
    
    
    //--- BGP OPEN related tests ---------------------------------------------
    mod open {

        use super::*;
        use bytes::Bytes;

        #[test]
        fn no_optional_parameters() {
            // BGP OPEN message, 2-octet ASN 64496, no opt params
            let buf = vec![
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x1d, 0x01, 0x04, 0xfb, 0xf0, 0x00, 0x5a,
                0xc0, 0x00, 0x02, 0x01, 0x00
            ];

            let bb = Bytes::from(buf);

            //let open: OpenMessage<_> = parse_open(&buf);
            //let open: OpenMessage<_> = Message::from_octets(&buf, None).unwrap().try_into().unwrap();
            let open: OpenMessage<_> = Message::from_octets(bb, None).unwrap().try_into().unwrap();

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

            //let open: OpenMessage<_> = parse_msg(&buf);
            let open: OpenMessage<_> = Message::from_octets(buf, None).unwrap().try_into().unwrap();

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

            //let open: OpenMessage<_> = parse_msg(&buf);
            let open: OpenMessage<_> = Message::from_octets(&buf, None).unwrap().try_into().unwrap();

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

            //let open: OpenMessage<_> = parse_msg(&buf);
            let open: OpenMessage<_> = Message::from_octets(&buf, None).unwrap().try_into().unwrap();

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
        use crate::bgp::communities::*;

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
        //   x normal
        //   x extended
        //   x large
        //   x chained iter
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
            assert!(Message::from_octets(&buf, None).is_err());
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

            //let update: UpdateMessage<_> = parse_msg(&buf);
            let update: UpdateMessage<_> = Message::from_octets(
                &buf,
                Some(SessionConfig::modern())
            ).unwrap().try_into().unwrap();

            assert_eq!(update.length(), 55);
            assert_eq!(update.total_path_attribute_len(), 27);

            //let mut pa_iter = update.path_attributes().iter();
            let pas = update.path_attributes();
            let mut pa_iter = pas.iter();

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

            //let mut nlri_iter = update.nlris().iter();
            let nlris = update.nlris();
            let mut nlri_iter = nlris.iter();
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

            //let update: UpdateMessage<_> = parse_msg(&buf);
            let update: UpdateMessage<_> = Message::from_octets(
                &buf,
                Some(SessionConfig::modern())
            ).unwrap().try_into().unwrap();

            assert_eq!(update.total_path_attribute_len(), 27);
            assert_eq!(update.nlris().iter().count(), 2);

            let prefixes = ["10.10.10.9/32", "192.168.97.0/30"].map(|p|
                Prefix::from_str(p).unwrap()
            );

            for (nlri, prefix) in update.nlris().iter().zip(prefixes.iter()) {
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
            //let update: UpdateMessage<_> = parse_msg(&buf);
            let update: UpdateMessage<_> = Message::from_octets(
                &buf,
                Some(SessionConfig::modern())
            ).unwrap().try_into().unwrap();

            assert_eq!(update.withdrawn_routes_len(), 0);
            assert_eq!(update.total_path_attribute_len(), 113);

            let nlris = update.nlris();
            let nlri_iter = nlris.iter();
            assert_eq!(nlri_iter.count(), 5);
            //assert_eq!(update.nlris().iter().count(), 5);

            let prefixes = [
                "fc00::10/128",
                "2001:db8:ffff::/64",
                "2001:db8:ffff:1::/64",
                "2001:db8:ffff:2::/64",
                "2001:db8:ffff:3::/64",
            ].map(|p|
                Prefix::from_str(p).unwrap()
            );

            for (nlri, prefix) in update.nlris().iter().zip(prefixes.iter()) {
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
            //let update: UpdateMessage<_> = parse_msg(&buf);
            let update: UpdateMessage<_> = Message::from_octets(
                &buf,
                Some(SessionConfig::modern())
            ).unwrap().try_into().unwrap();

            assert_eq!(update.withdrawals().iter().count(), 12);

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

            for (nlri, w) in update.withdrawals().iter().zip(ws.iter()) {
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
            //let update: UpdateMessage<_> = parse_msg(&buf);
            let update: UpdateMessage<_> = Message::from_octets(
                &buf,
                Some(SessionConfig::modern())
            ).unwrap().try_into().unwrap();

            assert_eq!(update.withdrawals().iter().count(), 4);
            
            let ws = [
                "2001:db8:ffff::/64",
                "2001:db8:ffff:1::/64",
                "2001:db8:ffff:2::/64",
                "2001:db8:ffff:3::/64",
            ].map(|w|
                Prefix::from_str(w).unwrap()
            );

            for (nlri, w) in update.withdrawals().iter().zip(ws.iter()) {
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
            //let update: UpdateMessage<_> = parse_msg(&buf);
            let update: UpdateMessage<_> = Message::from_octets(
                &buf,
                Some(SessionConfig::modern())
            ).unwrap().try_into().unwrap();
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
            //let update: UpdateMessage<_> = parse_msg(&buf);
            let update: UpdateMessage<_> = Message::from_octets(
                &buf,
                Some(SessionConfig::modern())
            ).unwrap().try_into().unwrap();
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
            
            let sc = SessionConfig::legacy();
            let update: UpdateMessage<_> = Message::from_octets(&buf, Some(sc))
                .unwrap().try_into().unwrap();

            update.path_attributes().iter();//.count();
            if let Some(aspath) = update.path_attributes().iter().find(|pa|
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

            if let Some(as4path) = update.path_attributes().iter().find(|pa|
                pa.type_code() == PathAttributeType::As4Path
            ){
                assert_eq!(as4path.flags(), 0xd0);
                assert_eq!(as4path.length(), 42);
                //TODO check actual aspath
            } else {
                panic!("AS4PATH path attribute not found")
            }

        }

        //--- Communities ----------------------------------------------------
        
        #[test]
        fn pa_communities() {
            // BGP UPDATE with 9 path attributes for 1 NLRI with Path Id,
            // includes both normal communities and extended communities.
            let buf = vec![
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x82, 0x02, 0x00, 0x00, 0x00, 0x62, 0x40,
                0x01, 0x01, 0x00, 0x40, 0x02, 0x16, 0x02, 0x05,
                0x00, 0x00, 0x00, 0x65, 0x00, 0x00, 0x01, 0x2d,
                0x00, 0x00, 0x01, 0x2c, 0x00, 0x00, 0x02, 0x58,
                0x00, 0x00, 0x02, 0xbc, 0x40, 0x03, 0x04, 0x0a,
                0x01, 0x03, 0x01, 0x80, 0x04, 0x04, 0x00, 0x00,
                0x00, 0x00, 0x40, 0x05, 0x04, 0x00, 0x00, 0x00,
                0x64, 0xc0, 0x08, 0x0c, 0x00, 0x2a, 0x02, 0x06,
                0xff, 0xff, 0xff, 0x01, 0xff, 0xff, 0xff, 0x03,
                0xc0, 0x10, 0x10, 0x00, 0x06, 0x00, 0x00, 0x44,
                0x9c, 0x40, 0x00, 0x40, 0x04, 0x00, 0x00, 0x44,
                0x9c, 0x40, 0x00, 0x80, 0x0a, 0x04, 0x0a, 0x00,
                0x00, 0x04, 0x80, 0x09, 0x04, 0x0a, 0x00, 0x00,
                0x03, 0x00, 0x00, 0x00, 0x01, 0x19, 0xc6, 0x33,
                0x64, 0x00
            ];
            let sc = SessionConfig::modern_addpath();
            let upd: UpdateMessage<_> = Message::from_octets(&buf, Some(sc))
                .unwrap().try_into().unwrap();

            assert_eq!(
                upd.nlris().iter().next().unwrap().prefix(),
                Some(Prefix::from_str("198.51.100.0/25").unwrap())
            );

            assert!(upd.communities().is_some());
            assert!(upd.communities().unwrap().eq([
                    Community::Standard(StandardCommunity::new(42.into(), Tag::new(518))),
                    WellKnown::NoExport.into(),
                    WellKnown::NoExportSubconfed.into()
            ]));

            assert!(upd.ext_communities().is_some());
            let mut ext_comms = upd.ext_communities().unwrap();
            let ext_comm1 = ext_comms.next().unwrap();
            assert!(ext_comm1.is_transitive());

            assert_eq!(
                ext_comm1.types(),
                (ExtendedCommunityType::TransitiveTwoOctetSpecific,
                 ExtendedCommunitySubType::OtherSubType(0x06))
            );

            use crate::bgp::communities::Asn16;
            assert_eq!(ext_comm1.as2(), Some(Asn16::from_u16(0)));

            let ext_comm2 = ext_comms.next().unwrap();
            assert!(!ext_comm2.is_transitive());
            assert_eq!(
                ext_comm2.types(),
                (ExtendedCommunityType::NonTransitiveTwoOctetSpecific,
                 ExtendedCommunitySubType::OtherSubType(0x04))
            );
            assert_eq!(ext_comm2.as2(), Some(Asn16::from_u16(0)));

            assert!(ext_comms.next().is_none());

        }

        #[test]
        fn large_communities() {
            // BGP UPDATE with several path attributes, including Large
            // Communities with three communities: 65536:1:1, 65536:1:2, 65536:1:3
            let buf = vec![
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x57, 0x02, 0x00, 0x00, 0x00, 0x3b, 0x40,
                0x01, 0x01, 0x00, 0x40, 0x02, 0x06, 0x02, 0x01,
                0x00, 0x01, 0x00, 0x00, 0x40, 0x03, 0x04, 0xc0,
                0x00, 0x02, 0x02, 0xc0, 0x20, 0x24, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x03, 0x20, 0xcb, 0x00, 0x71, 0x0d
            ];
            let update: UpdateMessage<_> = Message::from_octets(
                &buf,
                Some(SessionConfig::modern())
            ).unwrap().try_into().unwrap();

            let mut lcs = update.large_communities().unwrap();
            let lc1 = lcs.next().unwrap();
            assert_eq!(lc1.global(), 65536);
            assert_eq!(lc1.local1(), 1);
            assert_eq!(lc1.local2(), 1);

            let lc2 = lcs.next().unwrap();
            assert_eq!(lc2.global(), 65536);
            assert_eq!(lc2.local1(), 1);
            assert_eq!(lc2.local2(), 2);

            let lc3 = lcs.next().unwrap();
            assert_eq!(lc3.global(), 65536);
            assert_eq!(lc3.local1(), 1);
            assert_eq!(lc3.local2(), 3);

            assert_eq!(format!("{}", lc3), "65536:1:3");

            assert!(lcs.next().is_none());

        }

        #[test]
        fn chained_community_iters() {
            let buf = vec![
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x82, 0x02, 0x00, 0x00, 0x00, 0x62, 0x40,
                0x01, 0x01, 0x00, 0x40, 0x02, 0x16, 0x02, 0x05,
                0x00, 0x00, 0x00, 0x65, 0x00, 0x00, 0x01, 0x2d,
                0x00, 0x00, 0x01, 0x2c, 0x00, 0x00, 0x02, 0x58,
                0x00, 0x00, 0x02, 0xbc, 0x40, 0x03, 0x04, 0x0a,
                0x01, 0x03, 0x01, 0x80, 0x04, 0x04, 0x00, 0x00,
                0x00, 0x00, 0x40, 0x05, 0x04, 0x00, 0x00, 0x00,
                0x64, 0xc0, 0x08, 0x0c, 0x00, 0x2a, 0x02, 0x06,
                0xff, 0xff, 0xff, 0x01, 0xff, 0xff, 0xff, 0x03,
                0xc0, 0x10, 0x10, 0x00, 0x06, 0x00, 0x00, 0x44,
                0x9c, 0x40, 0x00, 0x40, 0x04, 0x00, 0x00, 0x44,
                0x9c, 0x40, 0x00, 0x80, 0x0a, 0x04, 0x0a, 0x00,
                0x00, 0x04, 0x80, 0x09, 0x04, 0x0a, 0x00, 0x00,
                0x03, 0x00, 0x00, 0x00, 0x01, 0x19, 0xc6, 0x33,
                0x64, 0x00
            ];
            let sc = SessionConfig::modern_addpath();
            let upd: UpdateMessage<_> = Message::from_octets(&buf, Some(sc))
                .unwrap().try_into().unwrap();

            for c in upd.all_communities().unwrap() {
                println!("{}", c);
            }
            assert!(upd.all_communities().unwrap().eq(&[
                    Community::Standard(StandardCommunity::new(42.into(), Tag::new(518))),
                    WellKnown::NoExport.into(),
                    WellKnown::NoExportSubconfed.into(),
                    [0x00, 0x06, 0x00, 0x00, 0x44, 0x9c, 0x40, 0x00].into(),
                    [0x40, 0x04, 0x00, 0x00, 0x44, 0x9c, 0x40, 0x00].into(),
            ]))

        }

    }


    //--- BGP NOTIFICATION related tests -------------------------------------
    mod notification {
        use super::*;

        #[test]
        fn notification() {
            let buf = vec![
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x15, 0x03, 0x06, 0x04
            ];
            let notification: NotificationMessage<_> =
                Message::from_octets(&buf, None).unwrap().try_into().unwrap();
            assert_eq!(notification.length(), 21);

            assert_eq!(notification.code(), 6);
            assert_eq!(notification.subcode(), 4);
            assert_eq!(notification.data(), None);

        }
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
