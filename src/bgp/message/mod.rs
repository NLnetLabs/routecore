pub mod open;
pub mod update;
pub mod nlri;
pub mod notification;
pub mod keepalive;
pub mod attr_change_set;

use octseq::{Octets, Parser};
use crate::util::parser::ParseError;
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::error::Error;
use crate::addr::PrefixError;
use crate::typeenum; // from util::macros

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

pub use open::OpenMessage;
pub use update::{UpdateMessage, SessionConfig};
pub use notification::NotificationMessage;
pub use keepalive::KeepaliveMessage;

//--- Generic ----------------------------------------------------------------

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
///  * `KeepaliveMessage`
///  * TODO: `RouteRefreshMessage`
///
#[derive(Clone)]
pub enum Message<Octs: Octets> {
    Open(OpenMessage<Octs>),
    Update(UpdateMessage<Octs>),
    Notification(NotificationMessage<Octs>),
    Keepalive(KeepaliveMessage<Octs>),
}

impl<Octs: Octets> AsRef<[u8]> for Message<Octs> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Message::Open(m) => m.as_ref(),
            Message::Update(m) => m.as_ref(),
            Message::Notification(m) => m.as_ref(),
            Message::Keepalive(m) => m.as_ref(),
        }
    }
}

impl<Octs: Octets> Message<Octs> {
    fn octets(&self) -> &Octs {
        match self {
            Message::Open(m) => m.octets(),
            Message::Update(m) => m.octets(),
            Message::Notification(m) => m.octets(),
            Message::Keepalive(m) => m.octets(),
        }
    }
}

impl<Octs: Octets> Message<Octs> {
    fn header(&self) -> Header<Octs::Range<'_>> {
        Header::for_slice(self.octets().range(..19))
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

typeenum!(
/// BGP Message types.
    MsgType, u8,
    1 => Open,
    2 => Update,
    3 => Notification,
    4 => Keepalive,
    5 => RouteRefresh, // RFC2918
    //6 => //Capability, // draft-ietf-idr-dynamic-cap
);

impl<Octs: Octets> Message<Octs> {
    /// Create a Message from an octets sequence.
    pub fn from_octets(octets: Octs, config: Option<SessionConfig>)
        -> Result<Message<Octs>, ParseError>
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
            MsgType::Keepalive =>
                Ok(Message::Keepalive(
                        KeepaliveMessage::from_octets(octets)?
                )),
            t => panic!("not implemented yet: {:?}", t)
        }
    }
}

//--- From / TryFrom ---------------------------------------------------------


impl<Octs: Octets> TryFrom<Message<Octs>> for OpenMessage<Octs> {
    type Error = MessageError;

    fn try_from(msg: Message<Octs>) -> Result<Self, Self::Error> {
        match msg {
            Message::Open(u) => Ok(u),
            _ => Err(MessageError::InvalidMsgType),
        }
    }
}

impl<Octs: Octets> TryFrom<Message<Octs>> for UpdateMessage<Octs> {
    type Error = MessageError;

    fn try_from(msg: Message<Octs>) -> Result<Self, Self::Error> {
        match msg {
            Message::Update(u) => Ok(u),
            _ => Err(MessageError::InvalidMsgType),
        }
    }
}

impl<Octs: Octets> TryFrom<Message<Octs>> for NotificationMessage<Octs> {
    type Error = MessageError;

    fn try_from(msg: Message<Octs>) -> Result<Self, Self::Error> {
        match msg {
            Message::Notification(u) => Ok(u),
            _ => Err(MessageError::InvalidMsgType),
        }
    }
}

//--- Header -----------------------------------------------------------------
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
        
/// BGP Message header.
#[derive(Clone, Copy, Default)]
pub struct Header<Octs>(Octs);

impl<Octs: Octets + AsMut<[u8]>> Header<Octs> {
    pub fn set_type(&mut self, typ: MsgType) {
        self.0.as_mut()[18] = typ.into();
    }

    pub fn set_length(&mut self, len: u16) {
        self.0.as_mut()[16..=17].copy_from_slice( &(len.to_be_bytes()) );
    }
}

impl<Octs: Octets> AsRef<[u8]> for Header<Octs> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<Octs: Octets> Header<Octs> {

    pub fn new() -> Header<Vec<u8>> {
        let mut buf = vec![0xff; 19]; // set marker
        buf[16] = 0;        // first length byte
        buf[17] = 0x13;     // second length byte, default to 19, the minimum 
        buf[18] = 0;        // message type
        Header::<Vec<u8>>(buf)
    }


    /// Create a Header from an Octets.
    pub fn for_slice(s: Octs) -> Self {
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
            4 => MsgType::Keepalive,
            5 => MsgType::RouteRefresh,
            u => panic!("illegal Message Type {}", u)
        }
    }
}

impl<Octs: Octets> Header<Octs> {
    fn parse<'a, R>(parser: &mut Parser<'a, R>) -> Result<Self, ParseError>
    where
        R: Octets<Range<'a> = Octs>
    {
        let pos = parser.pos();
        Marker::check(parser)?;
        let _len = parser.parse_u16_be()?;
        let _typ = parser.parse_u8()?;
        parser.seek(pos)?;
        let res = parser.parse_octets(19)?;
        Ok(Header(res))
    }
}

impl Header<()> {
    pub fn check(parser: &mut Parser<[u8]>) -> Result<(), ParseError> {
        Marker::check(parser)?;
        let len = parser.parse_u16_be()? as usize;
        if len != parser.len() {
            return Err(ParseError::form_error("invalid length"));
        }
        // jump over type 
        // XXX should we check whether type is in our enum?
        parser.advance(1)?;
        Ok(())
    }
}

struct Marker;
impl Marker {
    fn check<R: Octets + ?Sized>(parser: &mut Parser<'_, R>)
        -> Result<(), ParseError>
    {
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

//--- Errors -----------------------------------------------------------------

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
