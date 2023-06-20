use octseq::{Octets, OctetsBuilder, Parser, ShortBuf};
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize}; // for typeenum! macro

use crate::bgp::message::{Header, MsgType};
use crate::typeenum;
use crate::util::parser::ParseError;

use std::fmt;

const COFF: usize = 19; // XXX replace this with .skip()'s?

/// BGP NOTIFICATION message, variant of the [`Message`] enum.
#[derive(Clone)]
pub struct NotificationMessage<Octets> {
    octets: Octets
}

impl<Octs: Octets> NotificationMessage<Octs> {
    /// Returns the [`Header`] for this message.
    pub fn header(&self) -> Header<Octs::Range<'_>> {
        Header::for_slice(self.octets.range(..19))
    }

    /// Returns the length in bytes of the entire BGP message.
	pub fn length(&self) -> u16 {
        self.header().length()
	}
}

impl<Octs: Octets> AsRef<[u8]> for NotificationMessage<Octs> {
    fn as_ref(&self) -> &[u8] {
        self.octets.as_ref()
    }

}

/// BGP NOTIFICATION Message.
///
///
impl<Octs: Octets> NotificationMessage<Octs> {

    pub fn octets(&self) -> &Octs {
            &self.octets
    }

    pub fn for_slice(s: Octs) -> Self {
        Self { octets: s }
    }
    
    pub fn code(&self) -> ErrorCode {
        self.octets.as_ref()[COFF].into()
    }

    pub fn subcode(&self) -> SubCode {
        let raw = self.octets.as_ref()[COFF+1];
        match self.code() {
            ErrorCode::Cease => SubCode::Cease(raw.into()),
            _ => SubCode::Todo(raw),
        }
    }

    pub fn data(&self) -> Option<&[u8]> {
        if self.as_ref().len() > 21 {
            Some(&self.as_ref()[21..])
        } else {
            None
        }
    }
}

impl<Octs: Octets> NotificationMessage<Octs> {
    pub fn from_octets(octets: Octs) -> Result<Self, ParseError> {
        Ok(NotificationMessage { octets })
    }

    // TODO impl fn check()

    pub fn parse<'a, R>(parser: &mut Parser<'a, R>)
        -> Result<Self, ParseError>
    where
        R: Octets<Range<'a> = Octs>, 
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

//------------ Builder --------------------------------------------------------

pub struct NotificationBuilder<Target> {
    _target: Target,
}

use core::convert::Infallible;
impl<Target: OctetsBuilder> NotificationBuilder<Target>
where Infallible: From<<Target as OctetsBuilder>::AppendError> {
    pub fn from_target<D: AsRef<[u8]>>(
        mut target: Target,
        code: ErrorCode,
        subcode: SubCode,
        data: Option<D>
    ) -> Result<Target, NotificationBuildError> {
        let mut h = Header::<&[u8]>::new();
        h.set_length(21 +
            u16::try_from(
                data.as_ref().map_or(0, |d| d.as_ref().len())
            ).map_err(|_| NotificationBuildError::LargePdu)?
        );
        h.set_type(MsgType::Notification);

        let _ = target.append_slice(h.as_ref());
        // XXX or do we want
        //target.append_slice(h.as_ref()).map_err(|_| NotificationBuildError::ShortBuf)?;

        // code + subcode
        let _ = target.append_slice(&[code.into(), subcode.into()]);

        if let Some(data) = data {
            let _ = target.append_slice(&data.as_ref());
        }

        Ok(target)
    }

}

impl NotificationBuilder<Vec<u8>> {
    pub fn new_vec<D: AsRef<[u8]>>(
        code: ErrorCode,
        subcode: SubCode,
        data: Option<D>
    ) -> Result<Vec<u8>, NotificationBuildError> {
        Ok(Self::from_target(Vec::with_capacity(21), code, subcode, data)?)
    }
}

#[derive(Debug)]
pub enum NotificationBuildError {
    ShortBuf,
    LargePdu,
}

impl From<octseq::ShortBuf> for NotificationBuildError {
    fn from(_: octseq::ShortBuf) -> Self {
        NotificationBuildError::ShortBuf
    }
}

impl fmt::Display for NotificationBuildError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NotificationBuildError::ShortBuf => octseq::ShortBuf.fmt(f),
            NotificationBuildError::LargePdu => {
                f.write_str("PDU size exceeded")
            }
        }
    }
}



// to properly enumify the codes, check:
// RFCs
//  4271
//  4486
//  8203
//  9003

typeenum!(ErrorCode, u8, 
    0 => Reserved,
    1 => MessageHeaderError,
    2 => OpenMessageError,
    3 => UpdateMessageError,
    4 => HoldTimerExpired,
    5 => FiniteStateMachineError,
    6 => Cease,
    7 => RouteRefreshMessageError,
);

typeenum!(CeaseSubCode, u8,
    0 => Reserved,
    1 => MaximumPrefixesReached,
    2 => AdministrativeShutdown,
    3 => PeerDeconfigured,
    4 => AdministrativeReset,
    5 => ConnectionRejected,
    6 => OtherConfigurationChange,
    7 => ConnectionCollisionResolution,
    8 => OutOfResources,
    9 => HardReset,
    10 => BfdDown,
);

#[derive(Debug, Eq, PartialEq)]
pub enum SubCode {
    Cease(CeaseSubCode),
    Todo(u8),
}

impl From<SubCode> for u8 {
    fn from(s: SubCode) -> u8 {
        match s {
            SubCode::Cease(csc) => csc.into(),
            SubCode::Todo(u) => u,
        }
    }
}

//--- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::message::Message;

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

        assert_eq!(notification.code(), ErrorCode::Cease);
        assert_eq!(
            notification.subcode(),
            SubCode::Cease(CeaseSubCode::AdministrativeReset)
        );
        assert_eq!(notification.data(), None);

    }

    #[test]
    fn build() {
        let msg = NotificationBuilder::new_vec(
            ErrorCode::Cease,
            SubCode::Cease(CeaseSubCode::OtherConfigurationChange),
            Some(Vec::new())
        ).unwrap();

        let parsed = NotificationMessage::from_octets(&msg).unwrap();
        assert_eq!(parsed.code(), ErrorCode::Cease);
        assert_eq!(
            parsed.subcode(),
            SubCode::Cease(CeaseSubCode::OtherConfigurationChange)
        );
        assert_eq!(parsed.length(), 21);
        assert_eq!(parsed.as_ref().len(), 21);
    }
}
