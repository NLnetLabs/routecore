use log::warn;
use octseq::{Octets, OctetsBuilder, Parser};
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

    /// Get the (sub)code and optional data for this Notification message.
    pub fn details(&self) -> Details {
        let subraw = self.octets.as_ref()[COFF+1];
        use ErrorCode as E;
        use Details as S;
        match self.code() {
            E::Reserved => S::Reserved,
            E::MessageHeaderError => S::MessageHeaderError(subraw.into()),
            E::OpenMessageError => S::OpenMessageError(subraw.into()),
            E::UpdateMessageError => S::UpdateMessageError(subraw.into()),
            E::HoldTimerExpired => S::HoldTimerExpired,
            E::FiniteStateMachineError => {
                S::FiniteStateMachineError(subraw.into())
            }
            E::Cease => S::Cease(subraw.into()),
            E::RouteRefreshMessageError => {
                S::RouteRefreshMessageError(subraw.into())
            }
            E::Unimplemented(code) => S::Unimplemented(code, subraw)
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

//------------ Builder -------------------------------------------------------

pub struct NotificationBuilder<Target> {
    _target: Target,
}

use core::convert::Infallible;
impl<Target: OctetsBuilder> NotificationBuilder<Target>
where
    Infallible: From<<Target as OctetsBuilder>::AppendError>,
{
    pub fn from_target<S, D: AsRef<[u8]>>(
        mut target: Target,
        subcode: S,
        data: Option<D>
    ) -> Result<Target, NotificationBuildError>
        where S: Into<Details>
    {
        let mut h = Header::<&[u8]>::new();
        h.set_length(21 +
            u16::try_from(
                data.as_ref().map_or(0, |d| d.as_ref().len())
            ).map_err(|_| NotificationBuildError::LargePdu)?
        );
        h.set_type(MsgType::Notification);

        let _ = target.append_slice(h.as_ref());
        // XXX or do we want
        // target.append_slice(
        //     h.as_ref()).map_err(|_| NotificationBuildError::ShortBuf)?;

        let _ = target.append_slice(&subcode.into().raw());

        if let Some(data) = data {
            let _ = target.append_slice(data.as_ref());
        }

        Ok(target)
    }

}

impl NotificationBuilder<Vec<u8>> {
    pub fn new_vec<S, D: AsRef<[u8]>>(
        subcode: S,
        data: Option<D>
    ) -> Result<Vec<u8>, NotificationBuildError>
        where S: Into<Details>
    {
        Self::from_target(Vec::with_capacity(21), /*code,*/ subcode, data)
    }

    pub fn new_vec_nodata<S>(subcode: S) -> Vec<u8>
        where S: Into<Details>
    {
        // Without data (of arbitrary length) this is infallible for Vecs
        // so we simply unwrap
        Self::from_target(
            Vec::with_capacity(21),
            subcode,
            Option::<Vec<u8>>::None
        ).unwrap()
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



#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Details {
    Reserved,
    MessageHeaderError(MessageHeaderSubcode),
    OpenMessageError(OpenMessageSubcode),
    UpdateMessageError(UpdateMessageSubcode),
    HoldTimerExpired, // no subcodes, should be 0
    FiniteStateMachineError(FiniteStateMachineSubcode),
    Cease(CeaseSubcode),
    RouteRefreshMessageError(RouteRefreshMessageSubcode),
    Unimplemented(u8, u8),
}

impl Details {
    pub fn raw(&self) -> [u8; 2] {
        use Details as S;
        use ErrorCode as E;
        match self {
            S::Reserved => [0, 0],
            S::MessageHeaderError(sub) => {
                [E::MessageHeaderError.into(), (*sub).into()]
            }
            S::OpenMessageError(sub) => {
                [E::OpenMessageError.into(), (*sub).into()]
            }
            S::UpdateMessageError(sub) => {
                [E::UpdateMessageError.into(), (*sub).into()]
            }
            S::HoldTimerExpired => { 
                [E::HoldTimerExpired.into(), 0]
            }
            S::FiniteStateMachineError(sub) => {
                [E::FiniteStateMachineError.into(), (*sub).into()]
            }
            S::Cease(sub) => {
                [E::Cease.into(), (*sub).into()]
            }
            S::RouteRefreshMessageError(sub) => {
                [E::RouteRefreshMessageError.into(), (*sub).into()]
            }
            S::Unimplemented(code, subcode) => {
                warn!("serializing unimplemented \
                      Notification code/subcode {}/{}",
                      code, subcode);
                [*code, *subcode]
            }
        }
    }

}

//------------ Codes and Subcodes --------------------------------------------

// See RFCs 4271 4486 8203 9003

typeenum!(
    ErrorCode, u8,
    {
        0 => Reserved,
        1 => MessageHeaderError,
        2 => OpenMessageError,
        3 => UpdateMessageError,
        4 => HoldTimerExpired,
        5 => FiniteStateMachineError,
        6 => Cease,
        7 => RouteRefreshMessageError,
    }
);

typeenum!(
    MessageHeaderSubcode, u8,
    {
        0 => Unspecific,
        1 => ConnectionNotSynchronized,
        2 => BadMessageLength, // data: u16 bad length
        3 => BadMessageType, // data: u8 bad type
    }
);

impl From<MessageHeaderSubcode> for Details {
    fn from(s: MessageHeaderSubcode) -> Self {
        Details::MessageHeaderError(s)
    }
}

typeenum!(
    OpenMessageSubcode, u8,
    {
        0 => Unspecific,
        1 => UnsupportedVersionNumber, // only one with data: u16 version number
        2 => BadPeerAs,
        3 => BadBgpIdentifier,
        4 => UnsupportedOptionalParameter,
        5 => Deprecated5, // was: authentication failure
        6 => UnacceptableHoldTime,
        7 => UnsupportedCapability,
        8 => Deprecated8, // 8-10 deprecated because of 'improper use', rfc9234
        9 => Deprecated9,
        10 => Deprecated10,
        11 => RoleMismatch,
    }
);

impl From<OpenMessageSubcode> for Details {
    fn from(s: OpenMessageSubcode) -> Self {
        Details::OpenMessageError(s)
    }
}

typeenum!(
    UpdateMessageSubcode, u8,
    {
        0 => Unspecific,
        1 => MalformedAttributeList, // no data
        2 => UnrecognizedWellknownAttribute, // data: unrecognized attribute
        3 => MissingWellknownAttribute, // data: typecode of missing attribute
        4 => AttributeFlagsError, // data: erroneous attribute (t, l, v)
        5 => AttributeLengthError, // data: erroneous attribute (t, l, v)
        6 => InvalidOriginAttribute, // data: erroneous attribute (t, l, v)
        7 => Deprecated7, // was: AS routing loop, rfc1771
        8 => InvalidNextHopAttribute, // data: erroneous attribute (t, l, v)
        9 => OptionalAttributeError, // data: erroneous attribute (t, l, v)
        10 => InvalidNetworkField, // no data
        11 => MalformedAsPath, // no data
    }
);

impl From<UpdateMessageSubcode> for Details {
    fn from(s: UpdateMessageSubcode) -> Self {
        Details::UpdateMessageError(s)
    }
}

typeenum!(
    FiniteStateMachineSubcode, u8,
    {
        0 => UnspecifiedError,
        1 => UnexpectedMessageInOpenSentState, // data: u8 of message type
        2 => UnexpectedMessageInOpenConfirmState, // data: u8 of message type
        3 => UnexpectedMessageInEstablishedState, // data: u8 of message type
    }
);

impl From<FiniteStateMachineSubcode> for Details {
    fn from(s: FiniteStateMachineSubcode) -> Self {
        Details::FiniteStateMachineError(s)
    }
}

typeenum!(
    CeaseSubcode, u8,
    {
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
    }
);

impl From<CeaseSubcode> for Details {
    fn from(s: CeaseSubcode) -> Self {
        Details::Cease(s)
    }
}


typeenum!(
    RouteRefreshMessageSubcode, u8,
    {
        0 => Reserved,
        1 => InvalidMessageLength, // data: complete RouteRefresh message
    }
);

impl From<RouteRefreshMessageSubcode> for Details {
    fn from(s: RouteRefreshMessageSubcode) -> Self {
        Details::RouteRefreshMessageError(s)
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
            notification.details(),
            Details::Cease(CeaseSubcode::AdministrativeReset)
        );
        assert_eq!(notification.data(), None);

    }

    #[test]
    fn build_nodata() {
        let msg = NotificationBuilder::new_vec(
            CeaseSubcode::OtherConfigurationChange,
            Some(Vec::new())
        ).unwrap();

        let parsed = NotificationMessage::from_octets(&msg).unwrap();
        assert_eq!(parsed.code(), ErrorCode::Cease);
        assert_eq!(
            parsed.details(),
            CeaseSubcode::OtherConfigurationChange.into()
        );
        assert_eq!(parsed.length(), 21);
        assert_eq!(parsed.as_ref().len(), 21);

        let msg2 = NotificationBuilder::new_vec_nodata(
            CeaseSubcode::OtherConfigurationChange
        );
        assert_eq!(msg, msg2);
    }

    #[test]
    fn build_with_data() {
        let msg = NotificationBuilder::new_vec(
            MessageHeaderSubcode::BadMessageType, Some([12])
        ).unwrap();

        assert_eq!(msg.len(), 22);

        let parsed = NotificationMessage::from_octets(&msg).unwrap();
        assert_eq!(parsed.length(), 22);
    }
}
