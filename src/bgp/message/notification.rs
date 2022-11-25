use crate::bgp::message::Header;
use crate::util::parser::ParseError;
use octseq::{OctetsRef, Parser, ShortBuf};

const COFF: usize = 19; // XXX replace this with .skip()'s?

/// BGP NOTIFICATION message, variant of the [`Message`] enum.
#[derive(Clone)]
pub struct NotificationMessage<Octets> {
    octets: Octets
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

    pub fn octets(&self) -> &Octets {
            &self.octets
    }

    pub fn for_slice(s: Octets) -> Self {
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

        assert_eq!(notification.code(), 6);
        assert_eq!(notification.subcode(), 4);
        assert_eq!(notification.data(), None);

    }
}
