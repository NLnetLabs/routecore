use crate::bgp::message::Header;
use crate::util::parser::ParseError;
use octseq::{Octets, Parser};

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

// to properly enumify the codes, check:
// RFCs
//  4271
//  4486
//  8203
//  9003

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
