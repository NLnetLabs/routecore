use octseq::{Octets, Parser};

use crate::bgp::message::Header;
use crate::bgp::types::{Afi, AfiSafi, RouteRefreshSubtype};
use crate::util::parser::ParseError;

/// BGP RouteRefresh message, variant of the [`Message`] enum.
#[derive(Clone, Debug)]
pub struct RouteRefreshMessage<Octets> {
    octets: Octets,
    afisafi: AfiSafi,
    subtype: RouteRefreshSubtype,
}

impl<Octs: Octets> RouteRefreshMessage<Octs> {
    pub fn from_octets(octets: Octs) -> Result<Self, ParseError> {
        let mut parser = Parser::from_ref(&octets);
        {
            let header = Header::parse(&mut parser)?;
            if header.length() != 23 || parser.remaining() != 4 {
                return Err(ParseError::form_error(
                        "ROUTEREFRESH of invalid size"
                ));
            }
        }
        let afi = parser.parse_u16_be()?;
        let subtype = parser.parse_u8()?.into();
        let safi = parser.parse_u8()?;
        let afisafi = (afi, safi).into();

        Ok(RouteRefreshMessage { octets, afisafi, subtype })
    }

    pub fn octets(&self) -> &Octs {
            &self.octets
    }
}

impl<Octs> RouteRefreshMessage<Octs> {
    /// Returns the `Afi` for this Route Refresh message.
    pub fn afi(&self) -> Afi {
        self.afisafi.afi()
    }

    /// Returns the `AfiSafi` for this Route Refresh message.
    pub fn afisafi(&self) -> AfiSafi {
        self.afisafi
    }

    /// Returns the `RouteRefreshSubtype` for this Route Refresh message.
    ///
    /// The subtype, as defined in RFC7313 (Enhanced Route Refresh
    /// Capability), is put in the 'reserved' byte as specified in the
    /// original RFC2918. That reserved byte should be set to 0 in the
    /// original, non-enhanced case, which translates to the
    /// RouteRefreshSubtype::Normal variant.
    /// This method does not distinguish between whether this message was
    /// received over a session with vs without Enhanced Route Refresh
    /// Capability.
    pub fn subtype(&self) -> RouteRefreshSubtype {
        self.subtype
    }
}

impl<Octs: Octets> AsRef<[u8]> for RouteRefreshMessage<Octs> {
    fn as_ref(&self) -> &[u8] {
        self.octets.as_ref()
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn from_octets() {

        let raw = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x17, 0x05, 0x00, 0x01, 0x01, 0x01
        ];

        let rr = RouteRefreshMessage::from_octets(&raw).unwrap();
        assert_eq!(rr.afisafi(), AfiSafi::Ipv4Unicast);
        assert_eq!(rr.subtype(), RouteRefreshSubtype::Begin);

    }
}
