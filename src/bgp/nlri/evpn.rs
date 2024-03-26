use std::fmt;

use octseq::{Octets, Parser};
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

use crate::typeenum;
use crate::util::parser::ParseError;

typeenum!(
    EvpnRouteType, u8,
    {
      1 => EthernetAutoDiscovery,
      2 => MacIpAdvertisement,
      3 => InclusiveMulticastEthernetTag,
      4 => EthernetSegment,
      5 => IpPrefix,
    }
);

/// NLRI containing a EVPN NLRI as defined in RFC7432.
///
/// **TODO**: implement accessor methods for the contents of this NLRI.
#[derive(Copy, Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EvpnNlri<Octs> {
    #[allow(dead_code)]
    route_type: EvpnRouteType,
    raw: Octs,
}

impl<T> EvpnNlri<T> {
    pub fn route_type(&self) -> EvpnRouteType {
        self.route_type
    }
}

impl<Octs: Octets> EvpnNlri<Octs> {
    pub fn parse<'a, R>(parser: &mut Parser<'a, R>)
        -> Result<Self, ParseError>
    where
        R: Octets<Range<'a> = Octs>
    {
        let route_type = parser.parse_u8()?.into();
        let route_len = parser.parse_u8()?;
        let raw = parser.parse_octets(route_len.into())?;

        Ok(
            EvpnNlri {
                route_type,
                raw
            }
        )
    }
}

impl<Octs, Other> PartialEq<EvpnNlri<Other>> for EvpnNlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &EvpnNlri<Other>) -> bool {
        self.route_type == other.route_type &&
            self.raw.as_ref() == other.raw.as_ref()
    }
}

impl<T> fmt::Display for EvpnNlri<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "EVPN-{}", self.route_type)
    }
}