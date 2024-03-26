use std::fmt;

use octseq::{Octets, Parser};
use crate::util::parser::ParseError;

use super::common::prefix_bits_to_bytes;

/// NLRI containing a Route Target membership as defined in RFC4684.
///
/// **TODO**: implement accessor methods for the contents of this NLRI.
#[derive(Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RouteTargetNlri<Octs> {
    raw: Octs
}

impl<Octs> RouteTargetNlri<Octs> {
    pub fn parse<'a, P>(parser: &mut Parser<'a, P>)
        -> Result<Self, ParseError>
    where
        P: Octets<Range<'a> = Octs>
    {
        let prefix_bits = parser.parse_u8()?;
        let prefix_bytes = prefix_bits_to_bytes(prefix_bits);
        let raw = parser.parse_octets(prefix_bytes)?;

        Ok(Self{raw})
    }
}

impl<Octs, Other> PartialEq<RouteTargetNlri<Other>> for RouteTargetNlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &RouteTargetNlri<Other>) -> bool {
        self.raw.as_ref() == other.raw.as_ref()
    }
}

impl<T> fmt::Display for RouteTargetNlri<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ROUTE-TARGET-NLRI")
    }
}