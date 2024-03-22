use std::fmt;

use octseq::{Octets, Parser};
use crate::util::parser::ParseError;

use super::common::prefix_bits_to_bytes;

/// NLRI containing a Route Target membership as defined in RFC4684.
///
/// **TODO**: implement accessor methods for the contents of this NLRI.
#[derive(Clone, Debug, Hash)]
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

impl<T> fmt::Display for RouteTargetNlri<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ROUTE-TARGET-NLRI")
    }
}
