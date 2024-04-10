use std::{cmp, fmt};

use inetnum::asn::Asn;
use octseq::{Octets, OctetsBuilder, Parser};
use crate::{bgp::communities::ExtendedCommunity, util::parser::ParseError};

use super::common::prefix_bits_to_bytes;

/// NLRI containing a Route Target membership as defined in RFC4684.
#[derive(Clone, Debug, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RouteTargetNlri<Octs> {
    raw: Octs
}

impl<Octs: AsRef<[u8]>> RouteTargetNlri<Octs> {
    /// Returns true if this represents the default route target.
    pub fn is_default(&self) -> bool {
        self.raw.as_ref().len() == 0
    }

    /// Returns the origin AS, if any.
    pub fn origin_as(&self) -> Option<Asn> {
        if self.raw.as_ref().len() > 4 {
            Some(u32::from_be_bytes(self.raw.as_ref()[0..4]
                    .try_into().unwrap()).into())
        } else {
            None
        }
    }

    /// Returns the Route Target described as [`ExtendedCommunity`], if any.
    pub fn route_target(&self) -> Option<ExtendedCommunity> {
        if self.raw.as_ref().len() == 12 {
            Some(ExtendedCommunity::from_raw(
                self.raw.as_ref()[4..12].try_into().unwrap()
            ))
        } else {
            None
        }
    }
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


impl<Octs: AsRef<[u8]>> RouteTargetNlri<Octs> {
    pub(super) fn compose_len(&self) -> usize {
        self.raw.as_ref().len()
    }

    pub(super) fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError> {
        let len = u8::try_from(8 * self.compose_len()).unwrap_or(u8::MAX);
        target.append_slice(&[len])?;
        target.append_slice(self.raw.as_ref())
    }
}

impl<Octs: AsRef<[u8]>> Eq for RouteTargetNlri<Octs> { }

impl<Octs, Other> PartialEq<RouteTargetNlri<Other>> for RouteTargetNlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &RouteTargetNlri<Other>) -> bool {
        self.raw.as_ref() == other.raw.as_ref()
    }
}

impl<Octs> PartialOrd for RouteTargetNlri<Octs>
where Octs: AsRef<[u8]>,
{
    fn partial_cmp(&self, other: &RouteTargetNlri<Octs>) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<Octs: AsRef<[u8]>> Ord for RouteTargetNlri<Octs> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.raw.as_ref().cmp(other.raw.as_ref())
    }
}

impl<T> fmt::Display for RouteTargetNlri<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ROUTE-TARGET-NLRI")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use octseq::Parser;
    use crate::bgp::communities::{
        ExtendedCommunityType,
        ExtendedCommunitySubType
    };


    #[test]
    fn parse() {
        let raw = vec![
            0x60, 0x00, 0x00, 0x00, 0x64, 0x00, 0x02, 0x00,
            0x64, 0x00, 0x00, 0x00, 0x01, 0x60, 0x00, 0x00,
            0x00, 0x64, 0x01, 0x02, 0x0a, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x64, 0x01,
            0x02, 0x0a, 0x00, 0x00, 0x02, 0x00, 0x01
        ];
        let mut parser = Parser::from_ref(&raw);
        let mut res = vec![];

        while parser.remaining() > 0 {
            res.push(RouteTargetNlri::parse(&mut parser).unwrap());
        }
        assert_eq!(res.len(), 3);
        let nlri1 = &res[0];
        assert_eq!(nlri1.origin_as(), Some(Asn::from_u32(100)));
        let ec1 = nlri1.route_target().unwrap();
        assert_eq!(ec1.types(), (
            ExtendedCommunityType::TransitiveTwoOctetSpecific,
            ExtendedCommunitySubType::RouteTarget
        ));
    }
}
