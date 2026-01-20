use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use octseq::{Octets, Parser};
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

use crate::bgp::types::RouteDistinguisher;
use crate::util::parser::{parse_ipv4addr, parse_ipv6addr, ParseError};

use super::afisafi::AfiSafiType as AfiSafi;

/// Conventional and BGP-MP Next Hop variants.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))] 
pub enum NextHop {
    Multicast(IpAddr),
    #[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))] 
    Ipv6LL{global: Ipv6Addr, link_local: Ipv6Addr}, // is this always unicast?
    MplsVpnUnicast(RouteDistinguisher, IpAddr),
    Empty, // FlowSpec
    Unimplemented(AfiSafi),
    #[cfg_attr(feature = "serde", serde(untagged, serialize_with = "serialize_unicast"))]
    Unicast(IpAddr),
}

#[cfg(feature = "serde")]
fn serialize_unicast<S>(ip: &IpAddr, s: S) -> Result<S::Ok, S::Error> where S: serde::Serializer {
    match ip {
        IpAddr::V4(v4) => s.serialize_newtype_variant("Afisafi", 0, "ipv4Unicast", &v4),
        IpAddr::V6(v6) => s.serialize_newtype_variant("Afisafi", 1, "ipv6Unicast", &v6),
    }
}

impl NextHop {
    pub fn new(afisafi: AfiSafi) -> Self {
        use AfiSafi::*;
        match afisafi {
            Ipv4Unicast => Self::Unicast(Ipv4Addr::from(0).into()),
            Ipv6Unicast => Self::Unicast(Ipv6Addr::from(0).into()),
            Ipv4Multicast => Self::Multicast(Ipv4Addr::from(0).into()),
            Ipv6Multicast => Self::Multicast(Ipv6Addr::from(0).into()),

            Ipv4MplsUnicast => Self::Unicast(Ipv4Addr::from(0).into()),
            Ipv6MplsUnicast => Self::Unicast(Ipv6Addr::from(0).into()),

            Ipv4MplsVpnUnicast => Self::MplsVpnUnicast(
                RouteDistinguisher::zeroes(),
                Ipv4Addr::from(0).into()
            ),
            Ipv6MplsVpnUnicast => Self::MplsVpnUnicast(
                RouteDistinguisher::zeroes(),
                Ipv6Addr::from(0).into()
            ),

            Ipv4RouteTarget => Self::Unicast(Ipv4Addr::from(0).into()),

            Ipv4FlowSpec | Ipv6FlowSpec => Self::Empty,

            L2VpnVpls => Self::Unicast(Ipv4Addr::from(0).into()),
            L2VpnEvpn => Self::Unicast(Ipv4Addr::from(0).into()),
            AfiSafi::Unsupported(_, _) => Self::Unimplemented(afisafi)
        }
    }
}

impl std::fmt::Display for NextHop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unicast(ip) | Self::Multicast(ip)  => write!(f, "{}", ip),
            Self::Ipv6LL{global, link_local} => write!(f, "{} {} ", global, link_local),
            Self::MplsVpnUnicast(rd, ip) => write!(f, "rd {} {}", rd, ip),
            Self::Empty => write!(f, "empty"),
            Self::Unimplemented(afisafi) => {
                write!(f, "unimplemented for AfiSafi {}", afisafi)
            }
        }
    }
}



//--- NextHop in MP_REACH_NLRI -----------------------------------------------
impl NextHop {
    pub fn parse<R: Octets>(parser: &mut Parser<'_, R>, afisafi: AfiSafi)
        -> Result<Self, ParseError>
    {
        use AfiSafi::*;
        let len = parser.parse_u8()?;

        macro_rules! error {
            () => { return  Err(ParseError::Unsupported) }
        }

        let res = match afisafi {

            Ipv4Unicast |
                Ipv4Multicast |
                Ipv4RouteTarget |
                L2VpnVpls |
                L2VpnEvpn
            => {
                match len {
                    4 => NextHop::Unicast(parse_ipv4addr(parser)?.into()),
                    _ => error!()
                }
            }
            Ipv6Unicast => {
                match len {
                    16 => NextHop::Unicast(parse_ipv6addr(parser)?.into()),
                    32 => NextHop::Ipv6LL{
                        global: parse_ipv6addr(parser)?,
                        link_local: parse_ipv6addr(parser)?,
                    },
                    _ => error!()
                }
            }
            Ipv6Multicast => {
                match len {
                    16 => NextHop::Unicast(parse_ipv6addr(parser)?.into()),
                    _ => error!()
                }
            }
            // RFC4684: the nexthop for MPLS can be of the other AFI than the
            // NLRI themselves are.
            Ipv4MplsUnicast | Ipv6MplsUnicast => {
                match len {
                    4 => NextHop::Unicast(parse_ipv4addr(parser)?.into()),
                    16 => NextHop::Unicast(parse_ipv6addr(parser)?.into()),
                    _ => error!()
                }
            }
            Ipv4MplsVpnUnicast => {
                match len {
                    12 => NextHop::MplsVpnUnicast(
                        RouteDistinguisher::parse(parser)?,
                        parse_ipv4addr(parser)?.into()
                    ),
                    _ => error!()
                }
            }
            Ipv6MplsVpnUnicast => {
                match len {
                    24 => NextHop::MplsVpnUnicast(
                        RouteDistinguisher::parse(parser)?,
                        parse_ipv6addr(parser)?.into()
                    ),
                    _ => error!()
                }
            }

            Ipv4FlowSpec | Ipv6FlowSpec => Self::Empty,

            AfiSafi::Unsupported(_, _) => error!()
        };

        Ok(res)
    }

    pub fn skip<R: Octets>(parser: &mut Parser<'_, R>)
        -> Result<(), ParseError>
    {
        let len = parser.parse_u8()?;
        parser.advance(len.into())?;
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[cfg(feature = "serde")]
    #[test]
    fn nexthop_serialize() {
        assert_eq!(
            serde_json::to_string(
                &NextHop::Unicast("1.2.3.4".parse().unwrap()))
            .unwrap(),
            "{\"ipv4Unicast\":\"1.2.3.4\"}"
        );
        assert_eq!(
            serde_json::to_string(
                &NextHop::Unicast("2001:db8:abcd::".parse().unwrap())
            ).unwrap(),
            "{\"ipv6Unicast\":\"2001:db8:abcd::\"}"
        );
        assert_eq!(
            serde_json::to_string(
                &NextHop::Ipv6LL{
                        global: "2001:db8:abcd::".parse().unwrap(),
                        link_local: "fe80::".parse().unwrap(),
                    }
            ).unwrap(),
            "{\"ipv6LL\":{\"global\":\"2001:db8:abcd::\",\"linkLocal\":\"fe80::\"}}"
        );

        //eprintln!("{}", serde_json::to_string(&NextHop::Unicast("1.2.3.4".parse().unwrap())).unwrap());
        //eprintln!("{}", serde_json::to_string(&NextHop::Unicast("2001:db8:abcd::".parse().unwrap())).unwrap());
        //eprintln!("{}", 
        //    serde_json::to_string(
        //        &NextHop::Ipv6LL{
        //                global: "2001:db8:abcd::".parse().unwrap(),
        //                link_local: "fe80::".parse().unwrap(),
        //            }
        //    ).unwrap(),
        //);
    }
}
