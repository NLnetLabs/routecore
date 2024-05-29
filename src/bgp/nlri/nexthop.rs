use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use octseq::{Octets, Parser};
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

use crate::bgp::types::RouteDistinguisher;
use crate::util::parser::{parse_ipv4addr, parse_ipv6addr, ParseError};

use super::afisafi::AfiSafiType as AfiSafi;

/// Conventional and BGP-MP Next Hop variants.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum NextHop {
    Unicast(IpAddr),
    Multicast(IpAddr),
    Ipv6LL(Ipv6Addr, Ipv6Addr), // is this always unicast?
    MplsVpnUnicast(RouteDistinguisher, IpAddr),
    Empty, // FlowSpec
    Unimplemented(AfiSafi),
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
            Self::Ipv6LL(ip1, ip2) => write!(f, "{} {} ", ip1, ip2),
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
                    32 => NextHop::Ipv6LL(
                        parse_ipv6addr(parser)?,
                        parse_ipv6addr(parser)?
                    ),
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

