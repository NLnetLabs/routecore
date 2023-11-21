use crate::typeenum; // from util::macros
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::bgp::message::nlri::RouteDistinguisher;

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

typeenum!(
/// AFI as used in BGP OPEN and UPDATE messages.
        AFI, u16,
        {
            1 => Ipv4,
            2 => Ipv6,
            25 => L2Vpn
        });

typeenum!(
/// SAFI as used in BGP OPEN and UPDATE messages.
    SAFI, u8,
    {
        1 => Unicast,
        2 => Multicast,
        4 => MplsUnicast,
        65 => Vpls,
        70 => Evpn,
        128 => MplsVpnUnicast,
    132 => RouteTarget,
    133 => FlowSpec,
    134 => FlowSpecVpn
    });

typeenum!(
/// BGP Origin types as used in BGP UPDATE messages.
    OriginType, u8,
    {
        0 => Igp,
        1 => Egp,
        2 => Incomplete,
    }
);

typeenum!(
/// Enhanced Route Refresh subtypes.
    RouteRefreshSubtype, u8, 
    {
        0 => Normal,
        1 => Begin, 
        2 => End, 
        255 => Reserved
    }
);

typeenum!(
/// PathAttributeType
///
/// As per:
/// <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-2>
    PathAttributeType, u8,
    {
        0 => Reserved,
        1 => Origin,
        2 => AsPath,
        3 => NextHop,
        4 => MultiExitDisc,
        5 => LocalPref,
        6 => AtomicAggregate,
        7 => Aggregator,
        8 => Communities,
        9 => OriginatorId,
        10 => ClusterList,
        14 => MpReachNlri,
        15 => MpUnreachNlri,
        16 => ExtendedCommunities,
        17 => As4Path,
        18 => As4Aggregator,
        20 => Connector,
        21 => AsPathLimit,
        22 => PmsiTunnel,
        25 => Ipv6ExtendedCommunities,
        32 => LargeCommunities,
        33 => BgpsecAsPath,
        128 => AttrSet,
        255 => RsrvdDevelopment
    }
);

/// Wrapper for the 4 byte Multi-Exit Discriminator in path attributes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MultiExitDisc(pub u32);

impl std::fmt::Display for MultiExitDisc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Wrapper for the 4 byte Local Preference value in path attributes.
#[derive(Debug, Eq, PartialEq, Clone, Copy, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LocalPref(pub u32);

impl std::fmt::Display for LocalPref {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Conventional and BGP-MP Next Hop variants.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
// XXX introduce v4/v6 specific Empty for FlowSpec? it does not carry
// anything, but when creating the NextHop in
// MpReachNlriBuilder::new_for_nexthop() we need both an AFI and a SAFI.
pub enum NextHop {
    Unicast(IpAddr),
    Multicast(IpAddr),
    Ipv6LL(Ipv6Addr, Ipv6Addr), // is this always unicast?

    // XXX can we consolidate these two into one with IpAddr?
    Ipv4MplsVpnUnicast(RouteDistinguisher, Ipv4Addr),
    Ipv6MplsVpnUnicast(RouteDistinguisher, Ipv6Addr),

    Empty, // FlowSpec
    Evpn(IpAddr),
    Unimplemented(AFI, SAFI),
}

impl NextHop {
    pub fn new(afi: AFI, safi: SAFI) -> Self {
        match (afi, safi) {
            (AFI::Ipv4, SAFI::Unicast) => Self::Unicast(Ipv4Addr::from(0).into()),
            (AFI::Ipv6, SAFI::Unicast) => Self::Unicast(Ipv6Addr::from(0).into()),
            (AFI::Ipv4, SAFI::Multicast) => Self::Multicast(Ipv4Addr::from(0).into()),
            (AFI::Ipv6, SAFI::Multicast) => Self::Multicast(Ipv6Addr::from(0).into()),
            (AFI::Ipv4 | AFI::Ipv6, SAFI::FlowSpec) => Self::Empty,

            (_, _) => Self::Unimplemented(afi, safi)
        }
    }

    pub fn afi_safi(&self) -> (AFI, SAFI) {
        match self {
            Self::Unicast(IpAddr::V4(_)) => (AFI::Ipv4, SAFI::Unicast),
            Self::Unicast(IpAddr::V6(_)) => (AFI::Ipv6, SAFI::Unicast),
            Self::Multicast(IpAddr::V4(_)) => (AFI::Ipv4, SAFI::Multicast),
            Self::Multicast(IpAddr::V6(_)) => (AFI::Ipv6, SAFI::Multicast),
            Self::Ipv6LL(..) => (AFI::Ipv6, SAFI::Unicast), // always unicast?
            Self::Empty => (AFI::Ipv4, SAFI::FlowSpec),
            Self::Evpn(IpAddr::V4(_)) => (AFI::Ipv4, SAFI::Unicast),
            Self::Evpn(IpAddr::V6(_)) => (AFI::Ipv6, SAFI::Unicast),
            _ => todo!("{}", &self)
        }
    }
}

impl std::fmt::Display for NextHop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unicast(ip) | Self::Multicast(ip)  => write!(f, "{}", ip),
            Self::Ipv6LL(ip1, ip2) => write!(f, "{} {} ", ip1, ip2),
            Self::Ipv4MplsVpnUnicast(rd, ip) => write!(f, "rd {} {}", rd, ip),
            Self::Ipv6MplsVpnUnicast(rd, ip) => write!(f, "rd {} {}", rd, ip),
            Self::Empty => write!(f, "empty"),
            Self::Evpn(ip) => write!(f, "evpn-{}", ip),
            Self::Unimplemented(afi, safi) => write!(f, "unimplemented for AFI {} /SAFI {}", afi, safi),
        }
    }
}
