use crate::typeenum; // from util::macros
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::bgp::message::nlri::RouteDistinguisher;

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

typeenum!(
/// AFI as used in BGP OPEN and UPDATE messages.
#[cfg_attr(feature = "serde", serde(from = "u16"))]
        AFI, u16,
        {
            1 => Ipv4,
            2 => Ipv6,
            25 => L2Vpn
        });

typeenum!(
/// SAFI as used in BGP OPEN and UPDATE messages.
#[cfg_attr(feature = "serde", serde(from = "u8"))]
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

/// Valid/supported pair of `AFI` and `SAFI`.
///
/// Not all combinations of the `AFI` and `SAFI` variants make sense. This
/// enum explicitly comprises combinations which are described in standards
/// documents.
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum AfiSafi {
    Ipv4Unicast,
    Ipv6Unicast,
    Ipv4Multicast,
    Ipv6Multicast,

    Ipv4MplsUnicast,
    Ipv6MplsUnicast,

    Ipv4MplsVpnUnicast,
    Ipv6MplsVpnUnicast,

    Ipv4RouteTarget,

    Ipv4FlowSpec,
    Ipv6FlowSpec,

    L2VpnVpls,
    L2VpnEvpn,
}

impl TryFrom<(AFI, SAFI)> for AfiSafi {
    type Error = &'static str;
    fn try_from(t: (AFI, SAFI)) -> Result<Self, Self::Error> {

        use AfiSafi::*;
        match t {
            (AFI::Ipv4, SAFI::Unicast) => Ok(Ipv4Unicast),
            (AFI::Ipv6, SAFI::Unicast) => Ok(Ipv6Unicast),

            (AFI::Ipv4, SAFI::Multicast) => Ok(Ipv4Multicast),
            (AFI::Ipv6, SAFI::Multicast) => Ok(Ipv6Multicast),

            (AFI::Ipv4, SAFI::MplsUnicast) => Ok(Ipv4MplsUnicast),
            (AFI::Ipv6, SAFI::MplsUnicast) => Ok(Ipv6MplsUnicast),

            (AFI::Ipv4, SAFI::MplsVpnUnicast) => Ok(Ipv4MplsVpnUnicast),
            (AFI::Ipv6, SAFI::MplsVpnUnicast) => Ok(Ipv6MplsVpnUnicast),

            (AFI::Ipv4, SAFI::RouteTarget) => Ok(Ipv4RouteTarget),

            (AFI::Ipv4, SAFI::FlowSpec) => Ok(Ipv4FlowSpec),
            (AFI::Ipv6, SAFI::FlowSpec) => Ok(Ipv6FlowSpec),

            (AFI::L2Vpn, SAFI::Vpls) => Ok(L2VpnVpls),
            (AFI::L2Vpn, SAFI::Evpn) => Ok(L2VpnEvpn),
            _ => Err("unsupported AFI/SAFI combination")
        }
    }
}

impl AfiSafi {
    pub fn afi(&self) -> AFI {
        self.split().0
    }

    pub fn safi(&self) -> SAFI {
        self.split().1
    }

    pub fn split(&self) -> (AFI, SAFI) {
        match self {
            Self::Ipv4Unicast => (AFI::Ipv4, SAFI::Unicast),
            Self::Ipv6Unicast => (AFI::Ipv6, SAFI::Unicast),
            Self::Ipv4Multicast => (AFI::Ipv4, SAFI::Multicast),
            Self::Ipv6Multicast => (AFI::Ipv6, SAFI::Multicast),

            Self::Ipv4MplsUnicast => (AFI::Ipv4, SAFI::MplsUnicast),
            Self::Ipv6MplsUnicast => (AFI::Ipv6, SAFI::MplsUnicast),

            Self::Ipv4MplsVpnUnicast => (AFI::Ipv4, SAFI::MplsVpnUnicast),
            Self::Ipv6MplsVpnUnicast => (AFI::Ipv6, SAFI::MplsVpnUnicast),

            Self::Ipv4RouteTarget => (AFI::Ipv4, SAFI::RouteTarget),

            Self::Ipv4FlowSpec => (AFI::Ipv4, SAFI::FlowSpec),
            Self::Ipv6FlowSpec => (AFI::Ipv6, SAFI::FlowSpec),

            Self::L2VpnVpls => (AFI::L2Vpn, SAFI::Vpls),
            Self::L2VpnEvpn => (AFI::L2Vpn, SAFI::Evpn),
        }
    }
}

impl fmt::Display for AfiSafi {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Ipv4Unicast => write!(f, "Ipv4Unicast"),
            Self::Ipv6Unicast => write!(f, "Ipv6Unicast"),
            Self::Ipv4Multicast => write!(f, "Ipv4Multicast"),
            Self::Ipv6Multicast => write!(f, "Ipv6Multicast"),

            Self::Ipv4MplsUnicast => write!(f, "Ipv4MplsUnicast"),
            Self::Ipv6MplsUnicast => write!(f, "Ipv6MplsUnicast"),

            Self::Ipv4MplsVpnUnicast => write!(f, "Ipv4MplsVpnUnicast"),
            Self::Ipv6MplsVpnUnicast => write!(f, "Ipv6MplsVpnUnicast"),

            Self::Ipv4RouteTarget => write!(f, "Ipv4RouteTarget"),

            Self::Ipv4FlowSpec => write!(f, "Ipv4FlowSpec"),
            Self::Ipv6FlowSpec => write!(f, "Ipv6FlowSpec"),

            Self::L2VpnVpls => write!(f, "L2VpnVpls"),
            Self::L2VpnEvpn => write!(f, "L2VpnEvpn"),
        }

    }
}


#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AddpathFamDir(AfiSafi, AddpathDirection);
impl AddpathFamDir {
    pub fn new(afisafi: AfiSafi, apd: AddpathDirection) -> Self {
        Self(afisafi, apd)
    }

    pub fn merge(&self, other: Self) -> Option<Self> {
        if self.0 != other.0 {
            return None;
        }
        self.1.merge(other.1).map(|dir| Self::new(self.0, dir))
    }

    pub fn fam(&self) -> AfiSafi {
        self.0
    }

    pub fn dir(&self) -> AddpathDirection {
        self.1
    }
}

#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum AddpathDirection {
    Receive = 1,
    Send = 2,
    SendReceive = 3,
}

impl AddpathDirection {
    pub fn merge(&self, other: Self) -> Option<Self> {
        match (self, other) {
            (Self::Receive, Self::Receive) => None,
            (Self::Send, Self::Send) => None,
            (Self::SendReceive, Self::SendReceive) => Some(Self::SendReceive),
            (Self::Send, Self::Receive | Self::SendReceive) => Some(Self::Send),
            (Self::Receive, Self::Send | Self::SendReceive) => Some(Self::Receive),
            (Self::SendReceive, Self::Send) => Some(Self::Receive),
            (Self::SendReceive, Self::Receive) => Some(Self::Send),
        }
    }
}

impl TryFrom<u8> for AddpathDirection {
    type Error = &'static str;
    fn try_from(u: u8) -> Result<Self, Self::Error> {
        match u {
            1 => Ok(Self::Receive),
            2 => Ok(Self::Send),
            3 => Ok(Self::SendReceive),
            _ => Err("invalid ADDPATH send/receive value")
        }
    }

}


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
    //Evpn(IpAddr),
    Unimplemented(AFI, SAFI),
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

            Ipv4MplsVpnUnicast => Self::Ipv4MplsVpnUnicast(
                RouteDistinguisher::zeroes(),
                Ipv4Addr::from(0)
            ),
            Ipv6MplsVpnUnicast => Self::Ipv6MplsVpnUnicast(
                RouteDistinguisher::zeroes(),
                Ipv6Addr::from(0)
            ),

            Ipv4RouteTarget => Self::Unicast(Ipv4Addr::from(0).into()),

            Ipv4FlowSpec | Ipv6FlowSpec => Self::Empty,

            L2VpnVpls => Self::Unicast(Ipv4Addr::from(0).into()),
            L2VpnEvpn => Self::Unicast(Ipv4Addr::from(0).into()),
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
            //Self::Evpn(ip) => write!(f, "evpn-{}", ip),
            Self::Unimplemented(afi, safi) => write!(f, "unimplemented for AFI {} /SAFI {}", afi, safi),
        }
    }
}
