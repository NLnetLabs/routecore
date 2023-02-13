use crate::typeenum; // from util::macros
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::bgp::message::nlri::RouteDistinguisher;

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

typeenum!(
/// AFI as used in BGP OPEN and UPDATE messages.
    AFI, u16,
    1 => Ipv4,
    2 => Ipv6,
    25 => L2Vpn,
);

typeenum!(
/// SAFI as used in BGP OPEN and UPDATE messages.
    SAFI, u8,
    1 => Unicast,
    2 => Multicast,
    4 => MplsUnicast,
    65 => Vpls,
    70 => Evpn,
    128 => MplsVpnUnicast,
    132 => RouteTarget,
    133 => FlowSpec,
    134 => FlowSpecVpn,
);

/// BGP Origin types as used in BGP UPDATE messages.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum OriginType {
    Igp,
    Egp,
    Incomplete,
    Unknown(u8),
}

typeenum!(
/// PathAttributeType
///
/// As per:
/// <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-2>
    PathAttributeType, u8,
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
    128 => AttrSet,
    255 => RsrvdDevelopment,
);

/// Wrapper for the 4 byte Multi-Exit Discriminator in path attributes.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct MultiExitDisc(pub u32);

/// Wrapper for the 4 byte Local Preference value in path attributes.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct LocalPref(pub u32);

/// Conventional and BGP-MP Next Hop variants.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum NextHop {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Ipv6LL(Ipv6Addr, Ipv6Addr),
    Ipv4MplsVpnUnicast(RouteDistinguisher, Ipv4Addr),
    Ipv6MplsVpnUnicast(RouteDistinguisher, Ipv6Addr),
    Empty, // FlowSpec
    Unimplemented(AFI, SAFI),
}

