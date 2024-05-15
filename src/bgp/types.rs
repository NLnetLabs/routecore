use std::fmt;
use std::net::Ipv4Addr;


#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

use inetnum::asn::Asn;
pub use crate::bgp::nlri::afisafi::Afi;
pub use crate::bgp::nlri::common::PathId;
pub use crate::bgp::nlri::mpls_vpn::RouteDistinguisher;
pub use crate::bgp::nlri::nexthop::NextHop;
use crate::typeenum; // from util::macros

use super::aspath::HopPath;
use super::path_attributes::AggregatorInfo;


pub use crate::bgp::nlri::afisafi::AfiSafiType as AfiSafi;


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

impl From<AddpathDirection> for u8 {
    fn from(apd: AddpathDirection) -> u8 {
        match apd {
            AddpathDirection::Receive => 1,
            AddpathDirection::Send => 2,
            AddpathDirection::SendReceive => 3,
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
        3 => ConventionalNextHop,
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
        35 => Otc,
        128 => AttrSet,
        255 => RsrvdDevelopment
    }
);

/// Wrapper for the 1 byte Origin.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Origin(pub OriginType);

impl From<OriginType> for Origin {
    fn from(t: OriginType) -> Origin {
        Origin(t)
    }
}

impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Wrapper for the 4 byte Multi-Exit Discriminator in path attributes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MultiExitDisc(pub u32);

impl std::fmt::Display for MultiExitDisc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Wrapper for the 4 byte Local Preference value in path attributes.
#[derive(Debug, Eq, PartialEq, Clone, Copy, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LocalPref(pub u32);

impl From<LocalPref> for u32 {
    fn from(value: LocalPref) -> Self {
        value.0
    }
}

impl std::fmt::Display for LocalPref {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}


#[derive(Debug, Eq, PartialEq, Clone, Copy, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AtomicAggregate;

/// Wrapper for the 4 byte OnlyToCustomer (Otc) value in path attributes.
#[derive(Debug, Eq, PartialEq, Clone, Copy, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Otc(pub Asn);

impl From<Otc> for u32 {
    fn from(value: Otc) -> Self {
        value.0.into()
    }
}

impl std::fmt::Display for Otc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Conventional NextHop only, this gets stored in the
/// `PathAttribute::ConventionalNextHop` variant.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ConventionalNextHop(pub Ipv4Addr);

impl std::fmt::Display for ConventionalNextHop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OriginatorId(pub Ipv4Addr);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Connector(pub Ipv4Addr);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct As4Path(pub HopPath);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct As4Aggregator(pub AggregatorInfo);
