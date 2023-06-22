//! Structs and helpers for everything related to various flavours of BGP
//! communities.
//!
//! There is support for
//!  * Standard Communities, RFC1997, including well-known communities,
//!  * Extended Communities, RFC4360
//!  * IPv6 Extended Communities, RFC5701
//!  * Large Communities, RFC8092 
//!
//! **N.B.**: for Extended Communities, the constructors and pretty printing
//! is limited to mostly the Route Target / Route Origin subtypes. Though
//! all others can be constructed using raw bytes for input.
//!
//! # Basic usage
//!
//! The main enum [`Community`] comprises the supported variants. It can be
//! created from raw byte arrays, where the specific variant is determined by
//! the length of the array. Or, it can be parsed from strings, where it
//! attempts to parse as a StandardCommunity first, then LargeCommunity,
//! ExtendedCommunity, and finally Ipv6ExtendedCommunity.
//!
//! A few convenience methods are available on `Community` itself, most
//! notably [`asn()`](`Community::asn()`) which returns the [`Asn`] in the
//! Global Administrator part, if any.
//! Other methods include `as_ref()` returning the underlying raw byte array
//! and [`to_wellknown()`](`Community::to_wellknown()`).
//!
//! ```
//! use routecore::asn::Asn;
//! use routecore::bgp::communities::Community;
//! use std::str::FromStr;
//!
//! let c = Community::from_str("AS1234:7890").unwrap();
//! assert!(matches!(c, Community::Standard(_)));
//! let lc = Community::from_str("123:456:789").unwrap();
//! assert!(matches!(lc, Community::Large(_)));
//!
//! assert_eq!(c.asn(), Some(Asn::from_u32(1234)));
//! assert_eq!(lc.asn(), Some(Asn::from_u32(123)));
//!
//! ```
//!
//! Or specific variants can be created explicitly:
//!
//! ```
//! use routecore::bgp::communities::{Community, StandardCommunity, Wellknown};
//! use std::str::FromStr;
//!
//! // Specific community variants can be created by parsing strings of
//! // canonical notations, hexadecimal representations, or raw input:
//! 
//! let c1 = StandardCommunity::from_str("AS1234:7890").unwrap();
//! assert_eq!(c1.to_raw(), [0x04, 0xD2, 0x1E, 0xD2]);
//!
//! let c2 = StandardCommunity::from_str("0x04D21ED2").unwrap();
//! assert_eq!(c1, c2);
//!
//! let c3 = StandardCommunity::from_raw([0x04, 0xD2, 0x1E, 0xD2]);
//! assert_eq!(c1, c3);
//!
//!
//!
//! ```
//!
//! # Well-known communities
//!
//! See [`Wellknown`] for a complete overview of supported parseable formats
//! for every well-known community.
//!
//! ```
//! # use routecore::bgp::communities::{Community, StandardCommunity, Wellknown};
//! # use std::str::FromStr;
//! #
//! // Well-known communities are of the StandardCommunity variant.
//! // These can be created from the Wellknown enum, or by parsing strings:
//!
//! let no_export1: StandardCommunity = Wellknown::NoExport.into();
//! let no_export2 = StandardCommunity::from_str("NO_EXPORT").unwrap().into();
//! assert_eq!(no_export1, no_export2);
//!
//! // The Display implementation for StandardCommunities in the well-known
//! // range will output their canonical names:
//!
//! assert_eq!(no_export1.to_string(), "NO_EXPORT");
//! assert_eq!(
//!     Wellknown::from_str("NoAdvertise").unwrap().to_string(),
//!     "NO_ADVERTISE"
//! );
//! ```

use const_str::convert_case;
use std::fmt::{self, Display, Error, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::asn::{Asn, Asn16, ParseAsnError};

//--- Community --------------------------------------------------------------

/// Standard and Extended/Large Communities variants.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, )]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum Community {
    Standard(StandardCommunity),
    Extended(ExtendedCommunity),
    Ipv6Extended(Ipv6ExtendedCommunity),
    Large(LargeCommunity),
    //Container, // for Wide communities, still in IETF draft
}

impl Community {
    pub fn to_wellknown(self) -> Option<Wellknown> {
        match self {
            Community::Standard(sc) => sc.to_wellknown(),
            _ => None
        }
    }

    pub fn asn(self) -> Option<Asn> {
        use Community::*;
        match self {
            Standard(sc) => sc.asn(),
            Extended(e) => {
                e.as2().map(|a| a.into_asn32()).or_else(|| e.as4())
            }
            Ipv6Extended(_) => None, 
            Large(lc) => Some(lc.global().into()),
        }
    }
}

// AsRef

impl AsRef<[u8]> for Community {
    fn as_ref(&self) -> &[u8] {
        match self {
            Community::Standard(c) => c.as_ref(),
            Community::Extended(c) => c.as_ref(),
            Community::Ipv6Extended(c) => c.as_ref(),
            Community::Large(c) => c.as_ref(),
        }
    }
}

// From / FromStr

impl From<[u8; 4]> for Community {
    fn from(raw: [u8; 4]) -> Community {
        Community::Standard(StandardCommunity(raw))
    }
}

impl From<StandardCommunity> for Community {
    fn from(sc: StandardCommunity) -> Self {
        Community::Standard(sc)
    }
}

impl From<Wellknown> for Community {
    fn from(wk: Wellknown) -> Self {
        Community::Standard(wk.into())
    }
}

impl From<ExtendedCommunity> for Community {
    fn from(ec: ExtendedCommunity) -> Self {
        Community::Extended(ec)
    }
}

impl From<Ipv6ExtendedCommunity> for Community {
    fn from(ec: Ipv6ExtendedCommunity) -> Self {
        Community::Ipv6Extended(ec)
    }
}

impl From<LargeCommunity> for Community {
    fn from(lc: LargeCommunity) -> Self {
        Community::Large(lc)
    }
}

// There seems to be no case where we sensibly can 'upgrade' to another type
// of community if the input does not fit in a Standard Community: if the
// input contains a 32 bit AS, creating a Large Community leaves 6 bytes to be
// guessed. Similarly, an Extended Community leaves 2 bytes to be guessed.
impl FromStr for Community {
    type Err = ParseError;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(sc) = StandardCommunity::from_str(s) {
            return Ok(Community::Standard(sc))
        }
        if let Ok(lc) = LargeCommunity::from_str(s) {
            return Ok(Community::Large(lc))
        }
        if let Ok(ec) = ExtendedCommunity::from_str(s) {
            return Ok(Community::Extended(ec))
        }
        if let Ok(ec6) = Ipv6ExtendedCommunity::from_str(s) {
            return Ok(Community::Ipv6Extended(ec6))
        }
        Err(ParseError("can't parse"))
    }
}


impl Display for Community {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        match self {
            Community::Standard(c) => Display::fmt(c, f),
            Community::Extended(c) => Display::fmt(c, f),
            Community::Ipv6Extended(c) => Display::fmt(c, f),
            Community::Large(c) => Display::fmt(c, f),
        }
    }
}

//--- Wellknown --------------------------------------------------------------

macro_rules! wellknown {
    ($name:ident,
        $($hex:expr => $var:ident, $pprim:expr $(,$psec:expr)* ;)+
    )
    => {

        #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd )]
        /// Well-known communities as registered by IANA.
        ///
        /// | u32 | enum variant | prints as / parses from | alternative parses from |
        /// | --- | ---          | ---                     | ---                     |
        $(#[doc = concat!(
           "|", stringify!($hex),
           "|", stringify!($var),
           "|", $pprim,
           "|", $($psec,)*
           "|")])+

        pub enum $name {
            $(
            $var),+,
            Unrecognized(u16)
        }
        
        impl $name {

            pub fn to_u32(self) -> u32 {
                match self {
                    $($name::$var => $hex,)+
                    $name::Unrecognized(n) => (0xffff0000_u32 | n as u32)
                }
            }

            pub fn from_u16(n: u16) -> $name {
                match (0xffff0000_u32 | n as u32) {
                    $($hex => $name::$var,)+
                    _ => $name::Unrecognized(n)
                }
            }

            pub fn into_standard(self) -> StandardCommunity {
                self.into()
            }
        }

        impl From<u16> for $name {
            fn from(n: u16) -> $name {
                match (0xffff0000_u32 | n as u32) {
                    $($hex => $name::$var,)+
                    _ => $name::Unrecognized(n)
                }
            }
        }
        
        impl TryFrom<u32> for $name {
            type Error = ParseError;

            fn try_from(n: u32) -> Result<Self, ParseError> {
                if n & 0xffff0000 != 0xffff0000 {
                    return Err(ParseError("not in Wellknown range"))
                }
                Ok(Self::from_u16(n as u16)) // XXX is this correct in all
                                             // cases? does endianness come
                                             // into play here?
            }
        }
        
        impl FromStr for $name {
            type Err = ParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let s = s.to_lowercase();
                match s.as_str() {
                    $(
                        convert_case!(lower, $pprim)
                        $(
                        |convert_case!(lower, $psec)
                        )* => Ok($name::$var),
                        // until inline consts on pattern position are
                        // allowed, we abuse a match arm:
                        _ if s == stringify!($var).to_lowercase()
                            => Ok($name::$var),
                    )+
                    _ => Err(ParseError("cant parse"))
                }
            }
        }

        impl Display for $name {
            fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
                match self {
                    $($name::$var => write!(f, $pprim),)+
                    $name::Unrecognized(n) => write!(f, "0x{:08X}", n)
                }
            }
        }
    };
}

// Calling the macro generates an enum `Wellknown` with variants based on the
// name directly after the '=>'. FromStr is implemented to parse that name,
// and all the variants given in the list until the ;
// For the Display implementation, the first of that list is used.
// E.g. Wellknown::AcceptOwnNexthop can be parsed from "AcceptOwnNexthop",
// "accept-own-nexthop", "ACCEPT_OWN_NEXTHOP", and will be printed as
// "accept-own-nexthop".
wellknown!(Wellknown,
    0xFFFF0000 => GracefulShutdown, "GRACEFUL_SHUTDOWN";
    0xFFFF0001 => AcceptOwn, "ACCEPT_OWN";
    0xFFFF0002 => RouteFilterTranslatedV4, "ROUTE_FILTER_TRANSLATED_v4";
    0xFFFF0003 => RouteFilterV4, "ROUTE_FILTER_v4";
    0xFFFF0004 => RouteFilterTranslatedV6, "ROUTE_FILTER_TRANSLATED_v6";
    0xFFFF0005 => RouteFilterV6, "ROUTE_FILTER_v6";
    0xFFFF0006 => LlgrStale, "LLGR_STALE";
    0xFFFF0007 => NoLlgr, "NO_LLGR";
    0xFFFF0008 => AcceptOwnNexthop, "accept-own-nexthop", "ACCEPT_OWN_NEXTHOP";
    0xFFFF0009 => StandbyPe, "Standby PE", "standby-pe";

    0xFFFFFF01 => NoExport, "NO_EXPORT";
    0xFFFFFF02 => NoAdvertise, "NO_ADVERTISE";
    0xFFFFFF03 => NoExportSubconfed, "NO_EXPORT_SUBCONFED";
    0xFFFFFF04 => NoPeer, "NOPEER", "NO_PEER";

    0xFFFF029A => Blackhole, "BLACKHOLE";
);



//--- StandardCommunity ------------------------------------------------------

/// Conventional, RFC1997 4-byte community.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd )]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct StandardCommunity([u8; 4]);

impl StandardCommunity {
    pub fn new(asn: Asn16, tag: Tag) -> StandardCommunity {
        let a = asn.to_raw();
        let t = tag.to_raw();
        StandardCommunity([a[0], a[1], t[0], t[1]])
    }

    pub fn from_raw(raw: [u8; 4]) -> Self {
        Self(raw)
    }

    pub fn from_wellknown(wk: Wellknown) -> StandardCommunity {
        StandardCommunity::from_u32(wk.to_u32())
    }

    pub fn from_u32(raw: u32) -> StandardCommunity {
        StandardCommunity(raw.to_be_bytes())
    }

    pub fn to_u32(self) -> u32 {
        u32::from_be_bytes(self.0)
    }

    pub fn to_raw(self) -> [u8; 4] {
        self.0
    }

    // Methods for non well-known communities.
    // At least some routeservers seem to use the reserved 0:xxx,
    // for those we'll simply return the Asn for 0.

    // XXX so should this return an Asn, or an Asn16?
    pub fn asn(self) -> Option<Asn> {
        if !self.is_wellknown() {
            Some(Asn::from_u32(
                    u16::from_be_bytes([self.0[0], self.0[1]]) as u32
                ))
        } else {
            None
        }
    }

    pub fn tag(self) -> Option<Tag>{
        if !self.is_wellknown() {
            Some(Tag(u16::from_be_bytes([self.0[2], self.0[3]])))
        } else {
            None
        }
    }

    pub fn is_private(self) -> bool {
        !matches!(self.0, [0xff, 0xff, _, _] | [0x00, 0x00, _, _])
    }


    pub fn is_wellknown(self) -> bool {
        matches!(self.0, [0xff, 0xff, _, _])
    }

    pub fn to_wellknown(self) -> Option<Wellknown> {
        Wellknown::try_from(self.to_u32()).ok()
        //if self.is_wellknown() {
        //    Some(Wellknown::from_u32(self.to_u32()))
        //} else {
        //    None
        //}
    }

    pub fn is_reserved(self) -> bool {
        matches!(self.0, [0x00, 0x00, _, _])
    }
}

// AsRef

impl AsRef<[u8]> for StandardCommunity {
    fn as_ref(&self) -> &[u8] {
        &(self.0)
    }
}

// From / FromStr

impl From<[u8; 4]> for StandardCommunity {
    fn from(raw: [u8; 4]) -> StandardCommunity {
        StandardCommunity(raw)
    }
}

impl From<u32> for StandardCommunity {
    fn from(n: u32) -> StandardCommunity {
        StandardCommunity::from_u32(n)
    }
}

impl From<Wellknown> for StandardCommunity {
    fn from(wk: Wellknown) -> Self {
        StandardCommunity::from_u32(wk.to_u32())
    }
}


impl FromStr for StandardCommunity {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(wk) = Wellknown::from_str(s) {
            return Ok(wk.into());
        }
        if let Some((a, t)) = s.split_once(':') {
            let asn = Asn16::from_str(a)?;
            let tagv = u16::from_str(t).map_err(|_e| "cant parse Tag")?;
            Ok(StandardCommunity::new(asn, Tag(tagv)))
        } else if let Some(hex) = s.strip_prefix("0x") {
            if let Ok(hex) = u32::from_str_radix(hex, 16) {
                Ok(StandardCommunity(hex.to_be_bytes()))
            } else {
                Err("invalid hex".into())
            }

        } else {
            Err("failed FromStr for StandardCommunity".into())
        }
    }
}

// Display

// We only distinguish between Wellknown or not.
// The reserved 0x0000xxxx we print as AS0:xxxx, as it is used by route
// servers and obscuring it by printing as pure hex or whatever does not help
// anybody.
impl Display for StandardCommunity {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        if let Some(wk) = self.to_wellknown() {
            write!(f, "{}", wk)
        } else { 
            write!(f, "{}:{}", &self.asn().unwrap(), &self.tag().unwrap())
        }
    }

}


/// Final two octets of a [`StandardCommunity`], i.e. the 'community number'.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd )]
pub struct Tag(u16);

impl Tag {
    pub fn new(t: u16) -> Self {
        Self(t)
    }

    pub fn value(self) -> u16 {
        self.0
    }

    pub fn to_raw(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

impl Display for Tag {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{}", self.0)
    }
}

//--- ExtendedCommunity ------------------------------------------------------

/// Extended Community as defined in RFC4360.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd )]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ExtendedCommunity([u8; 8]);

impl ExtendedCommunity {

    pub fn from_raw(raw: [u8; 8]) -> Self {
        Self(raw)
    }

    pub fn raw(self) -> [u8; 8] {
        self.0
    }

    pub fn type_raw(self) -> u8 {
        self.0[0]
    }

    pub fn types(self) -> (ExtendedCommunityType, ExtendedCommunitySubType) {
        use ExtendedCommunityType::*;
        use ExtendedCommunitySubType::*;
        match self.0[0..2] { // XXX maybe a tuple is faster?
            // Transitive types
            [0x00, 0x02] => (TransitiveTwoOctetSpecific, RouteTarget),
            [0x00, 0x03] => (TransitiveTwoOctetSpecific, RouteOrigin),
            [0x00, b]    => (TransitiveTwoOctetSpecific, OtherSubType(b)),

            [0x01, 0x02] => (TransitiveIp4Specific, RouteTarget),
            [0x01, 0x03] => (TransitiveIp4Specific, RouteOrigin),
            [0x01, b]    => (TransitiveIp4Specific, OtherSubType(b)),

            [0x02, 0x02] => (TransitiveFourOctetSpecific, RouteTarget),
            [0x02, 0x03] => (TransitiveFourOctetSpecific, RouteOrigin),
            [0x02, b]    => (TransitiveFourOctetSpecific, OtherSubType(b)),

            [0x03, b]    => (TransitiveOpaque, OtherSubType(b)),

            // Non-transitive types

            [0x40, b]    => (NonTransitiveTwoOctetSpecific, OtherSubType(b)),

            [0x41, b]    => (NonTransitiveIp4Specific, OtherSubType(b)),

            [0x42, b]    => (NonTransitiveFourOctetSpecific, OtherSubType(b)),

            [0x43, 0x02] => (NonTransitiveOpaque, RouteTarget),
            [0x43, b]    => (NonTransitiveOpaque, OtherSubType(b)),


            // Catch-all

            _ => (OtherType(self.0[0]), OtherSubType(self.0[0]))
        }
    }

    pub fn is_transitive(self) -> bool {
        // Transitive bit 0 means the community is transitive
        self.type_raw() & 0x40 == 0x00
    }

    //--- route target constructors ------------------------------------------
    // Transitive two-octet AS specific
    pub fn transitive_as2_route_target(global: Asn16, local: u32) -> Self {
        let g = global.to_raw();
        let l = local.to_be_bytes();
        ExtendedCommunity([
            0x00, 0x02,
            g[0], g[1],
            l[0], l[1], l[2], l[3]
        ])
    }

    // Transitive four-octet AS specific
    pub fn transitive_as4_route_target(global: Asn, local: u16) -> Self {
        let g = global.to_raw();
        let l = local.to_be_bytes();
        ExtendedCommunity([
            0x02, 0x02,
            g[0], g[1], g[2], g[3],
            l[0], l[1]
        ])
    }

    //  Transitive ipv4-addr specific
    pub fn transitive_ip4_route_target(global: Ipv4Addr, local: u16) -> Self {
        let g = global.octets();
        let l = local.to_be_bytes();
        ExtendedCommunity([
            0x01, 0x02,
            g[0], g[1], g[2], g[3],
            l[0], l[1]
        ])
    }

    // Non-Transitive Opaque 
    pub fn non_transitive_opaque_route_target(v: [u8; 6]) -> Self {
        ExtendedCommunity([
            0x43, 0x02,
            v[0], v[1], v[2], v[3], v[4], v[5]
        ])
    }

    //--- route origin constructors ------------------------------------------

    pub fn transitive_as2_route_origin(global: Asn16, local: u32) -> Self {
        let g = global.to_raw();
        let l = local.to_be_bytes();
        ExtendedCommunity([
            0x00, 0x03,
            g[0], g[1],
            l[0], l[1], l[2], l[3]
        ])
    }

    // transitive four-octet AS specific
    pub fn transitive_as4_route_origin(global: Asn, local: u16) -> Self {
        let g = global.to_raw();
        let l = local.to_be_bytes();
        ExtendedCommunity([
            0x02, 0x03,
            g[0], g[1], g[2], g[3],
            l[0], l[1]
        ])
    }

    //  transitive ipv4-addr specific
    pub fn transitive_ip4_route_origin(global: Ipv4Addr, local: u16) -> Self {
        let g = global.octets();
        let l = local.to_be_bytes();
        ExtendedCommunity([
            0x01, 0x03,
            g[0], g[1], g[2], g[3],
            l[0], l[1]
        ])
    }

    // getters for specific types

    pub fn as2(self) -> Option<Asn16> {
        use ExtendedCommunityType::*;
        match self.types() {
            (TransitiveTwoOctetSpecific |
             NonTransitiveTwoOctetSpecific, _) =>
                Some(Asn16::from_u16(
                    u16::from_be_bytes(self.0[2..4].try_into().unwrap())
                )),
            _ => None
        }
    }

    pub fn as4(self) -> Option<Asn> {
        use ExtendedCommunityType::*;
        match self.types() {
            (TransitiveFourOctetSpecific |
             NonTransitiveFourOctetSpecific, _) =>
                Some(Asn::from_u32(
                    u32::from_be_bytes(self.0[2..6].try_into().unwrap())
                )),
            _ => None
        }
    }

    pub fn ip4(self) -> Option<Ipv4Addr> {
        use ExtendedCommunityType::*;
        match self.types() {
            (TransitiveIp4Specific |
             NonTransitiveIp4Specific, _) =>
                Some(
                    Ipv4Addr::from(<&[u8] as TryInto<[u8; 4]>>::try_into(
                            &self.0[2..6]
                    ).unwrap())
                ),
            _ => None
        }
    }


    // useable for types where the global administrator part is 4 of the 6
    // value bytes, i.e. ip4 and 4-octet specific types
    pub fn an2(self) -> Option<u16> {
        use ExtendedCommunityType::*;
        match self.types() {
            (TransitiveIp4Specific |
             NonTransitiveIp4Specific |
             TransitiveFourOctetSpecific |
             NonTransitiveFourOctetSpecific, _) =>
                Some(
                    u16::from_be_bytes(self.0[6..8].try_into().unwrap())
                ),
            _ => None
        }
    }

    // useable for types where the global administrator part is 2 of the 6
    // value bytes, i.e. 2-octet specific types
    pub fn an4(self) -> Option<u32> {
        use ExtendedCommunityType::*;
        match self.types() {
            (TransitiveTwoOctetSpecific | NonTransitiveTwoOctetSpecific, _) =>
                Some(
                    u32::from_be_bytes(self.0[4..8].try_into().unwrap())
                ),
            _ => None
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd )]
pub enum ExtendedCommunityType {
    TransitiveTwoOctetSpecific,
    TransitiveIp4Specific,
    TransitiveFourOctetSpecific,
    TransitiveOpaque,
    NonTransitiveTwoOctetSpecific,
    NonTransitiveIp4Specific,
    NonTransitiveFourOctetSpecific,
    NonTransitiveOpaque,
    OtherType(u8)
}

#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd )]
// TODO add 0x0b for TransitiveOpaque, Color (RFC 9012) ?
pub enum ExtendedCommunitySubType {
    RouteTarget,
    RouteOrigin,
    OtherSubType(u8),
}

// AsRef

impl AsRef<[u8]> for ExtendedCommunity {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// From / FromStr

impl From<[u8; 8]> for Community {
    fn from(raw: [u8; 8]) -> Community {
        Community::Extended(ExtendedCommunity(raw))
    }
}


impl FromStr for ExtendedCommunity {
    type Err = ParseError;
    
    // 'canonical' representations include:
    // rt:AS:AN
    // ro:AS:AN
    // XXX some inputs might be ambiguous here:
    // take rt:123:123. With both the numbers fitting in a u16, what type of
    // Extended Community should we return, 2-octet AS specific or 4-octet AS
    // specific?
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((tag, tail)) = s.split_once(':') {
            match tag {
                "rt" => {
                    let (ga, an) = tail.split_once(':')
                        .ok_or("expected ':'")?;
                    // XXX do we want to force/allow an AS prefix here?
                    // e.g. rt:AS1234:789 ?
                    let ga = strip_as(ga);
                    if let Ok(as2) = u16::from_str(ga) {
                        Ok(Self::transitive_as2_route_target(
                            as2.into(),
                            u32::from_str(an).map_err(|_| "illegal u32")?
                        ))
                    } else if let Ok(as4) = u32::from_str(ga) {
                        Ok(Self::transitive_as4_route_target(
                            as4.into(),
                            u16::from_str(an).map_err(|_| "illegal u16")?
                        ))
                    } else if let Ok(ip4) = Ipv4Addr::from_str(ga) {
                        Ok(Self::transitive_ip4_route_target(
                                ip4,
                                u16::from_str(an).map_err(|_| "illegal u16")?
                        ))
                    } else {
                        Err("invalid rt:AS:AN".into())
                    }
                },
            "ro" => {
                    let (ga, an) = tail.split_once(':')
                        .ok_or("expected ':'")?;
                    // XXX do we want to force/allow an AS prefix here?
                    // e.g. rt:AS1234:789 ?
                    let ga = strip_as(ga);
                    if let Ok(as2) = u16::from_str(ga) {
                        Ok(Self::transitive_as2_route_origin(
                            as2.into(),
                            u32::from_str(an).map_err(|_| "illegal u32")?
                        ))
                    } else if let Ok(as4) = u32::from_str(ga) {
                        Ok(Self::transitive_as4_route_origin(
                            as4.into(),
                            u16::from_str(an).map_err(|_| "illegal u16")?
                        ))
                    } else if let Ok(ip4) = Ipv4Addr::from_str(ga) {
                        Ok(Self::transitive_ip4_route_origin(
                                ip4,
                                u16::from_str(an).map_err(|_| "illegal u16")?
                        ))
                    } else {
                        Err("invalid rt:AS:AN".into())
                    }
                },
            _ => { Err(ParseError("unknown tag")) }
            }
        } else if let Some(hex) = s.strip_prefix("0x") {
            if let Ok(hex) = u64::from_str_radix(hex, 16) {
                Ok(ExtendedCommunity(hex.to_be_bytes()))
            } else {
                Err("invalid hex".into())
            }
        } else {
            Err("fail".into())
        }
    }
}

// Display

impl Display for ExtendedCommunity {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        use ExtendedCommunityType::*;
        use ExtendedCommunitySubType::*;

        match self.types() {
            // Route Target
 
            (TransitiveTwoOctetSpecific, RouteTarget) =>   
                write!(f, "rt:{}:{}",
                       &self.as2().unwrap(), &self.an4().unwrap()
                      ),
            (TransitiveIp4Specific, RouteTarget) =>   
                write!(f, "rt:{}:{}",
                       &self.ip4().unwrap(), &self.an2().unwrap()
                      ),
            (TransitiveFourOctetSpecific, RouteTarget) =>   
                write!(f, "rt:{}:{}",
                       &self.as4().unwrap(), &self.an2().unwrap()
                      ),
            (NonTransitiveOpaque, RouteTarget) => {
                write!(f, "rt:")?;
                for b in &self.as_ref()[2..8] {
                    write!(f, "{:x}", b)?;
                }
                Ok(())
            },

            // Route Origin

            (TransitiveTwoOctetSpecific, RouteOrigin) =>   
                write!(f, "ro:{}:{}",
                       &self.as2().unwrap(), &self.an4().unwrap()
                      ),
            (TransitiveIp4Specific, RouteOrigin) =>   
                write!(f, "ro:{}:{}",
                       &self.ip4().unwrap(), &self.an2().unwrap()
                      ),
            (TransitiveFourOctetSpecific, RouteOrigin) =>   
                write!(f, "ro:{}:{}",
                       &self.as4().unwrap(), &self.an2().unwrap()
                      ),


            // Catch-all
            
            (_,_) => {
                write!(f, "0x")?;
                for b in &self.raw() {
                    write!(f, "{:02X}", b)?;
                }
                Ok(())
            }
        }
    }
}


//--- Ipv6ExtendedCommunity --------------------------------------------------

/// IPv6 Extended Community as defined in RFC5701.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd )]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Ipv6ExtendedCommunity([u8; 20]);


impl Ipv6ExtendedCommunity {
    pub fn from_raw(raw: [u8; 20]) -> Self {
        Self(raw)
    }

    pub fn raw(self) -> [u8; 20] {
        self.0
    }

    pub fn type_raw(self) -> u8 {
        self.0[0]
    }

    pub fn is_transitive(self) -> bool {
        // Transitive bit 0 means the community is transitive
        self.type_raw() & 0x40 == 0x00
    }

    pub fn ip6(self) -> Ipv6Addr {
        Ipv6Addr::from(
            <&[u8] as TryInto<[u8; 16]>>::try_into(&self.0[2..18])
            .expect("parsed before")
        )
    }
    pub fn an2(self) -> u16 {
        u16::from_be_bytes(self.0[18..20].try_into().unwrap())
    }

    // alias for an2
    pub fn local_admin(self) -> u16 {
        self.an2()
    }
}

// AsRef

impl AsRef<[u8]> for Ipv6ExtendedCommunity {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// From / FromStr


impl From<[u8; 20]> for Community {
    fn from(raw: [u8; 20]) -> Community {
        Community::Ipv6Extended(Ipv6ExtendedCommunity(raw))
    }
}

// XXX with ':' being part of IPv6 addresses, it is unclear what the canonical
// format is to write out IPv6 Extended Communities.
// We limit to parsing a hex value only for now.
// If we figure out the canonical format, add:
// - rt:ipv6:an2 case
// - ro:ipv6:an2 case
// TODO collect some testdata for this
impl FromStr for Ipv6ExtendedCommunity {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(hex) = s.strip_prefix("0x") {
            // 20 bytes should be 40 characters
            if hex.len() != 40 {
                return Err("expected hex value of length 40".into());
            }
            let mut buf = [0u8; 20];
            if let Ok(hex1) = u64::from_str_radix(&hex[0..16], 16) {
                buf[0..8].copy_from_slice(&hex1.to_be_bytes());
            } else {
                return Err("invalid hex".into());
            }
            if let Ok(hex2) = u64::from_str_radix(&hex[16..32], 16) {
                buf[8..16].copy_from_slice(&hex2.to_be_bytes());
            } else {
                return Err("invalid hex".into());
            }
            if let Ok(hex3) = u32::from_str_radix(&hex[32..40], 16) {
                buf[16..].copy_from_slice(&hex3.to_be_bytes());
            } else {
                return Err("invalid hex".into());
            }
            Ok(Ipv6ExtendedCommunity::from_raw(buf))
        }else {
            Err("expected hex value starting with 0x".into())
        }
    }
}

// Display

impl Display for Ipv6ExtendedCommunity {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        match self.0[0..2] {
            [0x00, 0x02] => write!(f, "rt:{}:{}",
                                &self.ip6(), &self.an2()
                            ),
            _ => {
                write!(f, "0x")?;
                self.raw().iter().for_each(|b|{
                    let _ = write!(f, "{:02x}", b);
                });
                Ok(())
            }
        }
    }
}

//--- LargeCommunity ---------------------------------------------------------

/// Large Community as defined in RFC8092.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd )]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct LargeCommunity([u8; 12]);

impl LargeCommunity {

    pub fn asn(self) -> Asn {
        Asn::from_u32(self.global())
    }
    
    pub fn from_raw(raw: [u8; 12]) -> Self {
        Self(raw)
    }

    pub fn raw(self) -> [u8; 12] {
        self.0
    }

    pub fn global(self) -> u32 {
        u32::from_be_bytes(self.0[0..4].try_into().unwrap())
    }

    pub fn local1(self) -> u32 {
        u32::from_be_bytes(self.0[4..8].try_into().unwrap())
    }

    pub fn local2(self) -> u32 {
        u32::from_be_bytes(self.0[8..12].try_into().unwrap())
    }
}

// AsRef

impl AsRef<[u8]> for LargeCommunity {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// From / FromStr


impl From<[u8; 12]> for Community {
    fn from(raw: [u8; 12]) -> Community {
        Community::Large(LargeCommunity(raw))
    }
}

impl FromStr for LargeCommunity {
    type Err = ParseError;

    // Canonical form is u32:u32:u32
    // but we allow AS12345:u32:u32 as well
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(3, ':');

        let ga = parts.next().ok_or("expected more parts")?;
        let ga = strip_as(ga);
        let ga = u32::from_str(ga)
            .map_err(|_| "failed to parse global admin part")?;

        let l1 = parts.next().ok_or("expected more parts")?;
        let l1 = u32::from_str(l1)
            .map_err(|_| "failed to parse local1 part")?;

        let l2 = parts.next().ok_or("expected more parts")?;
        let l2 = u32::from_str(l2)
            .map_err(|_| "failed to parse local2 part")?;

        Ok(LargeCommunity(
                [ga.to_be_bytes(), l1.to_be_bytes(), l2.to_be_bytes()]
                .concat().try_into().unwrap()
        ))
    }
}

// Display

impl Display for LargeCommunity {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{}:{}:{}", self.global(), self.local1(), self.local2())
    }

}

fn strip_as(s: &str) -> &str {
    s.strip_prefix("AS")
        .or_else(|| s.strip_prefix("as"))
        .or_else(|| s.strip_prefix("As"))
        .or_else(|| s.strip_prefix("aS"))
        .unwrap_or(s)
}

//--- Error ------------------------------------------------------------------

#[derive(Debug)]
pub struct ParseError(&'static str);
impl From<&'static str> for ParseError {
    fn from(s: &'static str) -> Self {
        Self(s)
    }
}

impl Display for ParseError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f,"{}",self.0)
    }
}
impl std::error::Error for ParseError {}


impl From<ParseAsnError> for ParseError {
    fn from(_: ParseAsnError) -> Self {
        Self("invalid AS number")
    }
}



//--- tests ------------------------------------------------------------------
#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn macro_based() {
        let sc = StandardCommunity::from_str("NO_EXPORT").unwrap();
        let sc2 = StandardCommunity::from_str("NoExport").unwrap();
        assert!(sc.is_wellknown());
        assert!(!sc.is_private());
        assert_eq!(sc, sc2);

        assert_eq!(sc.to_u32(), 0xFFFFFF01);
        assert_eq!(sc.to_raw(), [0xFF, 0xFF, 0xFF, 0x01]);

        //let noexp = Wellknown::NoExport();
        let noexp = StandardCommunity::from_wellknown(Wellknown::NoExport);
        assert!(noexp.is_wellknown());
        assert_eq!(noexp, sc);
        assert_eq!(noexp.to_u32(), 0xFFFFFF01);
        assert_eq!(noexp.to_raw(), [0xFF, 0xFF, 0xFF, 0x01]);

        let pr = StandardCommunity::new(Asn16::from_u16(1234), Tag(5555));
        assert!(!pr.is_wellknown());
        assert!(pr.is_private());
        assert!(pr != noexp);
    }

    #[test]
    fn display() {
        use Wellknown::*;
        println!("{}", StandardCommunity::from_wellknown(NoExport));
        println!("{}", StandardCommunity::from_wellknown(NoAdvertise));
        println!("{}", StandardCommunity::from_u32(0xffff1234));
        println!("{}", StandardCommunity::new(Asn16::from_u16(1234), Tag(5555)));
        println!("{}", StandardCommunity::from_str("AS1234:5678").unwrap());

        println!("{}", StandardCommunity::from_str("AS0:5678").unwrap());

        println!("{}", ExtendedCommunity::from_str("rt:AS1234:666").unwrap());
    }

    #[test]
    fn from_strs() {
        use Wellknown::*;
        StandardCommunity::from_str("AS1234:5678").unwrap();
        assert_eq!(
            StandardCommunity::from_wellknown(NoExport),
            StandardCommunity::from_str("NoExport").unwrap()
        );
        StandardCommunity::from_str("1234:890").unwrap();
        StandardCommunity::from_str("as1234:890").unwrap();
        StandardCommunity::from_str("As1234:890").unwrap();
        StandardCommunity::from_str("aS1234:890").unwrap();

        assert_eq!(
            StandardCommunity::from_str("aS1234:890").unwrap(),
            StandardCommunity::from_str("1234:890").unwrap(),
        );

        //fails
        StandardCommunity::from_str("ASxyz:890").unwrap_err();
        StandardCommunity::from_str("AS1234:xyz").unwrap_err();
        StandardCommunity::from_str("AS1234:xyz:zzz").unwrap_err();
        StandardCommunity::from_str("AS1234:1:2").unwrap_err();
        
    }

    #[test]
    fn from_raw() {
        assert_eq!(
            <Wellknown as Into<Community>>::into(Wellknown::NoExport),
            [0xff_u8, 0xff, 0xff, 0x01].into()
        );
        assert_eq!(
            StandardCommunity::from_str("AS100:666").unwrap(),
            [0x00_u8, 0x64, 0x02, 0x9a].into()
        );
    }

    #[test]
    fn types() {
        let c = StandardCommunity::from_u32(0x00112233);
        assert!(!c.is_wellknown());
        assert!(c.to_wellknown().is_none());

        let c2: StandardCommunity = Wellknown::NoExport.into();
        println!("{}", c2);
        assert!(c2 == Wellknown::NoExport.into());
        assert!(c2 == StandardCommunity::from_u32(0xFFFFFF01));
        assert!(c2.to_wellknown() == Some(Wellknown::NoExport));

        let c3: Community = Wellknown::NoExport.into();
        println!("{:?}", c3);
        assert!(matches!(c3, Community::Standard(_)));
        assert!(c3 == Community::Standard(StandardCommunity::from_u32(0xFFFFFF01)));
        assert!(c3 == Wellknown::NoExport.into());
        assert!(c3.to_wellknown() == Some(Wellknown::NoExport));

        let u = StandardCommunity::from_u32(0xFFFF9999);
        assert!(u.is_wellknown());
        assert!(u.to_wellknown().is_some());
        assert_eq!(u, Wellknown::Unrecognized(0x9999).into());
        println!("u: {}", u);

        let u = StandardCommunity::from_u32(0x00FF9999);
        assert!(!u.is_wellknown());
        assert!(u.to_wellknown().is_none());
        println!("u: {}", u);


    }

    #[test]
    fn large() {
        LargeCommunity::from_str("1234:1234:1234").unwrap();
        LargeCommunity::from_str("AS1234:1234:1234").unwrap();
        LargeCommunity::from_str("AS1234:0:0").unwrap();

        let _c: Community = LargeCommunity::from_str("AS1234:0:0")
            .unwrap().into();

        LargeCommunity::from_str("xyz:1234:1234").unwrap_err();
        LargeCommunity::from_str("1234:xyz:1234").unwrap_err();
        LargeCommunity::from_str("1234:1234:xyz").unwrap_err();
        LargeCommunity::from_str("1234:1234").unwrap_err();
        LargeCommunity::from_str("1234:1234:5:6").unwrap_err();

    }

    #[test]
    fn from_str() {
        assert!(matches!(
                Community::from_str("AS1234:999").unwrap(),
                Community::Standard(_)
        ));
        assert!(matches!(
                Community::from_str("NO_EXPORT").unwrap(),
                Community::Standard(_)
        ));
        assert!(match Community::from_str("NO_EXPORT").unwrap() {
                Community::Standard(sc) => sc.is_wellknown(),
                _ => false
        });

        assert!(
            if let Ok(Community::Standard(sc)) =
                Community::from_str("NO_EXPORT")
            {
                sc.is_wellknown()
            } else {
                false
            }
        );

        assert!(
            Community::from_str("nO_eXpOrT").is_ok()
        );

        assert_eq!(
                Community::from_str("No_Export").unwrap(),
                Community::from_str("NOEXPORT").unwrap()
        );

        Community::from_str("abc").unwrap_err();
    }

    #[test]
    fn ext_comms() {
        use ExtendedCommunity as EC;
        let ec1 = EC::transitive_as2_route_target(1234_u16.into(), 6789);
        println!("{}", ec1);
        let ec2 = EC::transitive_as4_route_target(1234_u32.into(), 6789);
        println!("{}", ec2);
        let ec3 = EC::transitive_ip4_route_target(
            Ipv4Addr::from_str("127.0.0.1").unwrap(), 6789
        );
        println!("{}", ec3);

        let ec4 = EC::from_raw([10, 10, 1, 2, 3, 4, 5, 6]);
        println!("{}", ec4);
        assert_eq!(
            ec4,
            EC::from_str("0x0A0A010203040506").unwrap()
            );


        // route target
        EC::from_str("rt:1:66000").unwrap();
        EC::from_str("rt:66000:3").unwrap();
        EC::from_str("rt:127.0.0.1:3").unwrap();

        EC::from_str("rt:12").unwrap_err();
        EC::from_str("rt:1:2:3").unwrap_err();



        // route origin
        EC::from_str("ro:1:2").unwrap();
        EC::from_str("ro:127.0.0.1:2").unwrap();

        assert_eq!(
            EC::from_str("rt:AS1234:789").unwrap(),
            EC::from_str("rt:1234:00789").unwrap(),
        );


        assert_eq!(
            EC::from_str("rt:AS1234:789").unwrap(),
            EC::transitive_as2_route_target(1234.into(), 789)
        );
        assert_eq!(
            EC::from_str("rt:AS66001:789").unwrap(),
            EC::transitive_as4_route_target(66001_u32.into(), 789)
        );
        assert_eq!(
            EC::from_str("rt:127.0.0.1:789").unwrap(),
            EC::transitive_ip4_route_target(
                Ipv4Addr::from_str("127.0.0.1").unwrap(),
                789
            )
        );

    }

    #[test]
    fn reserved() {
        let sc = StandardCommunity::from_str("AS0:52005").unwrap();
        assert!(sc.is_reserved());
        assert!(!sc.is_private());
        assert!(sc.to_wellknown().is_none());
        assert!(sc.asn() == Some(Asn::from_str("AS0").unwrap()));
    }

    #[test]
    fn wellknowns() {
        use Wellknown::*;
        assert_eq!(StandardCommunity::from_wellknown(NoExport).asn(), None);
        assert_eq!(StandardCommunity::from_wellknown(NoExport).tag(), None);
    }

    #[test]
    fn asn() {
        use ExtendedCommunity as EC;
        let c1: Community = EC::transitive_as2_route_target(1234_u16.into(), 789).into();
        assert_eq!(c1.asn(), Some(Asn::from_u32(1234)));

        let c2: Community = EC::transitive_as4_route_target(66001_u32.into(), 78).into();
        assert_eq!(c2.asn(), Some(Asn::from_u32(66001)));
    }

    #[test]
    fn ipv6ext() {
        let s = "0x0102030405060708090a0b0c0d0e0f1011121314";
        let c = Ipv6ExtendedCommunity::from_str(s).unwrap();
        assert_eq!(s, c.to_string());
    }

    #[test]
    fn wk_try_from() {
        assert!(<Wellknown as TryFrom<u32>>::try_from(0xffff0001).is_ok());
        assert!(<Wellknown as TryFrom<u32>>::try_from(0x0fff0001).is_err());
    }
}
