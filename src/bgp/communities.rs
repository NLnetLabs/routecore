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
//! Standard Communities can possibly be converted to/from WellKnown
//! communities.

use std::fmt::{Display, Error, Formatter};
use std::str::FromStr;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::asn::Asn;


//--- Community --------------------------------------------------------------

/// Standard and Extended/Large Communities variants.
#[derive(Debug, Eq, PartialEq)]
pub enum Community {
    Standard(StandardCommunity),
    Extended(ExtendedCommunity),
    Ipv6Extended(Ipv6ExtendedCommunity),
    Large(LargeCommunity),
    //Container, // for Wide communities, still in IETF draft
}

impl Community {
    pub fn as_well_known(&self) -> Option<WellKnown> {
        match self {
            Community::Standard(sc) => {
                sc.as_well_known()
            },
            _ => None
        }
    }

    pub fn asn(&self) -> Option<Asn> {
        use Community::*;
        match self {
            Standard(sc) => sc.asn(),
            Extended(e) => e.as2().map(|a| a.into_asn32())
                                    .or_else(|| e.as4()),
            Ipv6Extended(_) => None, 
            Large(lc) => Some(lc.global().into()),
        }
    }
}

// AsRef
//
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

impl From<WellKnown> for Community {
    fn from(wk: WellKnown) -> Self {
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
    type Err = String;
    
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
        Err("cant parse".into())
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

//--- WellKnown --------------------------------------------------------------

macro_rules! wellknown {
    ($name:ident,
        $($hex:expr => $var:ident, $pprim:expr $(,$psec:expr)* );+
        $(;)+
    )
    => {

        // XXX maybe write doc in table form?
        // | type | prints as | from_str from |
        // $(| $var | $pprim    | $psec* |\n)*
        #[derive(Debug, Eq, PartialEq)]
        /// Well-known communities as registered by IANA.
        ///
        $(#[doc = concat!("`", stringify!($var), "` prints as \"", $pprim, "\", parses from \"",
        stringify!($var), "\", \"", $pprim $(,"\", \"",$psec)*,"\" \n\n" )]
        )+
        pub enum $name {
            $(#[doc = concat!("`", stringify!($var), "` prints as \"", $pprim, "\", parses from \"",
            stringify!($var), "\", \"", $pprim $(,"\", \"",$psec)*,"\"" )]
            $var),+,
            Unrecognized(u32)
        }
        
        impl $name {

            pub fn to_u32(self) -> u32 {
                match self {
                    $($name::$var => $hex,)+
                    $name::Unrecognized(n) => n
                }
            }

            pub fn from_u32(n: u32) -> $name {
                match n {
                    $($hex => $name::$var,)+
                    _ => $name::Unrecognized(n)
                }
            }

            pub fn into_stardard(self) -> StandardCommunity {
                self.into()
            }
        }
        
        impl FromStr for $name {
            type Err = String;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    //$($p | stringify!($n) => Ok($name::$n),)+
                    $($pprim $(|$psec)* | stringify!($var) => Ok($name::$var),)+
                        _ => Err("cant parse".to_owned())
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
    }
}

// Calling the macro generates an enum `WellKnown` with variants based on the
// name directly after the '=>'. FromStr is implemented to parse that name,
// and all the variants given in the list until the ;
// For the Display implementation, the first of that list is used.
// E.g. WellKnown::AcceptOwnNexthop can be parsed from "AcceptOwnNexthop",
// "accept-own-nexthop", "ACCEPT_OWN_NEXTHOP", and will be printed as
// "accept-own-nexthop".
wellknown!(WellKnown,
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

    0xFFFF029A => BlackHole, "BLACKHOLE";
);



//--- StandardCommunity ------------------------------------------------------

/// Conventional, RFC1997 4-byte community.
#[derive(Debug, Eq, PartialEq)]
pub struct StandardCommunity([u8; 4]);

impl StandardCommunity {
    pub fn new(asn: Asn16, tag: Tag) -> StandardCommunity {
        StandardCommunity(
            [asn.0.to_be_bytes(), tag.0.to_be_bytes()]
            .concat().try_into().unwrap()
            )
    }

    pub fn from_raw(raw: [u8; 4]) -> Self {
        Self(raw)
    }

    pub fn for_well_known(wk: WellKnown) -> StandardCommunity {
        StandardCommunity::from_u32(wk.to_u32())
    }

    pub fn from(raw: [u8; 4]) -> StandardCommunity {
        StandardCommunity(raw)
    }

    pub fn from_u32(raw: u32) -> StandardCommunity {
        StandardCommunity(raw.to_be_bytes())
    }

    pub fn as_u32(&self) -> u32 {
        u32::from_be_bytes(self.0)
    }

    pub fn raw(&self) -> [u8; 4] {
        self.0
    }

    // Methods for non well-known communities.
    // At least some routeservers seem to use the reserved 0:xxx,
    // for those we'll simply return the Asn for 0.

    pub fn asn(&self) -> Option<Asn> {
        if !self.is_well_known() {
            Some(Asn::from_u32(
                    u16::from_be_bytes([self.0[0], self.0[1]]) as u32
                ))
        } else {
            None
        }
    }

    pub fn tag(&self) -> Option<Tag>{
        if !self.is_well_known() {
            Some(Tag(u16::from_be_bytes([self.0[2], self.0[3]])))
        } else {
            None
        }
    }

    pub fn is_private(&self) -> bool {
        !matches!(self.0, [0xff, 0xff, _, _] | [0x00, 0x00, _, _])
    }


    pub fn is_well_known(&self) -> bool {
        matches!(self.0, [0xff, 0xff, _, _])
    }

    pub fn as_well_known(&self) -> Option<WellKnown> {
        if self.is_well_known() {
            Some(WellKnown::from_u32(self.as_u32()))
        } else {
            None
        }
    }

    pub fn is_reserved(&self) -> bool {
        matches!(self.0, [0x00, 0x00, _, _])
    }

    pub fn typ(&self) -> StandardCommunityType {
        match self.0 {
            [0x00, 0x00, _, _] => StandardCommunityType::Reserved,
            [0xff, 0xff, _, _] => StandardCommunityType::WellKnown,
            _ => StandardCommunityType::Private
        }
    }
}

#[derive(Debug)]
pub enum StandardCommunityType {
    Reserved,
    Private,
    WellKnown,
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

impl From<WellKnown> for StandardCommunity {
    fn from(wk: WellKnown) -> Self {
        StandardCommunity::from_u32(wk.to_u32())
    }
}


impl FromStr for StandardCommunity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(wk) = WellKnown::from_str(s) {
            return Ok(wk.into());
        }
        if let Some((a, t)) = s.split_once(':') {
            let asn = Asn16::from_str(a)?;
            let tagv = u16::from_str(t).map_err(|_e| "cant parse Tag")?;
            return Ok(StandardCommunity::new(asn, Tag(tagv)));
        }
        Err("failed FromStr for StandardCommunity".into())
    }
}

// Display

// We only distinguish between WellKnown or not.
// The reserved 0x0000xxxx we print as AS0:xxxx, as it is used by route
// servers and obscuring it by printing as pure hex or whatever does not help
// anybody.
impl Display for StandardCommunity {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        if let Some(wk) = self.as_well_known() {
            write!(f, "{}", wk)
        } else { 
            write!(f, "{}:{}", &self.asn().unwrap(), &self.tag().unwrap())
        }
    }

}


/// Final two octets of a [`StandardCommunity`], i.e. the 'community number'.
#[derive(Debug, Eq, PartialEq)]
pub struct Tag(u16);

impl Tag {
    pub fn new(t: u16) -> Self {
        Self(t)
    }

    pub fn value(&self) -> u16 {
        self.0
    }
}

impl Display for Tag {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{}", self.0)
    }
}

//--- ExtendedCommunity ------------------------------------------------------

/// Extended Community as defined in RFC4360.
#[derive(Debug, Eq, PartialEq)]
pub struct ExtendedCommunity([u8; 8]);

impl ExtendedCommunity {

    pub fn from_raw(raw: [u8; 8]) -> Self {
        Self(raw)
    }

    pub fn raw(&self) -> [u8; 8] {
        self.0
    }

    pub fn type_raw(&self) -> u8 {
        self.0[0]
    }

    pub fn types(&self) -> (ExtendedCommunityType, ExtendedCommunitySubType) {
        use ExtendedCommunityType::*;
        use ExtendedCommunitySubType::*;
        match self.0[0..2] {
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

    pub fn is_transitive(&self) -> bool {
        // Transitive bit 0 means the community is transitive
        self.type_raw() & 0x40 == 0x00
    }

    //--- route target constructors ------------------------------------------
    // Transitive two-octet AS specific
    pub fn transitive_as2_route_target(global: u16, local: u32) -> Self {
        let mut buf = [0u8; 8];
        
        buf[0] = 0x00;
        buf[1] = 0x02;
        buf[2..4].copy_from_slice(&global.to_be_bytes());
        buf[4..8].copy_from_slice(&local.to_be_bytes());
        
        ExtendedCommunity(buf)
    }

    // Transitive four-octet AS specific
    pub fn transitive_as4_route_target(global: u32, local: u16) -> Self {
        let mut buf = [0u8; 8];
        
        buf[0] = 0x02;
        buf[1] = 0x02;
        buf[2..6].copy_from_slice(&global.to_be_bytes());
        buf[6..8].copy_from_slice(&local.to_be_bytes());
        
        ExtendedCommunity(buf)
    }

    //  Transitive ipv4-addr specific
    pub fn transitive_ip4_route_target(global: Ipv4Addr, local: u16) -> Self {
        let mut buf = [0u8; 8];
        
        buf[0] = 0x01;
        buf[1] = 0x02;
        buf[2..6].copy_from_slice(&global.octets());
        buf[6..8].copy_from_slice(&local.to_be_bytes());
        
        ExtendedCommunity(buf)
    }

    // Non-Transitive Opaque 
    pub fn non_transitive_opaque_route_target(value: &[u8]) -> Self {
        let mut buf = [0u8; 8];

        buf[0] = 0x43;
        buf[1] = 0x02;
        buf[2..8].copy_from_slice(value);

        ExtendedCommunity(buf)
    }

    //--- route origin constructors ------------------------------------------
    // transitive two-octet AS specific
    //      0x0002 : AS2 : AS4
    pub fn transitive_as2_route_origin(global: u16, local: u32) -> Self {
        let mut buf = [0u8; 8];
        
        buf[0] = 0x00;
        buf[1] = 0x03;
        buf[2..4].copy_from_slice(&global.to_be_bytes());
        buf[4..8].copy_from_slice(&local.to_be_bytes());
        
        ExtendedCommunity(buf)
    }

    // transitive four-octet AS specific
    //      0x0202 : AS4 : AS2
    pub fn transitive_as4_route_origin(global: u32, local: u16) -> Self {
        let mut buf = [0u8; 8];
        
        buf[0] = 0x02;
        buf[1] = 0x03;
        buf[2..6].copy_from_slice(&global.to_be_bytes());
        buf[6..8].copy_from_slice(&local.to_be_bytes());
        
        ExtendedCommunity(buf)
    }

    //  transitive ipv4-addr specific
    //      0x0102 : 
    pub fn transitive_ip4_route_origin(global: Ipv4Addr, local: u16) -> Self {
        let mut buf = [0u8; 8];
        
        buf[0] = 0x01;
        buf[1] = 0x03;
        buf[2..6].copy_from_slice(&global.octets());
        buf[6..8].copy_from_slice(&local.to_be_bytes());
        
        ExtendedCommunity(buf)
    }

    // getters for specific types

    pub fn as2(&self) -> Option<Asn16> {
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

    pub fn as4(&self) -> Option<Asn> {
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

    pub fn ip4(&self) -> Option<Ipv4Addr> {
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
    pub fn an2(&self) -> Option<u16> {
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
    pub fn an4(&self) -> Option<u32> {
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

#[derive(Debug, Eq, PartialEq)]
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

#[derive(Debug, Eq, PartialEq)]
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
    type Err = String;
    
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
                        .ok_or_else(||"expected :".to_owned())?;
                    // XXX do we want to force/allow an AS prefix here?
                    // e.g. rt:AS1234:789 ?
                    let ga = ga.strip_prefix("AS").unwrap_or(ga);
                    if let Ok(as2) = u16::from_str(ga) {
                        Ok(Self::transitive_as2_route_target(
                            as2,
                            u32::from_str(an).map_err(|_| "illegal u32")?
                        ))
                    } else if let Ok(as4) = u32::from_str(ga) {
                        Ok(Self::transitive_as4_route_target(
                            as4,
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
                        .ok_or_else(|| "expected :".to_owned())?;
                    // XXX do we want to force/allow an AS prefix here?
                    // e.g. rt:AS1234:789 ?
                    let ga = ga.strip_prefix("AS").unwrap_or(ga);
                    if let Ok(as2) = u16::from_str(ga) {
                        Ok(Self::transitive_as2_route_origin(
                            as2,
                            u32::from_str(an).map_err(|_| "illegal u32")?
                        ))
                    } else if let Ok(as4) = u32::from_str(ga) {
                        Ok(Self::transitive_as4_route_origin(
                            as4,
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
            u => { Err(format!("unknown tag {}", u)) }
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
#[derive(Debug, Eq, PartialEq)]
pub struct Ipv6ExtendedCommunity([u8; 20]);


impl Ipv6ExtendedCommunity {
    pub fn from_raw(raw: [u8; 20]) -> Self {
        Self(raw)
    }

    pub fn raw(&self) -> [u8; 20] {
        self.0
    }

    pub fn type_raw(&self) -> u8 {
        self.0[0]
    }

    pub fn is_transitive(&self) -> bool {
        // Transitive bit 0 means the community is transitive
        self.type_raw() & 0x40 == 0x00
    }

    pub fn ip6(&self) -> Ipv6Addr {
        Ipv6Addr::from(
            <&[u8] as TryInto<[u8; 16]>>::try_into(&self.0[2..18])
            .expect("parsed before")
        )
    }
    pub fn an2(&self) -> u16 {
        u16::from_be_bytes(self.0[18..20].try_into().unwrap())
    }

    pub fn local_admin(&self) -> u16 {
        u16::from_be_bytes([self.0[19], self.0[20]])
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
    type Err = String;

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
#[derive(Debug, Eq, PartialEq)]
pub struct LargeCommunity([u8; 12]);

impl LargeCommunity {

    pub fn asn(&self) -> Asn {
        Asn::from_u32(self.global())
    }
    
    pub fn from_raw(raw: [u8; 12]) -> Self {
        Self(raw)
    }

    pub fn raw(&self) -> [u8; 12] {
        self.0
    }

    pub fn global(&self) -> u32 {
        u32::from_be_bytes(self.0[0..4].try_into().unwrap())
    }

    pub fn local1(&self) -> u32 {
        u32::from_be_bytes(self.0[4..8].try_into().unwrap())
    }

    pub fn local2(&self) -> u32 {
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
    type Err = String;

    // Canonical form is u32:u32:u32
    // but we allow AS12345:u32:u32 as well
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(3, ':');

        let ga = parts.next().ok_or("expected more parts")?;
        let ga = ga.strip_prefix("AS").unwrap_or(ga);
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

//--- Tmp should be in other place in routecore ------------------------------

#[derive(Debug, Eq, PartialEq)]
pub struct Asn16(u16);

impl Asn16 {
    pub fn from_u16(u: u16) -> Self {
        Self(u)
    }
    pub fn into_asn32(self) -> Asn {
        Asn::from_u32(self.0 as u32)
    }
}

impl Display for Asn16 {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "AS{}", self.0)
    }
}

impl From<u16> for Asn16 {
    fn from(n: u16) -> Self {
        Self(n)
    }
}

impl FromStr for Asn16 {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.strip_prefix("AS").ok_or_else(|| "missing AS".into())
            .and_then(|e| u16::from_str(e)
                      .map_err(|_e| "u16 parsing failed".into())
                     )
            .map(Asn16::from_u16)
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
        assert!(sc.is_well_known());
        assert!(!sc.is_private());
        assert_eq!(sc, sc2);

        assert_eq!(sc.as_u32(), 0xFFFFFF01);
        assert_eq!(sc.raw(), [0xFF, 0xFF, 0xFF, 0x01]);

        //let noexp = WellKnown::NoExport();
        let noexp = StandardCommunity::for_well_known(WellKnown::NoExport);
        assert!(noexp.is_well_known());
        assert_eq!(noexp, sc);
        assert_eq!(noexp.as_u32(), 0xFFFFFF01);
        assert_eq!(noexp.raw(), [0xFF, 0xFF, 0xFF, 0x01]);

        let pr = StandardCommunity::new(Asn16(1234), Tag(5555));
        assert!(!pr.is_well_known());
        assert!(pr.is_private());
        assert!(pr != noexp);
    }

    #[test]
    fn display() {
        use WellKnown::*;
        println!("{}", StandardCommunity::for_well_known(NoExport));
        println!("{}", StandardCommunity::for_well_known(NoAdvertise));
        println!("{}", StandardCommunity::from_u32(0xffff1234));
        println!("{}", StandardCommunity::new(Asn16(1234), Tag(5555)));
        println!("{}", StandardCommunity::from_str("AS1234:5678").unwrap());

        println!("{}", StandardCommunity::from_str("AS0:5678").unwrap());

        println!("{}", ExtendedCommunity::from_str("rt:AS1234:666").unwrap());
    }

    #[test]
    fn from_strs() {
        use WellKnown::*;
        StandardCommunity::from_str("AS1234:5678").unwrap();
        assert_eq!(
            StandardCommunity::for_well_known(NoExport),
            StandardCommunity::from_str("NoExport").unwrap()
        );

        //fails
        StandardCommunity::from_str("1234:890").unwrap_err();
        StandardCommunity::from_str("ASxyz:890").unwrap_err();
        StandardCommunity::from_str("AS1234:xyz").unwrap_err();
        StandardCommunity::from_str("AS1234:xyz:zzz").unwrap_err();
        StandardCommunity::from_str("AS1234:1:2").unwrap_err();
        
    }

    #[test]
    fn from_raw() {
        assert_eq!(
            <WellKnown as Into<Community>>::into(WellKnown::NoExport),
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
        assert!(!c.is_well_known());
        assert!(c.as_well_known().is_none());

        let c2: StandardCommunity = WellKnown::NoExport.into();
        println!("{}", c2);
        assert!(c2 == WellKnown::NoExport.into());
        assert!(c2 == StandardCommunity::from_u32(0xFFFFFF01));
        assert!(c2.as_well_known() == Some(WellKnown::NoExport));

        let c3: Community = WellKnown::NoExport.into();
        println!("{:?}", c3);
        assert!(matches!(c3, Community::Standard(_)));
        assert!(c3 == Community::Standard(StandardCommunity::from_u32(0xffffff01)));
        assert!(c3 == WellKnown::NoExport.into());
        assert!(c3.as_well_known() == Some(WellKnown::NoExport));

        let u = StandardCommunity::from_u32(0xFFFF9999);
        assert!(u.is_well_known());
        assert!(u.as_well_known().is_some());
        assert_eq!(u, WellKnown::Unrecognized(0xFFFF9999).into());
        println!("u: {}", u);

        let u = StandardCommunity::from_u32(0x00FF9999);
        assert!(!u.is_well_known());
        assert!(u.as_well_known().is_none());
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
                Community::Standard(sc) => sc.is_well_known(),
                _ => false
        });

        assert!(
            if let Ok(Community::Standard(sc)) =
                Community::from_str("NO_EXPORT")
            {
                sc.is_well_known()
            } else {
                false
            }
        );

        Community::from_str("abc").unwrap_err();
    }

    #[test]
    fn ext_comms() {
        use ExtendedCommunity as EC;
        let ec1 = EC::transitive_as2_route_target(1234, 6789);
        println!("{}", ec1);
        let ec2 = EC::transitive_as4_route_target(1234, 6789);
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
            EC::transitive_as2_route_target(1234, 789)
        );
        assert_eq!(
            EC::from_str("rt:AS66001:789").unwrap(),
            EC::transitive_as4_route_target(66001, 789)
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
        assert!(sc.as_well_known().is_none());
        assert!(sc.asn() == Some(Asn::from_str("AS0").unwrap()));
    }

    #[test]
    fn wellknowns() {
        use WellKnown::*;
        assert_eq!(StandardCommunity::for_well_known(NoExport).asn(), None);
        assert_eq!(StandardCommunity::for_well_known(NoExport).tag(), None);
    }

    #[test]
    fn asn() {
        use ExtendedCommunity as EC;
        let c1: Community = EC::transitive_as2_route_target(1234, 789).into();
        assert_eq!(c1.asn(), Some(Asn::from_u32(1234)));

        let c2: Community = EC::transitive_as4_route_target(66001, 78).into();
        assert_eq!(c2.asn(), Some(Asn::from_u32(66001)));
    }

    #[test]
    fn ipv6ext() {
        let s = "0x0102030405060708090a0b0c0d0e0f1011121314";
        let c = Ipv6ExtendedCommunity::from_str(s).unwrap();
        assert_eq!(s, c.to_string());
    }
}
