use core::hash::Hash;
use core::str::FromStr;
use std::fmt::{self, Debug};


use crate::typeenum; // from util::macros

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

// notes:
// - move in and adapt all remaining stuff from bgp/message/nlri.rs
// - can we do PartialEq impls in macro?
// - eventually rename this to bgp/nlri.rs ?
// - remove bgp/message/nlri.rs  
// - pub use Afi/Nlri/etc from bgp::types 
// - clean up / remove bgp/workshop/afisafi_nlri.rs 

use inetnum::addr::Prefix;
use super::common::{PathId, parse_prefix, prefix_bits_to_bytes};
use crate::util::parser::ParseError;
use paste::paste;


use octseq::{Octets, OctetsBuilder, Parser};

use super::evpn::*;
use super::flowspec::*;
use super::mpls::*;
use super::mpls_vpn::*;
use super::routetarget::*;
use super::vpls::*;

macro_rules! addpath { ($nlri:ident $(<$gen:ident>)? ) =>
{

paste! {
    #[allow(clippy::derived_hash_with_manual_eq)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Clone, Debug, Hash)]
    pub struct [<$nlri AddpathNlri>]$(<$gen>)?(PathId, [<$nlri Nlri>]$(<$gen>)?);
    impl$(<$gen: Clone + Debug + Hash>)? AfiSafiNlri for [<$nlri AddpathNlri>]$(<$gen>)? {
        type Nlri = <[<$nlri Nlri>]$(<$gen>)? as AfiSafiNlri>::Nlri;
        fn nlri(&self) -> Self::Nlri {
            self.1.nlri()
        }
    }

    impl$(<$gen>)? AfiSafi for [<$nlri AddpathNlri>]$(<$gen>)? {
        fn afi() -> Afi { <[<$nlri Nlri>]$(<$gen>)? as AfiSafi>::afi() }
        fn afi_safi() -> AfiSafiType { <[<$nlri Nlri>]$(<$gen>)? as AfiSafi>::afi_safi() }
    }

    impl<'a, Octs, P> AfiSafiParse<'a, Octs, P> for [<$nlri AddpathNlri>]$(<$gen>)?
    where
        Octs: Octets,
        P: 'a + Octets<Range<'a> = Octs>
    {
        type Output = Self;
        fn parse(parser: &mut Parser<'a, P>) -> Result<Self::Output, ParseError> {
            let path_id = PathId(parser.parse_u32_be()?);
            let inner = [<$nlri Nlri>]::parse(parser)?;
            Ok(
                Self(path_id, inner)
            )
        }
    }

    impl$(<$gen>)? IsNlri for [<$nlri AddpathNlri>]$(<$gen>)? { 
        fn nlri_type() -> NlriType {
            NlriType::[<$nlri Addpath>]
        }
    }

    impl$(<$gen: Clone + Debug + Hash>)? Addpath for [<$nlri AddpathNlri>]$(<$gen>)? {
        fn path_id(&self) -> PathId {
            self.0
        }
    }

    impl$(<$gen>)? fmt::Display for [<$nlri AddpathNlri>]$(<$gen>)? {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "[{}] ", self.0)?;
            fmt::Display::fmt(&self.1, f)
        }
    }

}}
}


// For Nlri generic over anything, use <Octs> literally. Using another name,
// e.g. <O>, does not work. This is a limitation of the macro.
macro_rules! afisafi {
    (
        $(
            $afi_code:expr => $afi_name:ident [ $( $safi_code:expr => $safi_name:ident$(<$gen:ident>)? ),+ $(,)* ]
        ),+ $(,)*
    ) =>
{
    typeenum!(
        /// AFI as used in BGP OPEN and UPDATE messages.
        #[cfg_attr(feature = "serde", serde(from = "u16"))]
        Afi, u16,
        {
            $($afi_code => $afi_name),+
        });

paste! {
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub enum AfiSafiType {
        $( $( [<$afi_name $safi_name>] ,)+)+
        Unsupported(u16, u8),
    }

    /*
    impl TryFrom<(u16, u8)> for AfiSafiType {
        type Error = &'static str;
        fn try_from(t: (u16, u8)) -> Result<Self, Self::Error> {
            match t {
                $($(
                    ($afi_code, $safi_code) => Self::[<$afi_name $safi_name>],
                )+)+
                _ => Err("unsupported AFI+SAFI combination")
            }
        }
    }
    */

    impl From<(u16, u8)> for AfiSafiType {
        fn from(t: (u16, u8)) -> Self {
            match t {
            $($(
                ($afi_code, $safi_code) => Self::[<$afi_name $safi_name>],
            )+)+
                _ => Self::Unsupported(t.0, t.1)
            }
        }
    }

    impl From<AfiSafiType> for (u16, u8) {
        fn from(afisafi: AfiSafiType) -> (u16, u8) {
            match afisafi {
            $($(
                AfiSafiType::[<$afi_name $safi_name>] => ($afi_code, $safi_code),
            )+)+
                AfiSafiType::Unsupported(a, s) => (a, s)
            }
        }
    }

    /*
    impl From<AfiSafiType> for [u8; 3] {
        fn from(afisafi: AfiSafiType) -> [u8; 3] {
            match afisafi {
            $($(
                AfiSafiType::[<$afi_name $safi_name>] => concat!($afi_code.to_be_bytes().into(), $safi_code),
            )+)+
                AfiSafiType::Unsupported(a, s) => [a.to_be_bytes(), s]
            }
        }
    }
    */

    /*
    impl AsRef<[u8]> for AfiSafiType {
        fn as_ref(&self) -> &[u8] {
            match self {
            $($(
                Self::[<$afi_name $safi_name>] => &[$afi_code, $safi_code),
            )+)+
                Self::Unsupported(a, s) => (a, s)
            }
        }
    }
    */

    impl AfiSafiType {
        pub const fn afi(self) -> Afi {
            match self {
            $($(
                Self::[<$afi_name $safi_name>] => Afi::$afi_name,
            )+)+
                Self::Unsupported(a, _s) => Afi::Unimplemented(a)
            }
        }

        pub const fn as_bytes(self) -> [u8; 3] {
            match self {
            $($(
                Self::[<$afi_name $safi_name>] => {
                    let afi = $afi_code.to_be_bytes();
                    [afi[0], afi[1], $safi_code]
                }
            )+)+
                AfiSafiType::Unsupported(a, s) => {
                    let afi = a.to_be_bytes();
                    [afi[0], afi[1], s]
                }
            }
        }
    }


    impl fmt::Display for AfiSafiType {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
            $($(
                Self::[<$afi_name $safi_name>] => {
                    write!(f, stringify!([<$afi_name $safi_name>]))
                }
            )+)+
                Self::Unsupported(a, s) => {
                    write!(f, "UnsupportedAfiSafi({}, {})", a, s)
                }
            }
        }
    }

    // this enforces these derives on all *Nlri structs.
    #[derive(Clone, Debug, Hash)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub enum Nlri<Octs> {
    $($(
        [<$afi_name $safi_name>]([<$afi_name $safi_name Nlri>]$(<$gen>)?),
        [<$afi_name $safi_name Addpath>]([<$afi_name $safi_name AddpathNlri>]$(<$gen>)?)
    ,)+)+
    }

    impl<Octs> Nlri<Octs> {
        pub fn afi_safi(&self) -> AfiSafiType {
            match self {
            $($(
                Self::[<$afi_name $safi_name>](..) => AfiSafiType::[<$afi_name $safi_name >],
                Self::[<$afi_name $safi_name Addpath>](..) => AfiSafiType::[<$afi_name $safi_name >],
            )+)+
            }
        }
    }

    impl<T> fmt::Display for Nlri<T> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
            $($(
                Self::[<$afi_name $safi_name>](i) => fmt::Display::fmt(i, f),
                Self::[<$afi_name $safi_name Addpath>](i) => {
                    fmt::Display::fmt(i, f)
                }
            )+)+
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub enum NlriType {
    $($(
        [<$afi_name $safi_name>],
        [<$afi_name $safi_name Addpath>],
    )+)+
        Unsupported(u16, u8),
    }

    impl NlriType {
        pub fn afi_safi(&self) -> AfiSafiType {
            match self {
            $($(
                Self::[<$afi_name $safi_name>] => AfiSafiType::[<$afi_name $safi_name >],
                Self::[<$afi_name $safi_name Addpath>] => AfiSafiType::[<$afi_name $safi_name >],
            )+)+
                Self::Unsupported(a, s) => AfiSafiType::Unsupported(*a, *s)
            }
        }
    }

    impl From<(AfiSafiType, bool)> for NlriType {
        fn from(t: (AfiSafiType, bool)) -> Self {
            match (t.0, t.1) {
                $($(
                    (AfiSafiType::[<$afi_name $safi_name>], false)  => NlriType::[<$afi_name $safi_name >],
                    (AfiSafiType::[<$afi_name $safi_name>], true)  => NlriType::[<$afi_name $safi_name Addpath>],
                )+)+
                    (AfiSafiType::Unsupported(a, s), _)  => NlriType::Unsupported(a, s),
            }
        }
    }

    impl From<NlriType> for AfiSafiType {
        fn from(n: NlriType) -> Self {
            n.afi_safi()
        }
    }


$($(
    // Instead of doing:
    //pub struct [<$afi_name $safi_name Nlri>];
    //
    // .. we rely on the impl below, forcing us to actually create the
    // $Afi$SafiNlri struct, along with all its basic or exotic data fields
    // and whatnot. We can not do that in a generic way in this macro.
    impl$(<$gen>)? AfiSafi for [<$afi_name $safi_name Nlri>]$(<$gen>)? { 
        fn afi() -> Afi { Afi::$afi_name }
        fn afi_safi() -> AfiSafiType {
            AfiSafiType::[<$afi_name $safi_name>]
        }
    }

    impl$(<$gen>)? IsNlri for [<$afi_name $safi_name Nlri>]$(<$gen>)? { 
        fn nlri_type() -> NlriType {
            NlriType::[<$afi_name $safi_name>]
        }
    }

    impl<Octs> From<[<$afi_name $safi_name Nlri>]$(<$gen>)?> for Nlri<Octs> {
        fn from(n: [<$afi_name $safi_name Nlri>]$(<$gen>)?) -> Self {
            Nlri::[<$afi_name $safi_name>](n)
        }
    }

    impl<Octs> From<[<$afi_name $safi_name AddpathNlri>]$(<$gen>)?> for Nlri<Octs> {
        fn from(n: [<$afi_name $safi_name AddpathNlri>]$(<$gen>)?) -> Self {
            Nlri::[<$afi_name $safi_name Addpath>](n)
        }
    }

    impl$(<$gen>)? From<[<$afi_name $safi_name AddpathNlri>]$(<$gen>)?> for [<$afi_name $safi_name Nlri>]$(<$gen>)? {
        fn from(n: [<$afi_name $safi_name AddpathNlri>]$(<$gen>)?) -> Self {
            n.1
        }
    }

    //--- NlriIter

    impl<'a, Octs, P> NlriIter<'a, Octs, P, [<$afi_name $safi_name Nlri>]$(<$gen>)?>
    where
        Octs: Octets,
        P: Octets<Range<'a> = Octs>
    {
        pub fn [<$afi_name:lower _ $safi_name:lower>](parser: Parser<'a, P>) -> Self {
            NlriIter::<'a, Octs, P, [<$afi_name $safi_name Nlri>]$(<$gen>)?>::new(parser)
        }
    }

    impl<'a, Octs, P> NlriIter<'a, Octs, P, [<$afi_name $safi_name AddpathNlri>]$(<$gen>)?>
    where
        Octs: Octets,
        P: Octets<Range<'a> = Octs>
    {
        pub fn [<$afi_name:lower _ $safi_name:lower _ addpath>](parser: Parser<'a, P>) -> Self {
            NlriIter::<'a, Octs, P, [<$afi_name $safi_name AddpathNlri>]$(<$gen>)?>::new(parser)
        }
    }

    // Some attempts to add fn iter() to the Nlri structs below.
    // Problem is that we can only act on _presence_ of $gen , but not on its
    // absence. So when we have the <Octs> on the struct, the fn iter can not
    // define it again, though we need it there for the non <Octs> structs.
    
    /*
    impl [<$afi_name $safi_name Nlri>]  {
        pub fn iter1<'a, Octs, P>(parser: Parser<'a, P>) -> NlriIter<'a, Octs, P, Self>
        where
            Octs: Octets,
            P: 'a + Octets<Range<'a> = Octs>
        {
            NlriIter::[<$afi_name:lower _ $safi_name:lower>](parser)
        }
    }
    */

    /*
    // <Octs> structs only
    $(
    impl<$gen> [<$afi_name $safi_name Nlri>]<$gen>  {
        pub fn iter2<'a, P>(parser: Parser<'a, P>) -> NlriIter<'a, Octs, P, Self>
        where
            Octs: Octets,
            P: 'a + Octets<Range<'a> = Octs>
        {
            NlriIter::[<$afi_name:lower _ $safi_name:lower>](parser)
        }
    }
    )?
    */

    impl$(<$gen>)?  [<$afi_name $safi_name Nlri>]$(<$gen>)?  {
        pub fn into_addpath(self, path_id: PathId) -> [<$afi_name $safi_name AddpathNlri>]$(<$gen>)? {
            [<$afi_name $safi_name AddpathNlri>](path_id, self)
        }
    }

    // Create the Addpath version
    addpath!([<$afi_name $safi_name>]$(<$gen>)?);
)+)+

}}
}

//--- Trait implementations for macro generated types

impl<Octs: AsRef<[u8]>> Eq for Nlri<Octs> {}

impl<Octs, Other> PartialEq<Nlri<Other>> for Nlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &Nlri<Other>) -> bool {
        use Nlri::*;
        match (self, other) {
            (Ipv4Unicast(p1), Ipv4Unicast(p2)) => p1 == p2,
            (Ipv4UnicastAddpath(p1), Ipv4UnicastAddpath(p2)) => p1 == p2,
            (Ipv4Multicast(p1), Ipv4Multicast(p2)) => p1 == p2,
            (Ipv4MulticastAddpath(p1), Ipv4MulticastAddpath(p2)) => p1 == p2,
            (Ipv4MplsUnicast(p1), Ipv4MplsUnicast(p2)) => p1 == p2,
            (Ipv4MplsUnicastAddpath(p1), Ipv4MplsUnicastAddpath(p2)) => p1 == p2,
            (Ipv4MplsVpnUnicast(p1), Ipv4MplsVpnUnicast(p2)) => p1 == p2,
            (Ipv4MplsVpnUnicastAddpath(p1), Ipv4MplsVpnUnicastAddpath(p2)) => p1 == p2,
            (Ipv4RouteTarget(p1), Ipv4RouteTarget(p2)) => p1 == p2,
            (Ipv4RouteTargetAddpath(p1), Ipv4RouteTargetAddpath(p2)) => p1 == p2,
            (Ipv4FlowSpec(p1), Ipv4FlowSpec(p2)) => p1 == p2,
            (Ipv4FlowSpecAddpath(p1), Ipv4FlowSpecAddpath(p2)) => p1 == p2,
            (Ipv6Unicast(p1), Ipv6Unicast(p2)) => p1 == p2,
            (Ipv6UnicastAddpath(p1), Ipv6UnicastAddpath(p2)) => p1 == p2,
            (Ipv6Multicast(p1), Ipv6Multicast(p2)) => p1 == p2,
            (Ipv6MulticastAddpath(p1), Ipv6MulticastAddpath(p2)) => p1 == p2,
            (Ipv6MplsUnicast(p1), Ipv6MplsUnicast(p2)) => p1 == p2,
            (Ipv6MplsUnicastAddpath(p1), Ipv6MplsUnicastAddpath(p2)) => p1 == p2,
            (Ipv6MplsVpnUnicast(p1), Ipv6MplsVpnUnicast(p2)) => p1 == p2,
            (Ipv6MplsVpnUnicastAddpath(p1), Ipv6MplsVpnUnicastAddpath(p2)) => p1 == p2,
            (Ipv6FlowSpec(p1), Ipv6FlowSpec(p2)) => p1 == p2,
            (Ipv6FlowSpecAddpath(p1), Ipv6FlowSpecAddpath(p2)) => p1 == p2,
            (L2VpnVpls(p1), L2VpnVpls(p2)) => p1 == p2,
            (L2VpnVplsAddpath(p1), L2VpnVplsAddpath(p2)) => p1 == p2,
            (L2VpnEvpn(p1), L2VpnEvpn(p2)) => p1 == p2,
            (L2VpnEvpnAddpath(p1), L2VpnEvpnAddpath(p2)) => p1 == p2,
            _ => false
        }
    }
}

// While Nlri<()> might make more sense, it clashes with trait bounds
// like Vec<u8>: OctetsFrom<T> elsewhere, as, From<()> is not implemented for
// Vec<u8>. Similarly, () is not AsRef<[u8]>.
impl Nlri<&[u8]> {
    /// Creates a `Nlri::Unicast` for `prefix`.
    ///
    /// This returns the error thrown by `Prefix::from_str` if `prefix` does
    /// not represent a valid IPv6 or IPv4 prefix.
    pub fn unicast_from_str(prefix: &str)
        -> Result<Nlri<&[u8]>, <Prefix as FromStr>::Err>
    {
        let p = Prefix::from_str(prefix)?;
        if p.is_v4() {
            Ok(Nlri::Ipv4Unicast(Ipv4UnicastNlri(p)))
        } else {
            Ok(Nlri::Ipv6Unicast(Ipv6UnicastNlri(p)))
        }
    }
}

//------------ Traits ---------------------------------------------------------

/// A type characterized by an AFI and SAFI.
pub trait AfiSafi {
    fn afi() -> Afi;
    fn afi_safi() -> AfiSafiType;
}

pub trait IsNlri {
    fn nlri_type() -> NlriType;
}

/// A type representing an NLRI for a certain AFI+SAFI.
pub trait AfiSafiNlri: AfiSafi + IsNlri + Clone + Hash + Debug {
    type Nlri;
    fn nlri(&self) -> Self::Nlri;

    // TODO
    //fn nexthop_compatible(&self, nh: &super::nexthop::NextHop) -> bool;
}

pub trait AfiSafiParse<'a, O, P>: Sized + IsNlri
    where P: 'a + Octets<Range<'a> = O>
{
    type Output: AfiSafi;
    fn parse(parser: &mut Parser<'a, P>) -> Result<Self::Output, ParseError>;
}

pub trait NlriCompose: AfiSafiNlri {
    fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>;

    fn compose_len(&self) -> usize { todo!() }
}


/// A type containing nothing more than a (v4 or v6) Prefix.
pub trait IsPrefix: AfiSafiNlri {
    fn prefix(&self) -> Prefix;
    
    fn path_id(&self) -> Option<PathId> {
        None
    }
}

// with this blanket impl we can't distinguish addpath from non-addpath
/*
impl <T, B>IsPrefix for T where T: AfiSafiNlri<Nlri = B>, B: Into<Prefix> {
    fn prefix(&self) -> Prefix {
        self.nlri().into()
    }
}
*/

macro_rules! is_prefix {
    ($nlri:ident) => { paste! {
        impl IsPrefix for [<$nlri Nlri>] {
            fn prefix(&self) -> Prefix {
                self.nlri().into()
            }
        }
        impl IsPrefix for [<$nlri AddpathNlri>] {
            fn prefix(&self) -> Prefix {
                self.nlri().into()
            }
            fn path_id(&self) -> Option<PathId> {
                Some(<Self as Addpath>::path_id(&self))
            }
        }
    }}
}
is_prefix!(Ipv4Unicast);
is_prefix!(Ipv4Multicast);
is_prefix!(Ipv6Unicast);
is_prefix!(Ipv6Multicast);

/// An Nlri containing a Path Id.
pub trait Addpath: AfiSafiNlri {
    fn path_id(&self) -> PathId;
}


//------------ Implementations -----------------------------------------------

// adding AFI/SAFIs here requires some manual labor:
// - at the least, add a struct for $Afi$SafiNlri , deriving Clone,Debug,Hash
// - impl AfiSafiNlri, AfiSafiParse and Display

afisafi! {
    1_u16 => Ipv4 [
        1 => Unicast,
        2 => Multicast,
        4 => MplsUnicast<Octs>,
        128 => MplsVpnUnicast<Octs>,
        132 => RouteTarget<Octs>,
        133 => FlowSpec<Octs>,
        //134 => FlowSpecVpn<Octs>,

    ],
    2_u16 => Ipv6 [
        1 => Unicast,
        2 => Multicast,
        4 => MplsUnicast<Octs>,
        128 => MplsVpnUnicast<Octs>,
        133 => FlowSpec<Octs>,
        //134 => FlowSpecVpn<Octs>,
    ],
    25_u16 => L2Vpn [
        65 => Vpls,
        70 => Evpn<Octs>,
    ]
}


//------------ Ipv4 ----------------------------------------------------------


// --- Ipv4Unicast

#[derive(Clone, Debug, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ipv4UnicastNlri(Prefix);

impl AfiSafiNlri for Ipv4UnicastNlri {
    type Nlri = Prefix;
    fn nlri(&self) -> Self::Nlri {
        self.0
    }
}

impl FromStr for Ipv4UnicastNlri {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let p = Prefix::from_str(s).map_err(|_| "could not parse prefix")?;
        p.try_into()
    }
}

impl TryFrom<Prefix> for Ipv4UnicastNlri {
    type Error = &'static str;
    fn try_from(p: Prefix) -> Result<Self, Self::Error> {
        if p.is_v4() {
            Ok( Self(p) )
        } else {
            Err("prefix is not IPv4")
        }
    }
}

impl<'a, O, P> AfiSafiParse<'a, O, P> for Ipv4UnicastNlri
where
    O: Octets,
    P: 'a + Octets<Range<'a> = O>
{
    type Output = Self;
    fn parse(parser: &mut Parser<'a, P>) -> Result<Self::Output, ParseError> {
        Ok(
            Self(parse_prefix(parser, Afi::Ipv4)?)
        )
    }
}

impl NlriCompose for Ipv4UnicastNlri {
    fn compose_len(&self) -> usize {
        // 1 byte for the length itself
        1 + prefix_bits_to_bytes(self.prefix().len())
    }

    fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError> {
        let len = self.prefix().len();
        target.append_slice(&[len])?;
        let prefix_bytes = prefix_bits_to_bytes(len);
        match self.prefix().addr() {
            std::net::IpAddr::V4(a) => {
                target.append_slice(&a.octets()[..prefix_bytes])?
            }
            _ => unreachable!()
        }
        Ok(())
    }
}

impl NlriCompose for Ipv4UnicastAddpathNlri {
    fn compose_len(&self) -> usize {
        4 + self.1.compose_len()
    }

    fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
            target.append_slice(&self.0.0.to_be_bytes())?;
            self.1.compose(target)
    }

}

impl PartialEq<Ipv4UnicastAddpathNlri> for Ipv4UnicastAddpathNlri {
    fn eq(&self, other: &Ipv4UnicastAddpathNlri) -> bool {
        self.0 == other.0
    }
}

impl fmt::Display for Ipv4UnicastNlri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

//--- Ipv4Multicast

#[derive(Clone, Debug, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ipv4MulticastNlri(Prefix);

impl AfiSafiNlri for Ipv4MulticastNlri {
    type Nlri = Prefix;
    fn nlri(&self) -> Self::Nlri {
        self.0
    }
}

impl FromStr for Ipv4MulticastNlri {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let p = Prefix::from_str(s).map_err(|_| "err")?;
        p.try_into()
    }
}

impl TryFrom<Prefix> for Ipv4MulticastNlri {
    type Error = &'static str;
    fn try_from(p: Prefix) -> Result<Self, Self::Error> {
        if p.is_v4() {
            Ok( Self(p) )
        } else {
            Err("prefix is not IPv4")
        }
    }
}

impl<'a, O, P> AfiSafiParse<'a, O, P> for Ipv4MulticastNlri
where
    O: Octets,
    P: 'a + Octets<Range<'a> = O>
{
    type Output = Self;
    fn parse(parser: &mut Parser<'a, P>) -> Result<Self::Output, ParseError> {
        Ok(
            Self(parse_prefix(parser, Afi::Ipv4)?)
        )
    }
}

impl NlriCompose for Ipv4MulticastNlri {
    fn compose_len(&self) -> usize {
        // 1 byte for the length itself
        1 + prefix_bits_to_bytes(self.prefix().len())
    }

    fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError> {
        let len = self.prefix().len();
        target.append_slice(&[len])?;
        let prefix_bytes = prefix_bits_to_bytes(len);
        match self.prefix().addr() {
            std::net::IpAddr::V4(a) => {
                target.append_slice(&a.octets()[..prefix_bytes])?
            }
            _ => unreachable!()
        }
        Ok(())
    }
}

impl PartialEq<Ipv4MulticastAddpathNlri> for Ipv4MulticastAddpathNlri {
    fn eq(&self, other: &Ipv4MulticastAddpathNlri) -> bool {
        self.0 == other.0
    }
}

impl fmt::Display for Ipv4MulticastNlri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

//--- Ipv4MplsUnicast

#[derive(Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ipv4MplsUnicastNlri<Octs>(MplsNlri<Octs>);

impl<Octs: Clone + Debug + Hash> AfiSafiNlri for Ipv4MplsUnicastNlri<Octs> {
    type Nlri = MplsNlri<Octs>;
    fn nlri(&self) -> Self::Nlri {
        self.0.clone()
    }
}

impl<'a, O, P> AfiSafiParse<'a, O, P> for Ipv4MplsUnicastNlri<O>
where
    O: Octets,
    P: 'a + Octets<Range<'a> = O>
{
    type Output = Self;

    fn parse(parser: &mut Parser<'a, P>)
        -> Result<Self::Output, ParseError>
    {
        let (prefix, labels) = MplsNlri::parse_labels_and_prefix(parser, Afi::Ipv4)?;

        Ok(
            Self(MplsNlri::new(prefix,labels,))
        )
    }
}

impl<Octs, Other> PartialEq<Ipv4MplsUnicastNlri<Other>> for Ipv4MplsUnicastNlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &Ipv4MplsUnicastNlri<Other>) -> bool {
        self.0 == other.0
    }
}

impl<Octs, Other> PartialEq<Ipv4MplsUnicastAddpathNlri<Other>> for Ipv4MplsUnicastAddpathNlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &Ipv4MplsUnicastAddpathNlri<Other>) -> bool {
        self.0 == other.0
    }
}

impl<T> fmt::Display for Ipv4MplsUnicastNlri<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

//--- Ipv4MplsVpnUnicastNlri

#[derive(Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ipv4MplsVpnUnicastNlri<Octs>(MplsVpnNlri<Octs>);

impl<Octs: Clone + Debug + Hash> AfiSafiNlri for Ipv4MplsVpnUnicastNlri<Octs> {
    type Nlri = MplsVpnNlri<Octs>;
    fn nlri(&self) -> Self::Nlri {
        self.0.clone()
    }
}

impl<'a, O, P> AfiSafiParse<'a, O, P> for Ipv4MplsVpnUnicastNlri<O>
where
    O: Octets,
    P: 'a + Octets<Range<'a> = O>
{
    type Output = Self;

    fn parse(parser: &mut Parser<'a, P>)
        -> Result<Self::Output, ParseError>
    {
        let (labels, rd, prefix) =
            parse_labels_rd_prefix(parser, Afi::Ipv4)?;

        Ok(Self(MplsVpnNlri::new(prefix, labels, rd)))
    }
}

impl<Octs, Other> PartialEq<Ipv4MplsVpnUnicastNlri<Other>> for Ipv4MplsVpnUnicastNlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &Ipv4MplsVpnUnicastNlri<Other>) -> bool {
        self.0 == other.0
    }
}

impl<Octs, Other> PartialEq<Ipv4MplsVpnUnicastAddpathNlri<Other>> for Ipv4MplsVpnUnicastAddpathNlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &Ipv4MplsVpnUnicastAddpathNlri<Other>) -> bool {
        self.0 == other.0
    }
}

impl<T> fmt::Display for Ipv4MplsVpnUnicastNlri<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

//--- Ipv4RouteTarget


#[derive(Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ipv4RouteTargetNlri<Octs>(RouteTargetNlri<Octs>);

impl<Octs: Clone + Debug + Hash> AfiSafiNlri for Ipv4RouteTargetNlri<Octs> {
    type Nlri = RouteTargetNlri<Octs>;
    fn nlri(&self) -> Self::Nlri {
        self.0.clone()
    }
}

impl<'a, O, P> AfiSafiParse<'a, O, P> for Ipv4RouteTargetNlri<O>
where
    O: Octets,
    P: 'a + Octets<Range<'a> = O>
{
    type Output = Self;

    fn parse(parser: &mut Parser<'a, P>)
        -> Result<Self::Output, ParseError>
    {

        Ok(Self(RouteTargetNlri::parse(parser)?))
    }
}

impl<Octs, Other> PartialEq<Ipv4RouteTargetNlri<Other>> for Ipv4RouteTargetNlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &Ipv4RouteTargetNlri<Other>) -> bool {
        self.0 == other.0
    }
}

impl<Octs, Other> PartialEq<Ipv4RouteTargetAddpathNlri<Other>> for Ipv4RouteTargetAddpathNlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &Ipv4RouteTargetAddpathNlri<Other>) -> bool {
        self.0 == other.0
    }
}

impl<T> fmt::Display for Ipv4RouteTargetNlri<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

//--- Ipv4FlowSpec

#[derive(Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ipv4FlowSpecNlri<Octs>(FlowSpecNlri<Octs>);

impl<Octs: Clone + Debug + Hash> AfiSafiNlri for Ipv4FlowSpecNlri<Octs> {
    type Nlri = FlowSpecNlri<Octs>;
    fn nlri(&self) -> Self::Nlri {
        self.0.clone()
    }
}

impl<'a, O, P> AfiSafiParse<'a, O, P> for Ipv4FlowSpecNlri<O>
where
    O: Octets,
    P: 'a + Octets<Range<'a> = O>
{
    type Output = Self;

    fn parse(parser: &mut Parser<'a, P>)
        -> Result<Self::Output, ParseError>
    {

        Ok(Self(FlowSpecNlri::parse(parser, Afi::Ipv4)?))
    }
}

impl<Octs: Clone + Debug + Hash + Octets> NlriCompose for Ipv4FlowSpecNlri<Octs> {
    fn compose_len(&self) -> usize {
        let value_len = self.0.raw().as_ref().len();
        let len_len = if value_len >= 240 { 2 } else { 1 } ;
        len_len + value_len
    }

    fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError> {
        let len = self.0.raw().as_ref().len();
        if len >= 240 {
            todo!(); //FIXME properly encode into 0xfnnn for 239 < len < 4095
            /*
            target.append_slice(
                &u16::try_from(self.compose_len()).unwrap_or(u16::MAX)
                .to_be_bytes()
            )?;
            */
        } else {
            // We know len < 255 so we can safely unwrap.
            target.append_slice(&[u8::try_from(len).unwrap()])?;
        }
        target.append_slice(self.0.raw().as_ref())
    }
}

impl<T> From<Ipv4FlowSpecNlri<T>> for FlowSpecNlri<T> {
    fn from(value: Ipv4FlowSpecNlri<T>) -> Self {
        value.0
    }
}

impl<Octs, Other> PartialEq<Ipv4FlowSpecNlri<Other>> for Ipv4FlowSpecNlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &Ipv4FlowSpecNlri<Other>) -> bool {
        self.0 == other.0
    }
}

impl<Octs, Other> PartialEq<Ipv4FlowSpecAddpathNlri<Other>> for Ipv4FlowSpecAddpathNlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &Ipv4FlowSpecAddpathNlri<Other>) -> bool {
        self.0 == other.0
    }
}


impl<T> fmt::Display for Ipv4FlowSpecNlri<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

//------------ Ipv6 ----------------------------------------------------------

//--- Ipv6Unicast

#[derive(Clone, Debug, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ipv6UnicastNlri(Prefix);
impl AfiSafiNlri for Ipv6UnicastNlri {
    type Nlri = Prefix;
    fn nlri(&self) -> Self::Nlri {
        self.0
    }
}
impl FromStr for Ipv6UnicastNlri {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let p = Prefix::from_str(s).map_err(|_| "could not parse prefix")?;
        p.try_into()
    }
}

impl TryFrom<Prefix> for Ipv6UnicastNlri {
    type Error = &'static str;
    fn try_from(p: Prefix) -> Result<Self, Self::Error> {
        if p.is_v6() {
            Ok( Self(p) )
        } else {
            Err("prefix is not IPv6")
        }
    }
}

impl<'a, O, P> AfiSafiParse<'a, O, P> for Ipv6UnicastNlri
where
    O: Octets,
    P: 'a + Octets<Range<'a> = O>
{
    type Output = Self;
    fn parse(parser: &mut Parser<'a, P>) -> Result<Self::Output, ParseError> {
        Ok(
            Self(parse_prefix(parser, Afi::Ipv6)?)
        )
    }
}

impl NlriCompose for Ipv6UnicastNlri {
    fn compose_len(&self) -> usize {
        // 1 byte for the length itself
        1 + prefix_bits_to_bytes(self.prefix().len())
    }

    fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError> {
        let len = self.prefix().len();
        target.append_slice(&[len])?;
        let prefix_bytes = prefix_bits_to_bytes(len);
        match self.prefix().addr() {
            std::net::IpAddr::V6(a) => {
                target.append_slice(&a.octets()[..prefix_bytes])?
            }
            _ => unreachable!()
        }
        Ok(())
    }
}


impl PartialEq<Ipv6UnicastAddpathNlri> for Ipv6UnicastAddpathNlri {
    fn eq(&self, other: &Ipv6UnicastAddpathNlri) -> bool {
        self.0 == other.0
    }
}

impl fmt::Display for Ipv6UnicastNlri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

//--- Ipv6Multicast

#[derive(Clone, Debug, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ipv6MulticastNlri(Prefix);

impl AfiSafiNlri for Ipv6MulticastNlri {
    type Nlri = Prefix;
    fn nlri(&self) -> Self::Nlri {
        self.0
    }
}

impl<'a, O, P> AfiSafiParse<'a, O, P> for Ipv6MulticastNlri
where
    O: Octets,
    P: 'a + Octets<Range<'a> = O>
{
    type Output = Self;
    fn parse(parser: &mut Parser<'a, P>) -> Result<Self::Output, ParseError> {
        Ok(
            Self(parse_prefix(parser, Afi::Ipv6)?)
        )
    }
}

impl PartialEq<Ipv6MulticastAddpathNlri> for Ipv6MulticastAddpathNlri {
    fn eq(&self, other: &Ipv6MulticastAddpathNlri) -> bool {
        self.0 == other.0
    }
}

impl fmt::Display for Ipv6MulticastNlri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}


//--- Ipv6MplsUnicast

#[derive(Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ipv6MplsUnicastNlri<Octs>(MplsNlri<Octs>);

impl<Octs: Clone + Debug + Hash> AfiSafiNlri for Ipv6MplsUnicastNlri<Octs> {
    type Nlri = MplsNlri<Octs>;
    fn nlri(&self) -> Self::Nlri {
        self.0.clone()
    }
}

impl<'a, O, P> AfiSafiParse<'a, O, P> for Ipv6MplsUnicastNlri<O>
where
    O: Octets,
    P: 'a + Octets<Range<'a> = O>
{
    type Output = Self;

    fn parse(parser: &mut Parser<'a, P>)
        -> Result<Self::Output, ParseError>
    {
        let (prefix, labels) = MplsNlri::parse_labels_and_prefix(parser, Afi::Ipv6)?;

        Ok(
            Self(MplsNlri::new(prefix,labels,))
        )
    }
}

impl<Octs, Other> PartialEq<Ipv6MplsUnicastNlri<Other>> for Ipv6MplsUnicastNlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &Ipv6MplsUnicastNlri<Other>) -> bool {
        self.0 == other.0
    }
}

impl<Octs, Other> PartialEq<Ipv6MplsUnicastAddpathNlri<Other>> for Ipv6MplsUnicastAddpathNlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &Ipv6MplsUnicastAddpathNlri<Other>) -> bool {
        self.0 == other.0
    }
}

impl<T> fmt::Display for Ipv6MplsUnicastNlri<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

//--- Ipv6MplsVpnUnicastNlri

#[derive(Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ipv6MplsVpnUnicastNlri<Octs>(MplsVpnNlri<Octs>);

impl<Octs: Clone + Debug + Hash> AfiSafiNlri for Ipv6MplsVpnUnicastNlri<Octs> {
    type Nlri = MplsVpnNlri<Octs>;
    fn nlri(&self) -> Self::Nlri {
        self.0.clone()
    }
}

impl<'a, O, P> AfiSafiParse<'a, O, P> for Ipv6MplsVpnUnicastNlri<O>
where
    O: Octets,
    P: 'a + Octets<Range<'a> = O>
{
    type Output = Self;

    fn parse(parser: &mut Parser<'a, P>)
        -> Result<Self::Output, ParseError>
    {
        let (labels, rd, prefix) =
            parse_labels_rd_prefix(parser, Afi::Ipv6)?;

        Ok(Self(MplsVpnNlri::new(prefix, labels, rd)))
    }
}

impl<Octs, Other> PartialEq<Ipv6MplsVpnUnicastNlri<Other>> for Ipv6MplsVpnUnicastNlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &Ipv6MplsVpnUnicastNlri<Other>) -> bool {
        self.0 == other.0
    }
}

impl<Octs, Other> PartialEq<Ipv6MplsVpnUnicastAddpathNlri<Other>> for Ipv6MplsVpnUnicastAddpathNlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &Ipv6MplsVpnUnicastAddpathNlri<Other>) -> bool {
        self.0 == other.0
    }
}

impl<T> fmt::Display for Ipv6MplsVpnUnicastNlri<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}


//--- Ipv6FlowSpec

#[derive(Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ipv6FlowSpecNlri<Octs>(FlowSpecNlri<Octs>);

impl<Octs: Clone + Debug + Hash> AfiSafiNlri for Ipv6FlowSpecNlri<Octs> {
    type Nlri = FlowSpecNlri<Octs>;
    fn nlri(&self) -> Self::Nlri {
        self.0.clone()
    }
}

impl<'a, O, P> AfiSafiParse<'a, O, P> for Ipv6FlowSpecNlri<O>
where
    O: Octets,
    P: 'a + Octets<Range<'a> = O>
{
    type Output = Self;

    fn parse(parser: &mut Parser<'a, P>)
        -> Result<Self::Output, ParseError>
    {

        Ok(Self(FlowSpecNlri::parse(parser, Afi::Ipv6)?))
    }
}

impl<T> From<Ipv6FlowSpecNlri<T>> for FlowSpecNlri<T> {
    fn from(value: Ipv6FlowSpecNlri<T>) -> Self {
        value.0
    }
}

impl<Octs, Other> PartialEq<Ipv6FlowSpecNlri<Other>> for Ipv6FlowSpecNlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &Ipv6FlowSpecNlri<Other>) -> bool {
        self.0 == other.0
    }
}

impl<Octs, Other> PartialEq<Ipv6FlowSpecAddpathNlri<Other>> for Ipv6FlowSpecAddpathNlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &Ipv6FlowSpecAddpathNlri<Other>) -> bool {
        self.0 == other.0
    }
}

impl<T> fmt::Display for Ipv6FlowSpecNlri<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}


/*
impl Ipv6UnicastAddpathNlri {
    pub fn iter<'a, O, P>(parser: Parser<'a, P>) -> NlriIter<'a, O, P, Self>
    where
        O: Octets,
        P: 'a + Octets<Range<'a> = O>
    {
        NlriIter::ipv6_unicast_addpath(parser)
    }
}

impl<Octs> Ipv4MplsUnicastNlri<Octs> {
    pub fn iter<'a, P>(parser: Parser<'a, P>) -> NlriIter<'a, Octs, P, Self>
    where
        Octs: Octets,
        P: 'a + Octets<Range<'a> = Octs>
    {
        NlriIter::ipv4_mplsunicast(parser)
    }
}
*/

//------------ L2Vpn ----------------------------------------------------------

//--- L2VpnVpls

#[derive(Clone, Debug, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct L2VpnVplsNlri(VplsNlri);

impl AfiSafiNlri for L2VpnVplsNlri {
    type Nlri = VplsNlri;
    fn nlri(&self) -> Self::Nlri {
        self.0
    }
}

impl<'a, O, P> AfiSafiParse<'a, O, P> for L2VpnVplsNlri
where
    O: Octets,
    P: 'a + Octets<Range<'a> = O>
{
    type Output = Self;

    fn parse(parser: &mut Parser<'a, P>)
        -> Result<Self::Output, ParseError>
    {

        Ok(Self(VplsNlri::parse(parser)?))
    }
}

impl PartialEq<L2VpnVplsAddpathNlri> for L2VpnVplsAddpathNlri {
    fn eq(&self, other: &L2VpnVplsAddpathNlri) -> bool {
        self.0 == other.0
    }
}

impl fmt::Display for L2VpnVplsNlri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

//--- Evpn

#[derive(Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct L2VpnEvpnNlri<Octs>(EvpnNlri<Octs>);

impl<Octs: Clone + Debug + Hash> AfiSafiNlri for L2VpnEvpnNlri<Octs> {
    type Nlri = EvpnNlri<Octs>;
    fn nlri(&self) -> Self::Nlri {
        self.0.clone()
    }
}

impl<'a, O, P> AfiSafiParse<'a, O, P> for L2VpnEvpnNlri<O>
where
    O: Octets,
    P: 'a + Octets<Range<'a> = O>
{
    type Output = Self;

    fn parse(parser: &mut Parser<'a, P>)
        -> Result<Self::Output, ParseError>
    {

        Ok(Self(EvpnNlri::parse(parser)?))
    }
}

impl<Octs, Other> PartialEq<L2VpnEvpnNlri<Other>> for L2VpnEvpnNlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &L2VpnEvpnNlri<Other>) -> bool {
        self.0 == other.0
    }
}

impl<Octs, Other> PartialEq<L2VpnEvpnAddpathNlri<Other>> for L2VpnEvpnAddpathNlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &L2VpnEvpnAddpathNlri<Other>) -> bool {
        self.0 == other.0
    }
}

impl<T> fmt::Display for L2VpnEvpnNlri<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}


//------------ Iteration ------------------------------------------------------

// Iterating over NLRI likely mostly happens when ingesting UPDATE PDUs, i.e.
// one or more (possibly >1000) NLRI of one single AfiSafiType. We therefore
// want type specific iterators, yielding exact types (e.g. Ipv6UnicastNlri)
// instead of the Nlri enum, as that would require the user to match/unpack
// every single item returned by next() (which would/should always be of the
// same type, anyway).
//
// For convenience or whatever other use cases, we might still want to provide
// an iterator yielding variants of the Nlri enum, probably based on the
// type-specific ones.
// Because of the From impls generated in the macro call, we can already do:
//
//     NlriIter::ipv4_mplsunicast(parser).map(Nlri::<_>::from)
//
// .. to turn a specific iterator into a generic one, returning the Nlri enum
// type.
//
// Seems that creating the convenience constructors involves a lot of typy
// typy which could also become part of the afisafi! macro.


pub struct NlriIter<'a, O, P, ASP> {
    parser: Parser<'a, P>,
    asp: std::marker::PhantomData<ASP>,
    output: std::marker::PhantomData<O>,
}

impl<'a, O, P, ASP> NlriIter<'a, O, P, ASP>
where
    O: Octets,
    P: Octets<Range<'a> = O>,
    ASP: AfiSafiParse<'a, O, P>
{
    pub fn new(parser: Parser<'a, P>) -> Self {
        NlriIter {
            parser,
            asp: std::marker::PhantomData,
            output: std::marker::PhantomData
        }
    }

    pub fn afi_safi(&self) -> AfiSafiType {
        ASP::Output::afi_safi()
    }

    pub fn nlri_type(&self) -> NlriType {
        ASP::nlri_type()
    }

    // Validate the entire parser so we can safely return items from this
    // iterator, instead of returning Option<Result<Nlri>, ParseError>
    //
    pub fn validate(&self) -> Result<(), ParseError> {
        let mut parser = self.parser;
        while parser.remaining() > 0 {
            // TODO replace this ::parse with a cheaper ::check, if available
            ASP::parse(&mut parser)?;
        }
        Ok(())
    }
}


impl<'a, O, P, ASP: AfiSafiParse<'a, O, P>> Iterator for NlriIter<'a, O, P, ASP>
where 
    P: Octets<Range<'a> = O>
{
    type Item = Result<ASP::Output, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None;
        }
        Some(ASP::parse(&mut self.parser))
    }
}

/// Generic iterator returning Nlri enum variants instead of specific Nlri
/// structs.
pub struct NlriEnumIter<'a, P> {
    parser: Parser<'a, P>,
    ty: NlriType,
}

impl<'a, P> NlriEnumIter<'a, P> {
    pub fn new(parser: Parser<'a, P>, ty: NlriType) -> Self {
        Self { parser, ty }
    }

    pub fn nlri_type(&self) -> NlriType {
        self.ty
    }

    pub fn afi_safi(&self) -> AfiSafiType {
        self.ty.afi_safi()
    }
}

impl<'a, O, P> Iterator for NlriEnumIter<'a, P>
where 
    O: Octets,
    P: Octets<Range<'a> = O>,
{
    type Item = Result<Nlri<O>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None
        }
        
        let res = match self.ty {
            NlriType::Ipv4Unicast => Ipv4UnicastNlri::parse(&mut self.parser).map(Nlri::Ipv4Unicast),
            NlriType::Ipv4UnicastAddpath => Ipv4UnicastAddpathNlri::parse(&mut self.parser).map(Nlri::Ipv4UnicastAddpath),
            NlriType::Ipv4Multicast => Ipv4MulticastNlri::parse(&mut self.parser).map(Nlri::Ipv4Multicast),
            NlriType::Ipv4MulticastAddpath => Ipv4MulticastAddpathNlri::parse(&mut self.parser).map(Nlri::Ipv4MulticastAddpath),
            NlriType::Ipv4MplsUnicast => Ipv4MplsUnicastNlri::parse(&mut self.parser).map(Nlri::Ipv4MplsUnicast),
            NlriType::Ipv4MplsUnicastAddpath => Ipv4MplsUnicastAddpathNlri::parse(&mut self.parser).map(Nlri::Ipv4MplsUnicastAddpath),
            NlriType::Ipv4MplsVpnUnicast => Ipv4MplsVpnUnicastNlri::parse(&mut self.parser).map(Nlri::Ipv4MplsVpnUnicast),
            NlriType::Ipv4MplsVpnUnicastAddpath => Ipv4MplsVpnUnicastAddpathNlri::parse(&mut self.parser).map(Nlri::Ipv4MplsVpnUnicastAddpath),
            NlriType::Ipv4RouteTarget => Ipv4RouteTargetNlri::parse(&mut self.parser).map(Nlri::Ipv4RouteTarget),
            NlriType::Ipv4RouteTargetAddpath => Ipv4RouteTargetAddpathNlri::parse(&mut self.parser).map(Nlri::Ipv4RouteTargetAddpath),
            NlriType::Ipv4FlowSpec => Ipv4FlowSpecNlri::parse(&mut self.parser).map(Nlri::Ipv4FlowSpec),
            NlriType::Ipv4FlowSpecAddpath => Ipv4FlowSpecAddpathNlri::parse(&mut self.parser).map(Nlri::Ipv4FlowSpecAddpath),
            NlriType::Ipv6Unicast => Ipv6UnicastNlri::parse(&mut self.parser).map(Nlri::Ipv6Unicast),
            NlriType::Ipv6UnicastAddpath => Ipv6UnicastAddpathNlri::parse(&mut self.parser).map(Nlri::Ipv6UnicastAddpath),
            NlriType::Ipv6Multicast => Ipv6MulticastNlri::parse(&mut self.parser).map(Nlri::Ipv6Multicast),
            NlriType::Ipv6MulticastAddpath => Ipv6MulticastAddpathNlri::parse(&mut self.parser).map(Nlri::Ipv6MulticastAddpath),
            NlriType::Ipv6MplsUnicast => Ipv6MplsUnicastNlri::parse(&mut self.parser).map(Nlri::Ipv6MplsUnicast),
            NlriType::Ipv6MplsUnicastAddpath => Ipv6MplsUnicastAddpathNlri::parse(&mut self.parser).map(Nlri::Ipv6MplsUnicastAddpath),
            NlriType::Ipv6MplsVpnUnicast => Ipv6MplsVpnUnicastNlri::parse(&mut self.parser).map(Nlri::Ipv6MplsVpnUnicast),
            NlriType::Ipv6MplsVpnUnicastAddpath => Ipv6MplsVpnUnicastAddpathNlri::parse(&mut self.parser).map(Nlri::Ipv6MplsVpnUnicastAddpath),
            NlriType::Ipv6FlowSpec => Ipv6FlowSpecNlri::parse(&mut self.parser).map(Nlri::Ipv6FlowSpec),
            NlriType::Ipv6FlowSpecAddpath => Ipv6FlowSpecAddpathNlri::parse(&mut self.parser).map(Nlri::Ipv6FlowSpecAddpath),
            NlriType::L2VpnVpls => L2VpnVplsNlri::parse(&mut self.parser).map(Nlri::L2VpnVpls),
            NlriType::L2VpnVplsAddpath => L2VpnVplsAddpathNlri::parse(&mut self.parser).map(Nlri::L2VpnVplsAddpath),
            NlriType::L2VpnEvpn => L2VpnEvpnNlri::parse(&mut self.parser).map(Nlri::L2VpnEvpn),
            NlriType::L2VpnEvpnAddpath => L2VpnEvpnAddpathNlri::parse(&mut self.parser).map(Nlri::L2VpnEvpnAddpath),
            NlriType::Unsupported(..) => { return None; }
        };

        Some(res)
    }
}

impl<'a, O, P, ASP> From<NlriIter<'a, O, P, ASP>> for NlriEnumIter<'a, P>
where 
    O: Octets,
    ASP: AfiSafiParse<'a, O, P>,
    P: Octets<Range<'a> = O>,
{
    fn from(iter: NlriIter<'a, O, P, ASP>) -> Self {
        Self {
            parser: iter.parser,
            ty: ASP::nlri_type() 
        }
    }
}

impl<'a, O, P, ASP: AfiSafiParse<'a, O, P>> NlriIter<'a, O, P, ASP>
where
    O: Octets,
    P: Octets<Range<'a> = O>
{
    pub fn next_with<T, F: FnOnce(<Self as Iterator>::Item) -> T>(&mut self, fmap: F) -> Option<T> {
        self.next().map(fmap)
    }
}

impl<'a, O, P> NlriEnumIter<'a, P>
where 
    O: Octets,
    P: Octets<Range<'a> = O>,
{
    pub fn next_with<T, F: FnOnce(<Self as Iterator>::Item) -> T>(&mut self, fmap: F) -> Option<T> {
        self.next().map(fmap)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use inetnum::addr::Prefix;
    use std::str::FromStr;

    #[test]
    fn test1() {
        let p = Prefix::from_str("1.2.3.0/24").unwrap();
        let n = Ipv4UnicastNlri(p);

        let _n2 = n.clone().nlri();

        let _b2 = n.prefix();

        let _nlri_type: Nlri<()> = n.into();

        let mc = Ipv4MulticastNlri(p);
        let _nlri_type2: Nlri<()> = mc.clone().into();

    }

    #[test]
    fn addpath() {
        let n = Ipv4UnicastAddpathNlri(
            PathId(13),
            Ipv4UnicastNlri(
                Prefix::from_str("1.2.3.0/24").unwrap().into()
        ));
        dbg!(&n);
        // XXX From<AddPathNlri> for Nlri is missing
        /*
        let nlri: Nlri<()> = n.clone().into();
        dbg!(&nlri.afi_safi());
        dbg!(&n.afi());
        dbg!(&n.path_id());
        dbg!(&n.basic_nlri());
        */
       
        // and this is why we need a distinc BasicNlriWithPathId type:
        //assert_eq!(n.path_id(), b.path_id().unwrap());
    }

    #[test]
    fn parse_ipv4unicast() {
        let raw = vec![24,1,2,3];
        let mut parser = Parser::from_ref(&raw);
        let n = Ipv4UnicastNlri::parse(&mut parser).unwrap();
        //dbg!(&n);
        eprintln!("{}", &n);
    }
    #[test]
    fn parse_ipv4mplsunicast() {
        // Label 8000 10.0.0.9/32
        let raw = vec![0x38, 0x01, 0xf4, 0x01, 0x0a, 0x00, 0x00, 0x09];
        let mut parser = Parser::from_ref(&raw);
        let n = Ipv4MplsUnicastNlri::parse(&mut parser).unwrap();
        eprintln!("{}", &n);

        let raw = bytes::Bytes::from_static(&[0x38, 0x01, 0xf4, 0x01, 0x0a, 0x00, 0x00, 0x09]);
        let mut parser = Parser::from_ref(&raw);
        let n2 = Ipv4MplsUnicastNlri::parse(&mut parser).unwrap();
        eprintln!("{}", &n2);

        assert_eq!(n, n2);

        let _n: Nlri<_> = n.into();
        let _n2: Nlri<_> = n2.into();
    }

    #[test]
    fn display() {
        let n: Nlri<()> = Ipv4UnicastNlri(Prefix::from_str("1.2.3.0/24").unwrap().into()).into();
        eprintln!("{}", n);
    }

    #[test]
    fn iter() {
        let raw = vec![
            0x38, 0x01, 0xf4, 0x01, 0x0a, 0x00, 0x00, 0x09,
            0x38, 0x01, 0xf4, 0x01, 0x0a, 0x00, 0x00, 0x0a,
        ];
        let parser = Parser::from_ref(&raw);
        let iter = NlriIter::ipv4_mplsunicast(parser);
        assert_eq!(iter.count(), 2);
    }

    #[test]
    fn iter_generic() {
        let mpls_raw = vec![
            0x38, 0x01, 0xf4, 0x01, 0x0a, 0x00, 0x00, 0x09,
            0x38, 0x01, 0xf4, 0x01, 0x0a, 0x00, 0x00, 0x0a,
        ];
        let parser = Parser::from_ref(&mpls_raw);
        let mpls_iter = NlriIter::ipv4_mplsunicast(parser);

        let v4_raw = vec![24, 1, 2, 3];
        let parser = Parser::from_ref(&v4_raw);
        let v4_iter = NlriIter::ipv4_unicast(parser); 


        for n in NlriEnumIter::from(v4_iter)
            .chain(NlriEnumIter::from(mpls_iter))
        {
            dbg!(&n);
        }
    }

    #[test]
    fn iter_addpath() {
        let raw = vec![
            0, 0, 0, 1, 24, 1, 2, 1,
            0, 0, 0, 2, 24, 1, 2, 2,
            0, 0, 0, 3, 24, 1, 2, 3,
            0, 0, 0, 4, 24, 1, 2, 4,
        ];

        let parser = Parser::from_ref(&raw);
        let iter = NlriIter::ipv4_unicast_addpath(parser);
        assert_eq!(iter.count(), 4);

        let iter = NlriIter::ipv4_unicast_addpath(parser);
        for n in iter.map(|e| e.unwrap().prefix()) {
            dbg!(&n);
        }
    }

    #[test]
    fn iter_addpath_alternative() {
        let raw = vec![
            0, 0, 0, 1, 24, 1, 2, 1,
            0, 0, 0, 2, 24, 1, 2, 2,
            0, 0, 0, 3, 24, 1, 2, 3,
            0, 0, 0, 4, 24, 1, 2, 4,
        ];

        let parser = Parser::from_ref(&raw);
        let iter = NlriIter::ipv6_unicast_addpath(parser);
        //assert_eq!(iter.count(), 4);
        for n in iter {
            eprintln!("{}", n.unwrap());
        }
    }

    #[test]
    fn iter_with() {
        let raw = vec![
            0, 0, 0, 1, 24, 1, 2, 1,
            0, 0, 0, 2, 24, 1, 2, 2,
            0, 0, 0, 3, 24, 1, 2, 3,
            0, 0, 0, 4, 24, 1, 2, 4,
        ];

        let parser = Parser::from_ref(&raw);
        let iter = NlriIter::ipv6_unicast_addpath(parser);
        //while let Some(x) = iter.next_with(|e| format!("IPv6!!!: {:?}", e).to_string()) {
        //    dbg!(x);
        //}

        for x in  iter.map(|e| format!("IPv6!!!: {:?}", e).to_string()) {
            dbg!(x);
        }

    }

    #[test]
    fn roundtrip_into_from_addpath() {
        let raw = vec![
            24, 1, 2, 1,
            24, 1, 2, 2,
            24, 1, 2, 3,
            24, 1, 2, 4,
        ];

        let parser = Parser::from_ref(&raw);
        let iter = NlriIter::ipv6_unicast(parser);
        for (idx, n) in iter.enumerate() {
            dbg!(
                Ipv6UnicastNlri::from(
                    dbg!(n.unwrap().into_addpath(PathId(idx.try_into().unwrap())))
                )
            );
        }
    }

}
