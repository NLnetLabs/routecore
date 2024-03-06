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

use crate::addr::Prefix;
use super::common::{PathId, parse_prefix, prefix_bits_to_bytes};
use crate::util::parser::ParseError;
use paste::paste;

use std::fmt;

use octseq::{Octets, Parser};

use core::hash::Hash;
use core::fmt::Debug;

use super::evpn::*;
use super::flowspec::*;
use super::mpls::*;
use super::mpls_vpn::*;
use super::routetarget::*;
use super::vpls::*;

macro_rules! addpath { ($nlri:ident $(<$gen:ident>)? ) =>
{

paste! {
    #[derive(Clone, Debug, Hash)]
    pub struct [<$nlri AddpathNlri>]$(<$gen>)?(PathId, [<$nlri Nlri>]$(<$gen>)?);
    impl$(<$gen: Clone + Debug + Hash>)? AfiSafiNlri for [<$nlri AddpathNlri>]$(<$gen>)? {
        type Nlri = <[<$nlri Nlri>]$(<$gen>)? as AfiSafiNlri>::Nlri;
        fn nlri(&self) -> Self::Nlri {
            self.1.nlri()
        }
    }

    impl$(<$gen>)? AfiSafi for [<$nlri AddpathNlri>]$(<$gen>)? {
        fn afi(&self) -> Afi { self.1.afi() }
        fn afi_safi(&self) -> AfiSafiType { self.1.afi_safi() }
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
    #[derive(Debug)]
    pub enum AfiSafiType {
        $( $( [<$afi_name $safi_name>] ,)+)+
    }

    // this enforces these derives on all *Nlri structs.
    #[derive(Clone, Debug, Hash)]
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

    impl fmt::Display for Nlri<()> {
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

$($(
    // Instead of doing:
    //pub struct [<$afi_name $safi_name Nlri>];
    //
    // .. we rely on the impl below, forcing us to actually create the
    // $Afi$SafiNlri struct, along with all its basic or exotic data fields
    // and whatnot. We can not do that in a generic way in this macro.
    impl$(<$gen>)? AfiSafi for [<$afi_name $safi_name Nlri>]$(<$gen>)? { 
        fn afi(&self) -> Afi { Afi::$afi_name }
        fn afi_safi(&self) -> AfiSafiType {
            AfiSafiType::[<$afi_name $safi_name>]
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

//------------ Traits ---------------------------------------------------------

/// A type characterized by an AFI and SAFI.
pub trait AfiSafi {
    fn afi(&self) -> Afi;
    fn afi_safi(&self) -> AfiSafiType;
}

/// A type representing an NLRI for a certain AFI+SAFI.
pub trait AfiSafiNlri: AfiSafi + Clone + Hash + Debug {
    type Nlri; //: AfiSafi;
    fn nlri(&self) -> Self::Nlri;

    // TODO
    // can/should we merge in AfiSafiParse here?

}

pub trait AfiSafiParse<'a, O, P>: Sized
    where P: 'a + Octets<Range<'a> = O>
{
    type Output; // XXX do we actually still need this?
    fn parse(parser: &mut Parser<'a, P>) -> Result<Self::Output, ParseError>;
}


/// A type containing nothing more than a (v4 or v6) Prefix.
pub trait IsPrefix {
    fn prefix(&self) -> Prefix;
    
    // TODO
    // fn into_routeworkshop() -> RouteWorkshop<_>;
}

impl <T, B>IsPrefix for T where T: AfiSafiNlri<Nlri = B>, B: Into<Prefix> {
    fn prefix(&self) -> Prefix {
        self.nlri().into()
    }
}

/// An Nlri containing a Path Id.
pub trait Addpath: AfiSafiNlri {
    fn path_id(&self) -> PathId;
}

//------------ Implementations -----------------------------------------------

// adding AFI/SAFIs here requires some manual labor:
// - at the least, add a struct for $Afi$SafiNlri , deriving Clone,Debug,Hash
// - impl AfiSafiNlri, AfiSafiParse and Display

afisafi! {
    1 => Ipv4 [
        1 => Unicast,
        2 => Multicast,
        4 => MplsUnicast<Octs>,
        128 => MplsVpnUnicast<Octs>,
        132 => RouteTarget<Octs>,
        133 => FlowSpec<Octs>,
        //134 => FlowSpecVpn<Octs>,

    ],
    2 => Ipv6 [
        1 => Unicast,
        2 => Multicast,
        4 => MplsUnicast<Octs>,
        128 => MplsVpnUnicast<Octs>,
        133 => FlowSpec<Octs>,
        //134 => FlowSpecVpn<Octs>,
    ],
    25 => L2Vpn [
        65 => Vpls,
        70 => Evpn<Octs>,
    ]
}


//------------ Ipv4 ----------------------------------------------------------


// --- Ipv4Unicast

#[derive(Clone, Debug, Hash, PartialEq)]
pub struct Ipv4UnicastNlri(Prefix);

impl AfiSafiNlri for Ipv4UnicastNlri {
    type Nlri = Prefix;
    fn nlri(&self) -> Self::Nlri {
        self.0
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

use octseq::OctetsBuilder;
impl Ipv4UnicastNlri {
    pub(crate) fn compose_len(&self) -> usize {
        // 1 byte for the length itself
        1 + prefix_bits_to_bytes(self.prefix().len())
    }

    pub(crate) fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
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

impl fmt::Display for Ipv4UnicastNlri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

//--- Ipv4Multicast

#[derive(Clone, Debug, Hash, PartialEq)]
pub struct Ipv4MulticastNlri(Prefix);

impl AfiSafiNlri for Ipv4MulticastNlri {
    type Nlri = Prefix;
    fn nlri(&self) -> Self::Nlri {
        self.0
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

impl fmt::Display for Ipv4MulticastNlri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

//--- Ipv4MplsUnicast

#[derive(Clone, Debug, Hash)]
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

impl<T> fmt::Display for Ipv4MplsUnicastNlri<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

//--- Ipv4MplsVpnUnicastNlri

#[derive(Clone, Debug, Hash)]
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

impl<T> fmt::Display for Ipv4MplsVpnUnicastNlri<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

//--- Ipv4RouteTarget


#[derive(Clone, Debug, Hash)]
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

impl<T> fmt::Display for Ipv4RouteTargetNlri<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

//--- Ipv4FlowSpec

#[derive(Clone, Debug, Hash)]
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

impl<T> fmt::Display for Ipv4FlowSpecNlri<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

//------------ Ipv6 ----------------------------------------------------------

//--- Ipv6Unicast

#[derive(Clone, Debug, Hash, PartialEq)]
pub struct Ipv6UnicastNlri(Prefix);
impl AfiSafiNlri for Ipv6UnicastNlri {
    type Nlri = Prefix;
    fn nlri(&self) -> Self::Nlri {
        self.0
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

impl fmt::Display for Ipv6UnicastNlri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

//--- Ipv6Multicast

#[derive(Clone, Debug, Hash, PartialEq)]
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

impl fmt::Display for Ipv6MulticastNlri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}


//--- Ipv6MplsUnicast

#[derive(Clone, Debug, Hash)]
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

impl<T> fmt::Display for Ipv6MplsUnicastNlri<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

//--- Ipv6MplsVpnUnicastNlri

#[derive(Clone, Debug, Hash)]
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

impl<T> fmt::Display for Ipv6MplsVpnUnicastNlri<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}


//--- Ipv6FlowSpec

#[derive(Clone, Debug, Hash)]
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

impl<T> fmt::Display for Ipv6FlowSpecNlri<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}


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

//------------ L2Vpn ----------------------------------------------------------

//--- L2VpnVpls

#[derive(Clone, Debug, Hash)]
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

impl fmt::Display for L2VpnVplsNlri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

//--- Evpn

#[derive(Clone, Debug, Hash)]
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

    pub fn map_into_vec<T, F: Fn(<ASP as AfiSafiParse<'_, O, P>>::Output) -> T>(parser: Parser<'a, P>, fmap: F) -> Vec<T> {
        NlriIter {
            parser,
            asp: std::marker::PhantomData::<ASP>,
            output: std::marker::PhantomData::<O>
        }
        .map(fmap)
        .collect::<Vec<_>>()
    }
}


pub fn iter_for_afi_safi<'a, O, P, ASP>(
    parser: Parser<'a, P>,
) -> NlriIter<'a, O, P, ASP>
where
    O: Octets,
    P: Octets<Range<'a> = O>,
    ASP: AfiSafiParse<'a, O, P>
{
    NlriIter::<'a, O, P, ASP>::new(parser)
}

    // 
    // Validate the entire parser so we can safely return items from this
    // iterator, instead of returning Option<Result<Nlri>, ParseError>
    //
    //pub fn validate(&self) { }


impl<'a, O, P, ASP: AfiSafiParse<'a, O, P>> Iterator for NlriIter<'a, O, P, ASP>
where 
    P: Octets<Range<'a> = O>
{
    type Item = ASP::Output;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None;
        }
        Some(ASP::parse(&mut self.parser).unwrap())
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

#[cfg(test)]
mod tests {

    use super::*;
    use crate::addr::Prefix;
    use std::str::FromStr;

    #[test]
    fn test1() {
        let p = Prefix::from_str("1.2.3.0/24").unwrap();
        let n = Ipv4UnicastNlri(p);
        dbg!(&n);

        let n2 = n.clone().nlri();
        dbg!(n2);

        let b2 = n.prefix();

        let nlri_type: Nlri<()> = n.into();
        dbg!(&nlri_type);

        let mc = Ipv4MulticastNlri(p);
        let nlri_type2: Nlri<()> = mc.clone().into();
        dbg!(&mc);

        dbg!(nlri_type2);
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
        let n: Nlri<_> = Ipv4UnicastNlri(Prefix::from_str("1.2.3.0/24").unwrap().into()).into();
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


        for n in v4_iter.map(Nlri::<_>::from).chain(mpls_iter.map(Nlri::<_>::from)) {
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
        for n in iter.map(|e| e.prefix()) {
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
            eprintln!("{n}");
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
                    dbg!(n.into_addpath(PathId(idx.try_into().unwrap())))
                )
            );
        }
    }

}
