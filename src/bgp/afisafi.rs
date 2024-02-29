//use crate::typeenum; // from util::macros

use crate::addr::Prefix;
use crate::bgp::message::nlri::{BasicNlri, PathId, parse_prefix};
use crate::util::parser::ParseError;
use crate::bgp::types::Afi;
use paste::paste;

use std::fmt;

use octseq::{Octets, Parser};

use core::hash::Hash;
use core::fmt::Debug;

macro_rules! afisafi {
    (
        $(
            $afi_code:expr => $afi_name:ident [ $( $safi_code:expr => $safi_name:ident$(<$gen:ident>)? ),+ $(,)* ]
        ),+ $(,)*
    ) => {
        /*
            #[derive(Debug)]
            pub enum Afi {
                $( $afi_name ),+
            }
        */


            paste! {
                #[derive(Debug)]
                pub enum AfiSafiType {
                    $(
                        $( [<$afi_name $safi_name>] ,)+
                    )+
                }

                // this enforces these derives on all *Nlri structs.
                #[derive(Clone, Debug, Hash)]
                pub enum Nlri<Octs> {
                    $(
                        $(
                            [<$afi_name $safi_name>]([<$afi_name $safi_name Nlri>]$(<$gen>)?)
                        ,)+
                    )+
                }

                impl<Octs> Nlri<Octs> {
                    pub fn afi_safi(&self) -> AfiSafiType {
                        match self {
                    $(
                        $(
                            Self::[<$afi_name $safi_name>](..) => AfiSafiType::[<$afi_name $safi_name >]
                        ,)+
                    )+
                        }
                    }
                }

                impl fmt::Display for Nlri<()> {
                    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                        match self {
                    $(
                        $(
                            Self::[<$afi_name $safi_name>](i) => fmt::Display::fmt(i, f)
                        ,)+
                    )+
                        
                        }
                    }
                }



                $(
                    $(
                    // Instead of doing:
                    //pub struct [<$afi_name $safi_name Nlri>];
                    //
                    // .. we rely on the impl below, forcing us to actually
                    // create the $Afi$SafiNlri struct, along with all its
                    // basic or exotic data fields and whatnot. We can not do
                    // that in a generic way in this macro.
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

                    )+
                )+
            }
        }
}



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
    type Output;
    fn parse(
        parser: &mut Parser<'a, P>
    )
    -> Result<Self::Output, ParseError>;
}


/// A type containing a BasicNlri.
pub trait HasBasicNlri {
    fn basic_nlri(&self) -> BasicNlri;
    
    // TODO
    // fn into_routeworkshop() -> RouteWorkshop<_>;
}

// blanket impl
//impl <T>HasBasicNlri for T where T: AfiSafiNlri<Nlri = BasicNlri> {
//    fn basic_nlri(&self) -> BasicNlri {
//        self.nlri()
//    }
//}
impl <T, B>HasBasicNlri for T where T: AfiSafiNlri<Nlri = B>, B: Into<BasicNlri> {
    fn basic_nlri(&self) -> BasicNlri {
        self.nlri().into()
    }
}


//afisafi! {
//    1 => Ipv4 [ 1 => Unicast, 2 => Multicast, 4 => MplsUnicast ],
//    2 => Ipv6 [ 1 => Unicast, 2 => Multicast, 4 => MplsUnicast ],
//    25 => L2Vpn [ 65 => Vpls, 70 => Evpn ],
//}

// adding AFI/SAFIs here requires some manual labor:
// - at the least, add a struct for $Afi$SafiNlri , deriving Clone,Debug,Hash
// - impl AfiSafiNlri for it to make it useful
afisafi! {
    1 => Ipv4 [ 1 => Unicast, 2 => Multicast, 4 => MplsUnicast<Octs>],
    2 => Ipv6 [ 1 => Unicast ],
}

#[derive(Clone, Debug, Hash)]
pub struct Ipv4MulticastNlri(BasicNlri);
/*
impl AfiSafi for BasicNlri {
    fn afi(&self) -> Afi {
        match self.is_v4() {
            true => Afi::Ipv4,
            false => Afi::Ipv6
        }
    }
    //fn safi(&self) -> u8 {
    //    panic!() // we don't know!
    //}
    //fn afi_safi(&self) -> AfiSafiType {
    //    panic!() // we still don't know!
    //}
}
*/
impl fmt::Display for Ipv4MulticastNlri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0.prefix())
    }
}

#[derive(Clone, Debug, Hash)]
pub struct Ipv4UnicastNlri(BasicNlri);
impl AfiSafiNlri for Ipv4UnicastNlri {
    type Nlri = BasicNlri;
    fn nlri(&self) -> Self::Nlri {
        self.0
    }
}

//impl Ipv4UnicastNlri {
//    pub fn parse<P: Octets>(parser: &mut Parser<P>) -> Result<Self, ParseError> {
//        Ok(
//            Self(BasicNlri::new(parse_prefix(parser, Afi::Ipv4)?))
//        )
//    }
//}
impl<'a, O, P> AfiSafiParse<'a, O, P> for Ipv4UnicastNlri
where
    O: Octets,
    P: 'a + Octets<Range<'a> = O>
{
    type Output = Self;
    fn parse(parser: &mut Parser<'a, P>) -> Result<Self::Output, ParseError> {
        Ok(
            Self(BasicNlri::new(parse_prefix(parser, Afi::Ipv4)?))
        )
    }
}

impl fmt::Display for Ipv4UnicastNlri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0.prefix())
    }
}



#[derive(Clone, Debug, Hash)]
pub struct Ipv6UnicastNlri(BasicNlri);
impl AfiSafiNlri for Ipv6UnicastNlri {
    type Nlri = BasicNlri;
    fn nlri(&self) -> Self::Nlri {
        self.0
    }
}

impl fmt::Display for Ipv6UnicastNlri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0.prefix())
    }
}

use crate::bgp::message::nlri::MplsNlri;
#[derive(Clone, Debug, Hash)]
pub struct Ipv4MplsUnicastNlri<Octs>(MplsNlri<Octs>);

impl<Octs, Other> PartialEq<Ipv4MplsUnicastNlri<Other>> for Ipv4MplsUnicastNlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &Ipv4MplsUnicastNlri<Other>) -> bool {
        self.0 == other.0
    }
}

//impl<O: Octets> Ipv4MplsUnicastNlri<O> {
//    // TODO clean up, this is just to test trait bounds et al
//    pub fn parse<'a, P: Octets<Range<'a> = O>>(parser: &mut Parser<'a, P>)
//        -> Result<Self, ParseError>
//    {
//        let (prefix, labels) = MplsNlri::parse_labels_and_prefix(parser, crate::bgp::types::AfiSafi::Ipv4Unicast)?;
//        let basic = BasicNlri::new(prefix);
//
//        Ok(
//            Self(MplsNlri::new(basic,labels,))
//        )
//    }
//}

//impl<'a, O: Octets, P: 'a + Octets<Range<'a> = O>> AfiSafiParse<'a, O, P> for Ipv4MplsUnicastNlri<O>
impl<'a, O, P> AfiSafiParse<'a, O, P> for Ipv4MplsUnicastNlri<O>
where
    O: Octets,
    P: 'a + Octets<Range<'a> = O>
{
    type Output = Self;

    fn parse(parser: &mut Parser<'a, P>)
        -> Result<Self::Output, ParseError>
           // where P: Octets<Range<'a> = Octs>
    {
        // XXX not sure how correct this all is, just testing trait bounds etc
        let (prefix, labels) = MplsNlri::parse_labels_and_prefix(parser, crate::bgp::types::AfiSafi::Ipv4Unicast)?;
        let basic = BasicNlri::new(prefix);

        Ok(
            Self(MplsNlri::new(basic,labels,))
        )
    }
}

impl<Octs: Clone + Debug + Hash> AfiSafiNlri for Ipv4MplsUnicastNlri<Octs> {
    type Nlri = MplsNlri<Octs>;
    fn nlri(&self) -> Self::Nlri {
        self.0.clone()
    }
}

impl<T> fmt::Display for Ipv4MplsUnicastNlri<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// what about a 'custom' Nlri, like an ADD-PATH one?
//
// This needs some more conversion magic and manual typy typy, but seems
// doable so far.
// The main benefit would be in the (yet to be added) fn parse in the
// AfiSafiNlri trait.
// What might be confusing in this particular case though, is that an
// Ipv4UnicastNlri can hold a BasicNlri with a PathId, and likewise, a
// *AddpathNlri can hold a BasicNlri _without_ a PathId.
// So this is really only useful in the FixedNlriIter scenario.
// Or we should introduce a BasicAddpathNlri type or somesuch.
// Maybe it is not that bad of an idea to make the PathId more explicit
// instead of hiding it behind an Option<>: it is crucial to distinguish
// between two ADD-PATH'd announcements.

// some more thoughts:
// if we split up BasicNlri into an AddPath and a non-AddPath version, the
// latter is basically just a addr::Prefix. 

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct BasicAddpathNlri {
    pub prefix: Prefix,
    pub path_id: PathId,
}
impl BasicAddpathNlri {
    pub fn new(prefix: Prefix, path_id: PathId) -> Self {
        Self{ prefix, path_id }
    }
}
impl From<BasicAddpathNlri> for BasicNlri {
    fn from(b: BasicAddpathNlri) -> Self {
        Self::with_path_id(b.prefix, b.path_id)
    }
}

#[derive(Clone, Debug, Hash)]
pub struct Ipv4UnicastAddpathNlri(BasicAddpathNlri);
impl AfiSafiNlri for Ipv4UnicastAddpathNlri {
    //type Nlri = BasicNlri;
    type Nlri = BasicAddpathNlri;
    fn nlri(&self) -> Self::Nlri {
        self.0
    }
}

impl AfiSafi for Ipv4UnicastAddpathNlri {
    fn afi(&self) -> Afi { Afi::Ipv4}
    fn afi_safi(&self) -> AfiSafiType { AfiSafiType::Ipv4Unicast }
}

impl AddPath for Ipv4UnicastAddpathNlri {
    fn path_id(&self) -> PathId {
        self.0.path_id
    }
}

impl From<Ipv4UnicastAddpathNlri> for Ipv4UnicastNlri {
    fn from(n: Ipv4UnicastAddpathNlri) -> Self {
        Self(n.0.prefix.into())
    }
}
impl<Octs> From<Ipv4UnicastAddpathNlri> for Nlri<Octs> {
    fn from(n: Ipv4UnicastAddpathNlri) -> Nlri<Octs> {
        Nlri::Ipv4Unicast(n.into())
    }
}

/// An Nlri containing a Path Id.
pub trait AddPath: AfiSafiNlri {
    fn path_id(&self) -> PathId;
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


pub struct NlriIter<'a, O, P, ASP> {
    parser: Parser<'a, P>,
    asp: std::marker::PhantomData<ASP>,
    output: std::marker::PhantomData<O>,
}

impl<'a, O, P, ASP> NlriIter<'a, O, P, ASP>
where
    O: Octets,
    P: Octets<Range<'a> = O>
{
    pub fn new(parser: Parser<'a, P>) -> Self {
        NlriIter {
            parser,
            asp: std::marker::PhantomData,
            output: std::marker::PhantomData
        }
    }


    // 
    // Validate the entire parser so we can safely return items from this
    // iterator, instead of returning Option<Result<Nlri>, ParseError>
    //
    //pub fn validate(&self) { }

}
impl<'a, O, P> NlriIter<'a, O, P, Ipv4MplsUnicastNlri<O>>
where
    O: Octets,
    P: Octets<Range<'a> = O>
{
    pub fn ipv4_mplsunicast(parser: Parser<'a, P>) -> Self {
        NlriIter::<'a, O, P, Ipv4MplsUnicastNlri<O>>::new(parser)
    }
}

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



#[cfg(test)]
mod tests {

    use super::*;
    use crate::bgp::message::nlri::BasicNlri;
    use crate::addr::Prefix;
    use std::str::FromStr;

    #[test]
    fn test1() {
        let b = BasicNlri::new(Prefix::from_str("1.2.3.0/24").unwrap());
        let n = Ipv4UnicastNlri(b);
        dbg!(&n);

        let n2 = n.clone().nlri();
        dbg!(n2);

        let b2 = n.basic_nlri();

        let nlri_type: Nlri<()> = n.into();
        dbg!(&nlri_type);

        let mc = Ipv4MulticastNlri(b);
        let nlri_type2: Nlri<()> = mc.clone().into();
        dbg!(&mc);

        dbg!(nlri_type2);
    }

    #[test]
    fn addpath() {
        //let b = BasicNlri::with_path_id(
        //    Prefix::from_str("1.2.3.0/24").unwrap(),
        //    PathId::from_u32(12)
        //    );
        let n = Ipv4UnicastAddpathNlri(BasicAddpathNlri::new(
                Prefix::from_str("1.2.3.0/24").unwrap(),
                PathId::from_u32(13)
        ));
        dbg!(&n);
        let nlri: Nlri<()> = n.clone().into();
        dbg!(&nlri.afi_safi());
        dbg!(&n.afi());
        dbg!(&n.path_id());
        dbg!(&n.basic_nlri());
       
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
}
