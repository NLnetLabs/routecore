//use crate::typeenum; // from util::macros

use crate::bgp::message::nlri::{BasicNlri, PathId};
use paste::paste;


use core::hash::Hash;
use core::fmt::Debug;

macro_rules! afisafi {
    (
        $(
            $afi_code:expr => $afi_name:ident [ $( $safi_code:expr => $safi_name:ident ),+ $(,)* ]
        ),+ $(,)*
    ) => {
            #[derive(Debug)]
            pub enum Afi {
                $( $afi_name ),+
            }


            paste! {
                #[derive(Debug)]
                pub enum AfiSafiType {
                    $(
                        $( [<$afi_name $safi_name>] ,)+
                    )+
                }

                // this enforces these derives on all *Nlri structs.
                #[derive(Clone, Debug, Hash)]
                pub enum Nlri {
                    $(
                        $(
                            [<$afi_name $safi_name>]([<$afi_name $safi_name Nlri>])
                        ,)+
                    )+
                }

                impl Nlri {
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


                $(
                    $(
                    // Instead of doing:
                    //pub struct [<$afi_name $safi_name Nlri>];
                    //
                    // .. we rely on the impl below, forcing us to actually
                    // create the $Afi$SafiNlri struct, along with all its
                    // basic or exotic data fields and whatnot. We can not do
                    // that in a generic way in this macro.
                    impl AfiSafi for [<$afi_name $safi_name Nlri>] { 
                        fn afi(&self) -> Afi { Afi::$afi_name }
                        fn afi_safi(&self) -> AfiSafiType {
                            AfiSafiType::[<$afi_name $safi_name>]
                        }
                    }

                    impl From<[<$afi_name $safi_name Nlri>]> for Nlri {
                        fn from(n: [<$afi_name $safi_name Nlri>]) -> Self {
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

    // TODO  adapt these from nlri.rs:
    //fn parse_nlri<'a, Octs: Octets>(
    //    parser: &mut Parser<'a, Octs>
    //) -> Result<Self::Item<Octs::Range<'a>>, ParseError>;

    //fn skip_nlri<Octs: Octets>(parser: &mut Parser<'_, Octs>)
    //    -> Result<(), ParseError>;

    //perhaps something like
    //fn parse(&mut parser) -> Result<Self, ParseError>;
    //so do not return Self::Item, but Self
    //though perhaps we need Self::item in the actual parsing logic

}


/// A type containing a BasicNlri.
pub trait HasBasicNlri {
    fn basic_nlri(&self) -> BasicNlri;
    
    // TODO
    // fn into_routeworkshop() -> RouteWorkshop<_>;
}

// blanket impl
impl <T>HasBasicNlri for T where T: AfiSafiNlri<Nlri = BasicNlri> {
    fn basic_nlri(&self) -> BasicNlri {
        self.nlri()
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
    1 => Ipv4 [ 1 => Unicast, 2 => Multicast ],
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

#[derive(Clone, Debug, Hash)]
pub struct Ipv4UnicastNlri(BasicNlri);
impl AfiSafiNlri for Ipv4UnicastNlri {
    type Nlri = BasicNlri;
    fn nlri(&self) -> Self::Nlri {
        self.0
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
//
#[derive(Clone, Debug, Hash)]
pub struct Ipv4UnicastAddpathNlri(BasicNlri, PathId);
impl AfiSafiNlri for Ipv4UnicastAddpathNlri {
    type Nlri = BasicNlri;
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
        self.1
    }
}

impl From<Ipv4UnicastAddpathNlri> for Ipv4UnicastNlri {
    fn from(n: Ipv4UnicastAddpathNlri) -> Self {
        Self(n.0)
    }
}
impl From<Ipv4UnicastAddpathNlri> for Nlri {
    fn from(n: Ipv4UnicastAddpathNlri) -> Nlri {
        Nlri::Ipv4Unicast(n.into())
    }
}

/// An Nlri containing a Path Id.
pub trait AddPath: AfiSafiNlri {
    fn path_id(&self) -> PathId;
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

        let nlri_type: Nlri = n.into();
        dbg!(&nlri_type);

        let mc = Ipv4MulticastNlri(b);
        let nlri_type2: Nlri = mc.clone().into();
        dbg!(&mc);

        dbg!(nlri_type2);
    }

    #[test]
    fn addpath() {
        let b = BasicNlri::with_path_id(
            Prefix::from_str("1.2.3.0/24").unwrap(),
            PathId::from_u32(12)
            );
        let n = Ipv4UnicastAddpathNlri(b, PathId::from_u32(13));
        dbg!(&n);
        let nlri: Nlri = n.clone().into();
        dbg!(&nlri.afi_safi());
        dbg!(&n.afi());
        dbg!(&n.path_id());
        dbg!(&b.path_id());
       
        // and this is why we need a distinc BasicNlriWithPathId type:
        //assert_eq!(n.path_id(), b.path_id().unwrap());
    }
}
