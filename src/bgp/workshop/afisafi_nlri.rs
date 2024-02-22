use std::{fmt::Debug, hash::Hash};

use octseq::Octets;

use crate::{
    addr::Prefix,
    bgp::{message::{
        nlri::{BasicNlri, FlowSpecNlri, Nlri},
        update::AfiSafi, update_builder::ComposeError,
    }, path_attributes::PaMap, ParseError},
};

use super::route::RouteWorkshop;

//------------ AfiSafiNlri ---------------------------------------------------

pub trait AfiSafiNlri<Octs>: Clone + Hash + Debug {
    type Nlri;
    fn nlri(&self) -> Self::Nlri;
    fn afi_safi() -> AfiSafi;
}


//------------ HasBasicNlri --------------------------------------------------

pub trait HasBasicNlri {
    fn basic_nlri(&self) -> BasicNlri;
    fn make_route_with_nlri<O: Octets, M>(nlri: M, pa: &PaMap) 
    -> RouteWorkshop<O, M> where M: AfiSafiNlri<O, Nlri = BasicNlri>;
}


//------------ Ipv4UnicastNlri -----------------------------------------------

#[derive(Clone, Debug, Hash)]
pub struct Ipv4UnicastNlri(pub BasicNlri);

impl<Octs: Octets> AfiSafiNlri<Octs> for Ipv4UnicastNlri {
    type Nlri = BasicNlri;

    fn nlri(&self) -> Self::Nlri {
        self.0
    }

    fn afi_safi() -> AfiSafi {
        AfiSafi::Ipv4Unicast
    }
}

impl HasBasicNlri for Ipv4UnicastNlri {
    fn basic_nlri(&self) -> BasicNlri {
        self.0
    }

    fn make_route_with_nlri<O: Octets, M>(nlri: M, pa: &PaMap) 
    -> RouteWorkshop<O, M> where M: AfiSafiNlri<O, Nlri = BasicNlri> {
        RouteWorkshop::<O, M>::from_pa_map(nlri, pa.clone())
    }
}

impl TryFrom<crate::bgp::message::nlri::Nlri<bytes::Bytes>> 
    for Ipv4UnicastNlri {
    type Error = ComposeError;

    fn try_from(value: crate::bgp::message::nlri::Nlri<bytes::Bytes>)
    -> Result<Self, ComposeError> {
        if let Nlri::Unicast(n) = value {
            if n.prefix.is_v4() {
                Ok(Ipv4UnicastNlri(n))
            } else {
                Err(ComposeError::InvalidAttribute)
            }
        } else {
            Err(ComposeError::InvalidAttribute)
        }
    }
}

//------------ Ipv6UnicastNlri -----------------------------------------------

#[derive(Clone, Debug, Hash)]
pub struct Ipv6UnicastNlri(pub BasicNlri);

impl<Octs: Octets> AfiSafiNlri<Octs> for Ipv6UnicastNlri {
    type Nlri = BasicNlri;

    fn nlri(&self) -> Self::Nlri {
        self.0
    }

    fn afi_safi() -> AfiSafi {
        AfiSafi::Ipv6Unicast
    }
}

impl From<Prefix> for Ipv6UnicastNlri {
    fn from(value: Prefix) -> Self {
        Self(BasicNlri {
            prefix: value,
            path_id: None,
        })
    }
}

impl HasBasicNlri for Ipv6UnicastNlri {
    fn basic_nlri(&self) -> BasicNlri {
        self.0
    }

    fn make_route_with_nlri<O: Octets, M>(nlri: M, pa: &PaMap)
    -> RouteWorkshop<O, M> where M: AfiSafiNlri<O, Nlri = BasicNlri> {
        RouteWorkshop::<O, M>::from_pa_map(nlri, pa.clone())
    }
}

impl TryFrom<crate::bgp::message::nlri::Nlri<bytes::Bytes>> 
    for Ipv6UnicastNlri {
    type Error = ComposeError;

    fn try_from(value: crate::bgp::message::nlri::Nlri<bytes::Bytes>)
    -> Result<Self, ComposeError> {
        if let Nlri::Unicast(n) = value {
            if !n.prefix.is_v4() {
                Ok(Ipv6UnicastNlri(n))
            } else {
                Err(ComposeError::InvalidAttribute)
            }
        } else {
            Err(ComposeError::InvalidAttribute)
        }
    }
}


//------------ Ipv4MulticastNlri ---------------------------------------------

#[derive(Clone, Debug, Hash)]
pub struct Ipv4MulticastNlri(pub BasicNlri);

impl<Octs: Octets> AfiSafiNlri<Octs> for Ipv4MulticastNlri {
    type Nlri = BasicNlri;

    fn nlri(&self) -> Self::Nlri {
        self.0
    }

    fn afi_safi() -> AfiSafi {
        AfiSafi::Ipv4Multicast
    }
}

impl HasBasicNlri for Ipv4MulticastNlri {
    fn basic_nlri(&self) -> BasicNlri {
        self.0
    }

    fn make_route_with_nlri<O: Octets, M>(nlri: M, pa: &PaMap)
    -> RouteWorkshop<O, M> where M: AfiSafiNlri<O, Nlri = BasicNlri> {
        RouteWorkshop::<O, M>::from_pa_map(nlri, pa.clone())
    }
}

impl TryFrom<crate::bgp::message::nlri::Nlri<bytes::Bytes>> 
    for Ipv4MulticastNlri {
    type Error = ComposeError;

    fn try_from(value: crate::bgp::message::nlri::Nlri<bytes::Bytes>)
    -> Result<Self, ComposeError> {
        if let Nlri::Multicast(n) = value {
            if n.prefix.is_v4() {
                Ok(Ipv4MulticastNlri(n))
            } else {
                Err(ComposeError::InvalidAttribute)
            }
        } else {
            Err(ComposeError::InvalidAttribute)
        }
    }
}


//------------ Ipv6MulticastNlri ---------------------------------------------

#[derive(Clone, Debug, Hash)]
pub struct Ipv6MulticastNlri(pub BasicNlri);

impl<Octs: Octets> AfiSafiNlri<Octs> for Ipv6MulticastNlri {
    type Nlri = BasicNlri;

    fn nlri(&self) -> Self::Nlri {
        self.0
    }

    fn afi_safi() -> AfiSafi {
        AfiSafi::Ipv6Multicast
    }
}

impl TryFrom<crate::bgp::message::nlri::Nlri<bytes::Bytes>> 
    for Ipv6MulticastNlri {
    type Error = ComposeError;

    fn try_from(value: crate::bgp::message::nlri::Nlri<bytes::Bytes>)
    -> Result<Self, ComposeError> {
        if let Nlri::Multicast(n) = value {
            if !n.prefix.is_v4() {
                Ok(Ipv6MulticastNlri(n))
            } else {
                Err(ComposeError::InvalidAttribute)
            }
        } else {
            Err(ComposeError::InvalidAttribute)
        }
    }
}


//------------ Ipv4FlowSpecNlri ----------------------------------------------

#[derive(Clone, Debug, Hash)]
pub struct Ipv4FlowSpecNlri<O>(pub FlowSpecNlri<O>);

impl<Octs: Octets + Clone + Debug + Hash> AfiSafiNlri<Octs>
    for Ipv4FlowSpecNlri<Octs>
{
    type Nlri = Ipv4FlowSpecNlri<Octs>;

    fn nlri(&self) -> Self::Nlri {
        Ipv4FlowSpecNlri(self.0.clone())
    }

    fn afi_safi() -> AfiSafi {
        AfiSafi::Ipv4FlowSpec
    }
}

impl TryFrom<Nlri<Vec<u8>>> for Ipv4UnicastNlri {
    type Error = ParseError;

    fn try_from(val: Nlri<Vec<u8>>) -> Result<Self, ParseError> {
        if let Nlri::Unicast(b) = val {
            if b.prefix.is_v4() {
                return Ok(Ipv4UnicastNlri(b));
            }
        }
        Err(ParseError::Unsupported)
    }
}