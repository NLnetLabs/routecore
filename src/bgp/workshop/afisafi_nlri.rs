use std::{fmt::Debug, hash::Hash};

use octseq::Octets;

use crate::{
    addr::Prefix,
    bgp::message::{
        nlri::{BasicNlri, FlowSpecNlri},
        update::AfiSafi,
    },
};

pub trait AfiSafiNlri<Octs>: Clone + Hash + Debug {
    type Nlri;
    fn nlri(&self) -> Self::Nlri;
    fn afi_safi() -> AfiSafi;
}

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
