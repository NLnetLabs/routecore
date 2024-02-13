use std::{fmt::Debug, hash::Hash};

use octseq::Octets;

use crate::{addr::Prefix, bgp::message::{nlri::{BasicNlri, FlowSpecNlri}, update::AfiSafi}};

pub trait AfiSafiNlri<O>: Clone + Hash + Debug {
    type Nlri;
    fn nlri(&self) -> Self::Nlri;
    fn afi_safi() -> AfiSafi;
    // fn make_route(&self, path_attributes: PathAttributesBuilder) -> impl RotoType;
}

#[derive(Clone, Debug, Hash)]
pub struct Ipv4UnicastNlri(pub BasicNlri);
impl<O: Octets> AfiSafiNlri<O> for Ipv4UnicastNlri {
    type Nlri = BasicNlri;

    fn nlri(&self) -> Self::Nlri { self.0 }

    fn afi_safi() -> AfiSafi {
        AfiSafi::Ipv4Unicast
    }

    // fn make_route(&self, status: NlriStatus, path_attributes: PathAttributesBuilder) -> impl RotoType {
    //     Route::<BasicNlri> {
    //         nlri: self.0,
    //         status,
    //         // afi_safi: AfiSafi::Ipv4Unicast,
    //         path_attributes: path_attributes.into_inner()
    //     }
    // }
}

#[derive(Clone, Debug, Hash)]
pub struct Ipv6UnicastNlri(pub BasicNlri);

impl<O: Octets> AfiSafiNlri<O> for Ipv6UnicastNlri {
    type Nlri = BasicNlri;

    fn nlri(&self) -> Self::Nlri { self.0 }

    fn afi_safi() -> AfiSafi {
        AfiSafi::Ipv6Unicast
    }

    // fn make_route(&self, status: NlriStatus, path_attributes: PathAttributesBuilder) -> impl RotoType {
    //     Route::<BasicNlri> {
    //         nlri: self.0,
    //         status,
    //         path_attributes: path_attributes.into_inner()
    //     }
    // }
}

impl From<Prefix> for Ipv6UnicastNlri {
    fn from(value: Prefix) -> Self {
        Self(BasicNlri { prefix: value, path_id: None })
    }
}

#[derive(Clone, Debug, Hash)]
pub struct Ipv4MulticastNlri(pub BasicNlri);

impl<O: Octets> AfiSafiNlri<O> for Ipv4MulticastNlri {
    type Nlri = BasicNlri;

    fn nlri(&self) -> Self::Nlri { self.0 }

    fn afi_safi() -> AfiSafi {
        AfiSafi::Ipv4Multicast
    }

    // fn make_route(&self, status: NlriStatus, path_attributes: PathAttributesBuilder) -> impl RotoType {
    //     Route::<BasicNlri> {
    //         nlri: self.0,
    //         status,
    //         path_attributes: path_attributes.into_inner()
    //     }
    // }
}

#[derive(Clone, Debug, Hash)]
pub struct Ipv6MulticastNlri(pub BasicNlri);

impl<O: Octets> AfiSafiNlri<O> for Ipv6MulticastNlri {
    type Nlri = BasicNlri;

    fn nlri(&self) -> Self::Nlri { self.0 }

    fn afi_safi() -> AfiSafi {
        AfiSafi::Ipv6Multicast
    }

    // fn make_route(&self, status: NlriStatus, path_attributes: PathAttributesBuilder) -> impl RotoType {
    //     Route::<BasicNlri> {
    //         nlri: self.0,
    //         status,
    //         path_attributes: path_attributes.into_inner()
    //     }
    // }
}

#[derive(Clone, Debug, Hash)]
pub struct Ipv4FlowSpecNlri<O>(pub FlowSpecNlri<O>);

impl<O: Octets + Clone + Debug + Hash> AfiSafiNlri<O> for Ipv4FlowSpecNlri<O> {
    type Nlri = Ipv4FlowSpecNlri<O>;

    fn nlri(&self) -> Self::Nlri { Ipv4FlowSpecNlri(self.0.clone()) }

    fn afi_safi() -> AfiSafi {
        AfiSafi::Ipv4FlowSpec
    }

    // fn make_route(&self, status: NlriStatus, path_attributes: PathAttributesBuilder) -> impl RotoType {
    //     Route::<FlowSpecNlri<bytes::Bytes>> {
    //         nlri: self.0.clone(),
    //         status,
    //         path_attributes: path_attributes.into_inner()
    //     }
    // }
}
