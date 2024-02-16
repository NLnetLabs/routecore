use std::fmt::Debug;
use std::hash::Hash;

use octseq::{Octets, OctetsFrom};
use serde::Serialize;

use crate::bgp::communities::Community;
use crate::bgp::message::update_builder::{ComposeError, MpReachNlriBuilder};
use crate::bgp::message::UpdateMessage;
use crate::bgp::path_attributes::{PaMap, FromAttribute};
use crate::bgp::{
    message::{nlri::Nlri, update_builder::StandardCommunitiesList},
    path_attributes::{
        ExtendedCommunitiesList, Ipv6ExtendedCommunitiesList,
        LargeCommunitiesList, PathAttribute, PathAttributeType,
    },
};


//------------ TypedRoute ----------------------------------------------------

#[derive(Debug)]
pub enum TypedRoute<N: Clone + Debug + Hash> {
    Announce(Route<N>),
    Withdraw(Nlri<N>),
}


//------------ Route ---------------------------------------------------------

#[derive(Debug, Eq, PartialEq, Clone, Hash, Serialize)]
pub struct Route<N: Clone + Debug + Hash>(N, PaMap);

impl<N: Clone + Debug + Hash> Route<N> {
    pub fn new(nlri: N, attrs: PaMap) -> Self {
        Self(nlri, attrs)
    }

    pub fn nlri(&self) -> &N {
        &self.0
    }

    pub fn get_attr<A: FromAttribute + Clone>(&self) -> Option<A> {
        if A::attribute_type().is_some() {
            self.1.get::<A>()
        } else {
            None
        }
    }

    pub fn attributes(&self) -> &PaMap {
        &self.1
    }

    pub fn attributes_mut(&mut self) -> &mut PaMap {
        &mut self.1
    }
}


//------------ From impls for PathAttribute ----------------------------------

impl From<crate::bgp::aspath::AsPath<bytes::Bytes>> for PathAttribute {
    fn from(value: crate::bgp::aspath::AsPath<bytes::Bytes>) -> Self {
        PathAttribute::AsPath(crate::bgp::path_attributes::AsPath(
            value.to_hop_path(),
        ))
    }
}

impl From<crate::bgp::aspath::AsPath<Vec<u8>>> for PathAttribute {
    fn from(value: crate::bgp::aspath::AsPath<Vec<u8>>) -> Self {
        PathAttribute::AsPath(crate::bgp::path_attributes::AsPath(
            value.to_hop_path(),
        ))
    }
}


//------------ The Workshop --------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RouteWorkshop<N>(Option<N>, Option<PaMap>);

impl<N: Clone + Debug + Hash> RouteWorkshop<N> {
    pub fn from_update_pdu<Octs: Octets>(
        pdu: &UpdateMessage<Octs>,
    ) -> Result<Self, ComposeError>
    where
        for<'a> Vec<u8>: OctetsFrom<Octs::Range<'a>>,
    {
        PaMap::from_update_pdu(pdu)
            .map(|r| Self(None, Some(r)))
    }

    pub fn nlri(&self) -> &Option<N> {
        &self.0
    }

    pub fn set_attr<WA: WorkshopAttribute<N>>(
        &mut self,
        value: WA,
    ) -> Result<(), ComposeError> {
        let mut res = Err(ComposeError::InvalidAttribute);
        if let Some(b) = &mut self.1 {
            res = WA::store(value, b);
        }
        res
    }

    pub fn get_attr<A: FromAttribute + WorkshopAttribute<N>>(
        &self,
    ) -> Option<A> {
        self.1
            .as_ref()
            .and_then(|b| b.get::<A>().or_else(|| <A>::retrieve(b)))
    }

    pub fn clone_into_route(&self) -> Option<Route<N>> {
        match self {
            RouteWorkshop(Some(nlri), Some(pab)) => {
                Some(Route::<N>(nlri.clone(), pab.clone()))
            }
            _ => None,
        }
    }

    pub fn into_route(self) -> Option<Route<N>> {
        match self {
            RouteWorkshop(Some(nlri), Some(pab)) => {
                Some(Route::<N>(nlri, pab))
            }
            _ => None,
        }
    }

    pub fn make_route_with_nlri(&self, nlri: N) -> Option<Route<N>> {
        match self {
            RouteWorkshop(_, Some(pab)) => {
                Some(Route::<N>(nlri.clone(), pab.clone()))
            }
            _ => None,
        }
    }
}

macro_rules! impl_workshop {
    (
        $( $attr:ty )+
    ) => {
        $(
            impl<N: Clone + Hash + Debug> WorkshopAttribute<N> for $attr {
                fn store(local_attrs: Self, attrs: &mut PaMap) ->
                    Result<(), ComposeError> { attrs.set(local_attrs); Ok(()) }
                fn retrieve(_attrs: &PaMap) ->
                    Option<Self> { None }
            }
        )+
    }
}

impl_workshop!(
    crate::bgp::aspath::HopPath
    crate::bgp::types::LocalPref
    crate::bgp::types::MultiExitDisc
    crate::bgp::types::OriginType
    crate::bgp::types::OriginatorId
    crate::bgp::path_attributes::AggregatorInfo
    crate::bgp::path_attributes::ExtendedCommunitiesList
    crate::bgp::path_attributes::AsPathLimitInfo
    crate::bgp::path_attributes::Ipv6ExtendedCommunitiesList
    crate::bgp::path_attributes::LargeCommunitiesList
    crate::bgp::path_attributes::ClusterIds
    crate::bgp::message::update_builder::StandardCommunitiesList
    crate::bgp::types::Otc
);

//------------ WorkshopAttribute ---------------------------------------------

pub trait WorkshopAttribute<N>: FromAttribute {
    fn retrieve(attrs: &PaMap) -> Option<Self>
    where
        Self: Sized;
    fn store(
        local_attrs: Self,
        attrs: &mut PaMap,
    ) -> Result<(), ComposeError>;
}

//------------ CommunitiesWorkshop -------------------------------------------

impl<N: Clone + Hash + Debug> WorkshopAttribute<N> for Vec<Community> {
    fn retrieve(attrs: &PaMap) -> Option<Self> {
        let mut c = attrs
            .get::<StandardCommunitiesList>()
            .unwrap()
            .fmap(|c| Community::Standard(*c));
        c.append(
            &mut attrs
                .get::<ExtendedCommunitiesList>()
                .unwrap()
                .fmap(Community::Extended),
        );
        c.append(
            &mut attrs
                .get::<Ipv6ExtendedCommunitiesList>()
                .unwrap()
                .fmap(Community::Ipv6Extended),
        );
        c.append(
            &mut attrs
                .get::<LargeCommunitiesList>()
                .unwrap()
                .fmap(Community::Large),
        );

        Some(c)
    }

    fn store(
        local_attr: Self,
        attrs: &mut PaMap,
    ) -> Result<(), ComposeError> {
        for comm in local_attr {
            match comm {
                Community::Standard(c) => {
                    if let Some(mut b) =
                        attrs.get::<StandardCommunitiesList>()
                    {
                        b.add_community(c)
                    }
                }
                Community::Extended(c) => {
                    if let Some(mut b) =
                        attrs.get::<ExtendedCommunitiesList>()
                    {
                        b.add_community(c)
                    }
                }
                Community::Ipv6Extended(c) => {
                    if let Some(mut b) =
                        attrs.get::<Ipv6ExtendedCommunitiesList>()
                    {
                        b.add_community(c)
                    }
                }
                Community::Large(_) => todo!(),
            };
        }

        Ok(())
    }
}

impl FromAttribute for Vec<Community> {
    fn from_attribute(_value: PathAttribute) -> Option<Self> {
        None
    }

    fn attribute_type() -> Option<PathAttributeType> {
        None
    }
}

//------------ NextHopWorkshop -----------------------------------------------

impl FromAttribute for crate::bgp::types::NextHop {
    fn attribute_type() -> Option<PathAttributeType> {
        None
    }

    fn from_attribute(_value: PathAttribute) -> Option<Self> {
        None
    }
}

impl<N: Clone + Hash> WorkshopAttribute<N> for crate::bgp::types::NextHop {
    fn retrieve(attrs: &PaMap) -> Option<Self> {
        if let Some(next_hop) =
            attrs.get::<crate::bgp::types::ConventionalNextHop>()
        {
            Some(crate::bgp::types::NextHop::Unicast(next_hop.0.into()))
        } else if let Some(nlri) =
            attrs.get::<MpReachNlriBuilder>()
        {
            Some(*nlri.get_nexthop())
        } else {
            Some(crate::bgp::types::NextHop::Empty)
        }
    }

    fn store(
        local_attr: Self,
        attrs: &mut PaMap,
    ) -> Result<(), ComposeError> {
        if let Some(mut nlri) =
            attrs.get::<MpReachNlriBuilder>()
        {
            nlri.set_nexthop(local_attr)
        } else {
            Err(ComposeError::InvalidAttribute)
        }
    }
}
