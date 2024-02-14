use std::fmt::Debug;
use std::hash::Hash;

use octseq::{Octets, OctetsFrom};
use serde::Serialize;

use crate::bgp::communities::Community;
use crate::bgp::message::update_builder::ComposeError;
use crate::bgp::message::UpdateMessage;
use crate::bgp::path_attributes::PaMap;
use crate::bgp::{
    message::{nlri::Nlri, update_builder::StandardCommunitiesList},
    path_attributes::{
        AttributesMap, ExtendedCommunitiesList, Ipv6ExtendedCommunitiesList,
        LargeCommunitiesList, PathAttribute, PathAttributeType,
    },
};

#[derive(Debug)]
pub enum TypedRoute<N: Clone + Debug + Hash> {
    Announce(Route<N>),
    Withdraw(Nlri<N>),
}

#[derive(Debug, Eq, PartialEq, Clone, Hash, Serialize)]
pub struct Route<N: Clone + Debug + Hash>(N, AttributesMap);

impl<N: Clone + Debug + Hash> Route<N> {
    pub fn new(nlri: N, attrs: AttributesMap) -> Self {
        Self(nlri, attrs)
    }

    pub fn nlri(&self) -> &N {
        &self.0
    }

    pub fn get_attr<A: FromAttribute>(&self) -> Option<A> {
        if let Some(attr_type) = A::attribute_type() {
            self.1
                .get(&attr_type)
                .and_then(|a| A::from_attribute(a.clone()))
        } else {
            None
        }
    }

    pub fn attributes(&self) -> &AttributesMap {
        &self.1
    }

    pub fn attributes_mut(&mut self) -> &mut AttributesMap {
        &mut self.1
    }
}

pub trait FromAttribute {
    fn from_attribute(value: PathAttribute) -> Option<Self>
    where
        Self: Sized;
    fn attribute_type() -> Option<PathAttributeType>;
}

//------------ From impls for PathAttribute ----------------------------------

// These conversions are used on the `set()` method of the
// PaMap, so not in the Workshop!

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

#[derive(Debug)]
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
        attr: WA,
    ) -> Result<(), ComposeError> {
        let mut res = Err(ComposeError::InvalidAttribute);
        if let Some(b) = &mut self.1 {
            res = WA::to_value(attr, b);
        }
        res
    }

    pub fn get_attr<A: FromAttribute + WorkshopAttribute<N>>(
        &self,
    ) -> Option<A> {
        self.1
            .as_ref()
            .and_then(|b| b.get::<A>().or_else(|| <A>::into_retrieved(b)))
    }

    pub fn make_route(&self) -> Option<Route<N>> {
        match self {
            RouteWorkshop(Some(nlri), Some(pab)) => {
                Some(Route::<N>(nlri.clone(), pab.attributes().clone()))
            }
            _ => None,
        }
    }

    pub fn make_route_with_nlri(&self, nlri: N) -> Option<Route<N>> {
        match self {
            RouteWorkshop(_, Some(pab)) => {
                Some(Route::<N>(nlri.clone(), pab.attributes().clone()))
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
                fn to_value(local_attrs: Self, attrs: &mut PaMap) ->
                    Result<(), ComposeError> { attrs.set(local_attrs); Ok(()) }
                fn into_retrieved(_attrs: &PaMap) ->
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
    fn into_retrieved(attrs: &PaMap) -> Option<Self>
    where
        Self: Sized;
    fn to_value(
        local_attrs: Self,
        attrs: &mut PaMap,
    ) -> Result<(), ComposeError>;
}

//------------ CommunitiesWorkshop -------------------------------------------

impl<N: Clone + Hash + Debug> WorkshopAttribute<N> for Vec<Community> {
    fn into_retrieved(attrs: &PaMap) -> Option<Self> {
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

    fn to_value(
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
    fn into_retrieved(attrs: &PaMap) -> Option<Self> {
        if let Some(next_hop) =
            attrs.get::<crate::bgp::types::ConventionalNextHop>()
        {
            Some(crate::bgp::types::NextHop::Unicast(next_hop.0.into()))
        } else if let Some(PathAttribute::MpReachNlri(nlri)) =
            attrs.attributes().get(&PathAttributeType::MpReachNlri)
        {
            Some(*(nlri.clone().inner().get_nexthop()))
        } else {
            Some(crate::bgp::types::NextHop::Empty)
        }
    }

    fn to_value(
        local_attr: Self,
        attrs: &mut PaMap,
    ) -> Result<(), ComposeError> {
        if let Some(PathAttribute::MpReachNlri(nlri)) =
            attrs.attributes().get(&PathAttributeType::MpReachNlri)
        {
            nlri.clone().inner().set_nexthop(local_attr)
        } else {
            Err(ComposeError::InvalidAttribute)
        }
    }
}
