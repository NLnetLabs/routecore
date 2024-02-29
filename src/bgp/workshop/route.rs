use std::fmt::Debug;
use std::hash::Hash;
use std::marker::PhantomData;

use octseq::{Octets, OctetsFrom};
use serde::Serialize;

use crate::bgp::communities::Community;
use crate::bgp::message::update_builder::{ComposeError, MpReachNlriBuilder};
use crate::bgp::message::UpdateMessage;
use crate::bgp::path_attributes::{FromAttribute, PaMap};
use crate::bgp::{
    message::{nlri::Nlri, update_builder::StandardCommunitiesList},
    path_attributes::{
        ExtendedCommunitiesList, Ipv6ExtendedCommunitiesList,
        LargeCommunitiesList, PathAttribute, 
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
        PathAttribute::AsPath(value.to_hop_path())
    }
}

impl From<crate::bgp::aspath::AsPath<Vec<u8>>> for PathAttribute {
    fn from(value: crate::bgp::aspath::AsPath<Vec<u8>>) -> Self {
        PathAttribute::AsPath(value.to_hop_path())
    }
}


//------------ The Workshop --------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct RouteWorkshop<O, N>(N, PaMap, PhantomData<O>);

impl<Octs: Octets, N: Clone + Debug + Hash> RouteWorkshop<Octs, N> {
    pub fn new(nlri: N) -> Self {
        Self(nlri, PaMap::empty(), PhantomData)
    }

    pub fn from_pa_map(nlri: N, pa_map: PaMap) -> Self {
        Self(nlri, pa_map, PhantomData)
    }
        
    pub fn from_update_pdu(
        nlri: N,
        pdu: &UpdateMessage<Octs>,
    ) -> Result<Self, ComposeError>
    where
        for<'a> Vec<u8>: OctetsFrom<Octs::Range<'a>>,
    {
        PaMap::from_update_pdu(pdu)
            .map(|r| Self(nlri, r, PhantomData))
    }

    pub fn nlri(&self) -> &N {
        &self.0
    }

    pub fn set_attr<WA: WorkshopAttribute<N>>(
        &mut self,
        value: WA,
    ) -> Result<(), ComposeError> {
        WA::store(value, &mut self.1)
    }

    pub fn get_attr<A: FromAttribute + WorkshopAttribute<N>>(
        &self,
    ) -> Option<A> {
        self.1.get::<A>().or_else(|| A::retrieve(&self.1))
    }

    pub fn clone_into_route(&self) -> Route<N> {
        Route::<N>(self.0.clone(), self.1.clone())
    }

    pub fn into_route(self) -> Route<N> {
        Route::<N>(self.0, self.1)
    }

    pub fn attributes(&self) -> &PaMap {
        &self.1
    }

    pub fn attributes_mut(&mut self) -> &mut PaMap {
        &mut self.1
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
    crate::bgp::types::Origin
    crate::bgp::types::OriginatorId
    crate::bgp::path_attributes::AggregatorInfo
    crate::bgp::path_attributes::ExtendedCommunitiesList
    crate::bgp::path_attributes::AsPathLimitInfo
    crate::bgp::path_attributes::Ipv6ExtendedCommunitiesList
    crate::bgp::path_attributes::LargeCommunitiesList
    crate::bgp::path_attributes::ClusterIds
    crate::bgp::message::update_builder::StandardCommunitiesList
    crate::bgp::types::Otc
    crate::bgp::message::update_builder::MpReachNlriBuilder
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
            .map(|c| c.fmap(|c| Community::Standard(*c)))
            .unwrap_or_default();
        c.append(
            &mut attrs
                .get::<ExtendedCommunitiesList>()
                .map(|c| c.fmap(Community::Extended))
                .unwrap_or_default()
        );
        c.append(
            &mut attrs
                .get::<Ipv6ExtendedCommunitiesList>()
                .map(|c| c.fmap(Community::Ipv6Extended))
                .unwrap_or_default()
        );
        c.append(
            &mut attrs
                .get::<LargeCommunitiesList>()
                .map(|c| c.fmap(Community::Large))
                .unwrap_or_default()
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

impl FromAttribute for Vec<Community> { }

//------------ NlriWorkshop --------------------------------------------------

impl FromAttribute for crate::bgp::message::nlri::Nlri<Vec<u8>> { }

impl<N: Clone + Hash> WorkshopAttribute<N> for crate::bgp::message::nlri::Nlri<Vec<u8>> {
    fn retrieve(attrs: &PaMap) -> Option<Self>
    where
        Self: Sized {
        attrs.get::<MpReachNlriBuilder>().and_then(|mr| mr.first_nlri())
    }

    fn store(
        local_attr: Self,
        attrs: &mut PaMap,
    ) -> Result<(), ComposeError> {
        if let Some(mut nlri) = attrs.get::<MpReachNlriBuilder>() {
            nlri.set_nlri(local_attr)
        } else {
            Err(ComposeError::InvalidAttribute)
        }
    }
}

//------------ NextHopWorkshop -----------------------------------------------

impl FromAttribute for crate::bgp::types::NextHop { }

impl<N: Clone + Hash> WorkshopAttribute<N> for crate::bgp::types::NextHop {
    fn retrieve(attrs: &PaMap) -> Option<Self> {
        if let Some(next_hop) =
            attrs.get::<crate::bgp::types::ConventionalNextHop>()
        {
            Some(crate::bgp::types::NextHop::Unicast(next_hop.0.into()))
        } else if let Some(nlri) = attrs.get::<MpReachNlriBuilder>() {
            Some(*nlri.get_nexthop())
        } else {
            Some(crate::bgp::types::NextHop::Empty)
        }
    }

    fn store(
        local_attr: Self,
        attrs: &mut PaMap,
    ) -> Result<(), ComposeError> {
        if let Some(mut nlri) = attrs.get::<MpReachNlriBuilder>() {
            nlri.set_nexthop(local_attr)?;
            attrs.set(nlri).ok_or(ComposeError::InvalidAttribute)?;
            Ok(())
        } else {
            Err(ComposeError::InvalidAttribute)
        }
    }
}
