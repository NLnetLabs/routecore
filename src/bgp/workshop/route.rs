use std::fmt::Debug;
use std::hash::Hash;
//use std::marker::PhantomData;

use octseq::{Octets, OctetsFrom, Parser};
use serde::Serialize;

use crate::addr::Prefix;
use crate::bgp::communities::Community;
use crate::bgp::message::update_builder::{ComposeError, /*MpReachNlriBuilder*/};
use crate::bgp::message::UpdateMessage;
use crate::bgp::nlri::common::PathId;
use crate::bgp::nlri::flowspec::FlowSpecNlri;
use crate::bgp::path_attributes::{FromAttribute, PaMap};
use crate::bgp::ParseError;
use crate::bgp::{
    message::{
        //nlri::Nlri,
        update_builder::StandardCommunitiesList
    },
    path_attributes::{
        ExtendedCommunitiesList, Ipv6ExtendedCommunitiesList,
        LargeCommunitiesList, PathAttribute, 
    },
};
use crate::bgp::nlri::afisafi::{Addpath, Ipv4MulticastNlri, Ipv6MulticastNlri, IsPrefix};
use crate::bgp::nlri::afisafi::{AfiSafiType, Ipv4UnicastNlri, Ipv6UnicastNlri};
use crate::bgp::nlri::afisafi::{Ipv4UnicastAddpathNlri, Ipv6UnicastAddpathNlri};
use crate::bgp::nlri::afisafi::{Ipv4MulticastAddpathNlri, Ipv6MulticastAddpathNlri};
use crate::bgp::nlri::afisafi::{iter_for_afi_safi, AfiSafiNlri, AfiSafiParse, Nlri};


//------------ TypedRoute ----------------------------------------------------

#[derive(Debug)]
pub enum TypedRoute<N: Clone + Debug + Hash> {
    Announce(Route<N>),
    Withdraw(Nlri<N>),
}


//------------ Route ---------------------------------------------------------

#[derive(Debug, Eq, PartialEq, Clone, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
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

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct RouteWorkshop<N>(N, PaMap);

impl<N: Clone + Debug + Hash> RouteWorkshop<N> {
    pub fn new(nlri: N) -> Self {
        Self(nlri, PaMap::empty())
    }

    pub fn from_pa_map(nlri: N, pa_map: PaMap) -> Self {
        Self(nlri, pa_map)
    }
        
    pub fn from_update_pdu<Octs: Octets>(
        nlri: N,
        pdu: &UpdateMessage<Octs>,
    ) -> Result<Self, ComposeError>
    where
        for<'a> Vec<u8>: OctetsFrom<Octs::Range<'a>>,
    {
        PaMap::from_update_pdu(pdu)
            .map(|r| Self(nlri, r))
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

    pub fn get_attr<A: WorkshopAttribute<N>>(
        &self,
    ) -> Option<A> {
        self.1.get::<A>().or_else(|| A::retrieve(&self.1))
    }

    // pub fn clone_into_route(&self) -> Route<N> {
    //     Route::<N>(self.0.clone(), self.1.clone())
    // }

    // pub fn into_route(self) -> Route<N> {
    //     Route::<N>(self.0, self.1)
    // }

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
    //crate::bgp::message::update_builder::MpReachNlriBuilder
);

/*
impl<A, N: Clone + Hash + Debug> WorkshopAttribute<N> for crate::bgp::message::update_builder::MpReachNlriBuilder<A> {
    fn store(local_attrs: Self, attrs: &mut PaMap) ->
        Result<(), ComposeError> { attrs.set(local_attrs); Ok(()) }
    fn retrieve(_attrs: &PaMap) ->
        Option<Self> { None }
}
*/



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

impl FromAttribute for Nlri<Vec<u8>> { }

/*
impl<N: Clone + Hash> WorkshopAttribute<N> for Nlri<Vec<u8>> {
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
*/

//------------ NextHopWorkshop -----------------------------------------------

impl FromAttribute for crate::bgp::types::NextHop { }

/*
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
*/

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct BasicNlri {
    pub ty: AfiSafiType,
    pub prefix: Prefix,
    pub path_id: Option<PathId>
}

impl BasicNlri {
    pub fn prefix(&self) -> Prefix {
        self.prefix
    }

    pub fn path_id(&self) -> Option<PathId> {
        self.path_id
    }

    pub fn get_type(&self) -> AfiSafiType {
        self.ty
    }
}


//------------ Ipv4 conversions ----------------------------------------------

impl From<Ipv4UnicastNlri> for BasicNlri {
    fn from(value: Ipv4UnicastNlri) -> Self {
        Self {
            ty: AfiSafiType::Ipv4Unicast,
            prefix: value.prefix(),
            path_id: None
        }
    }
}

impl From<Ipv4UnicastAddpathNlri> for BasicNlri {
    fn from(value: Ipv4UnicastAddpathNlri) -> Self {
        Self {
            ty: AfiSafiType::Ipv4Unicast,
            prefix: value.prefix(),
            path_id: Some(value.path_id())
        }
    }
}

impl From<Ipv4MulticastNlri> for BasicNlri {
    fn from(value: Ipv4MulticastNlri) -> Self {
        Self {
            ty: AfiSafiType::Ipv4Unicast,
            prefix: value.prefix(),
            path_id: None
        }
    }
}

impl From<Ipv4MulticastAddpathNlri> for BasicNlri {
    fn from(value: Ipv4MulticastAddpathNlri) -> Self {
        Self {
            ty: AfiSafiType::Ipv4Unicast,
            prefix: value.prefix(),
            path_id: Some(value.path_id())
        }
    }
}

//------------ Ipv6 conversions ----------------------------------------------

impl From<Ipv6UnicastNlri> for BasicNlri {
    fn from(value: Ipv6UnicastNlri) -> Self {
        Self {
            ty: AfiSafiType::Ipv6Unicast,
            prefix: value.prefix(),
            path_id: None
        }
    }
}

impl From<Ipv6UnicastAddpathNlri> for BasicNlri {
    fn from(value: Ipv6UnicastAddpathNlri) -> Self {
        Self {
            ty: AfiSafiType::Ipv6Unicast,
            prefix: value.prefix(),
            path_id: Some(value.path_id())
        }
    }
}

impl From<Ipv6MulticastNlri> for BasicNlri {
    fn from(value: Ipv6MulticastNlri) -> Self {
        Self {
            ty: AfiSafiType::Ipv6Unicast,
            prefix: value.prefix(),
            path_id: None
        }
    }
}

impl From<Ipv6MulticastAddpathNlri> for BasicNlri {
    fn from(value: Ipv6MulticastAddpathNlri) -> Self {
        Self {
            ty: AfiSafiType::Ipv6Unicast,
            prefix: value.prefix(),
            path_id: Some(value.path_id())
        }
    }
}

/// Creates a Vec with all of the single `NLRIs` for one type of `NLRI` and
/// converts all the resulting values to `T`.
/// 
/// The type of `NLRI` is specified with the `AF` type argument. If the
/// specified `NLRI` type is not present, it will return an empty `Vec`. The
/// type `T` should be able to convert all the different `NLRI` types in the
/// Vec to `T`.
pub fn into_wrapped_rws_vec<
    'a,
    O: Octets + Clone + Debug + Hash + 'a,
    P: 'a + Octets<Range<'a> = O>,
    AF: AfiSafiNlri + AfiSafiParse<'a, O, P, Output = AF>,
    AFT: Clone + Debug + Hash + From<AF>,
    T: From<RouteWorkshop<AFT>>,
>(
    update: &'a UpdateMessage<P>
) -> Vec<T> where Vec<u8>: OctetsFrom<P::Range<'a>> {
    
    let mut pa_map = PaMap::from_update_pdu(update).unwrap();
    let parser = update.nlri_parser().unwrap().unwrap();

    iter_for_afi_safi::<'_, _, _, AF>(parser)
        .filter_map(|n: Result<AF::Output, ParseError>| {
            if let Ok(nlri) = n {
                Some(RouteWorkshop::from_pa_map(
                    AFT::from(nlri), std::mem::take(&mut pa_map)).into()
                )
            } else {
                None
            }
        })
    .collect::<Vec<_>>()
}

// Internal version that takes a parser and a pa_map, instead of the
// `UpdateMessage`. Should not be public because it will try to parse for any
// AfiSafiNlri type, which could result in malformed resulting `NLRI`, if
// specifying non-present NRLI.
pub(crate) fn _into_wrapped_rws_vec<
    'a,
    O: Octets + Clone + Debug + Hash + 'a,
    P: 'a + Octets<Range<'a> = O>,
    AF: AfiSafiNlri + AfiSafiParse<'a, O, P, Output = AF>,
    AFT: Clone + Debug + Hash + From<AF>,
    T: From<RouteWorkshop<AFT>>,
>(
    parser: Parser<'a, P>,
    mut pa_map: PaMap,
) -> Vec<T> where Vec<u8>: OctetsFrom<O::Range<'a>> {
    iter_for_afi_safi::<'_, _, _, AF>(parser)
        .filter_map(|n: Result<AF::Output, ParseError>| {
            if let Ok(nlri) = n {
                Some(RouteWorkshop::from_pa_map(
                    AFT::from(nlri), std::mem::take(&mut pa_map)).into()
                )
            } else {
                None
            }
        })
    .collect::<Vec<_>>()
}

/// Creates a Vec with all of the single `NLRIs` for all `NLRI` and converts
/// all the values in `T`.
/// 
/// The type of `NLRI` is specified with the `AF` type argument. If the
/// specified `NLRI` type is not present, it will return an empty `Vec`. The
/// type `T` should be able to convert all the different `NLRI` types in the
/// Vec to `T`.
pub fn explode_into_wrapped_rws_vec<
    'a,
    O: Octets + Octets<Range<'a> = O> + Clone + Debug + Hash + 'a,
    P: 'a + Octets<Range<'a> = O>,
    T: From<RouteWorkshop<BasicNlri>> +
        From<RouteWorkshop<FlowSpecNlri<O>>>,
>(
    afi_safis: impl Iterator<Item = AfiSafiType>,
    add_path_cap: bool,
    update: &'a UpdateMessage<O>,
) -> Result<Vec<T>, ParseError> where Vec<u8>: OctetsFrom<O::Range<'a>> {

    let pa_map = PaMap::from_update_pdu(update).unwrap();
    let parser: Parser<'a, O> = update.nlri_parser()?.unwrap();
    let mut res = vec![];

    for afi_safi in afi_safis {
        match (afi_safi, add_path_cap) {
            (AfiSafiType::Ipv4Unicast, false) => { 
                res.extend(
                    _into_wrapped_rws_vec::<'_, _, _, Ipv4UnicastNlri, BasicNlri, T>(parser, pa_map.clone())
                );
            }
            (AfiSafiType::Ipv4Unicast, true) => {
                res.extend(
                    _into_wrapped_rws_vec::<'_, _, _, Ipv4UnicastAddpathNlri, BasicNlri, T>(parser, pa_map.clone())
                );
            }
            (AfiSafiType::Ipv6Unicast, false) => { 
                res.extend(
                    _into_wrapped_rws_vec::<'_, _, _, Ipv6UnicastNlri, BasicNlri, T>(parser, pa_map.clone())
                );
            },
            (AfiSafiType::Ipv6Unicast, true) => { 
                res.extend(
                    _into_wrapped_rws_vec::<'_, _, _, Ipv6UnicastAddpathNlri, BasicNlri, T>(parser, pa_map.clone())
                );
            },
            (AfiSafiType::Ipv4Multicast, false) => { 
                res.extend(
                    _into_wrapped_rws_vec::<'_, _, _, Ipv4MulticastNlri, BasicNlri, T>(parser, pa_map.clone())
                );
            },
            (AfiSafiType::Ipv4Multicast, true) => { 
                res.extend(
                    _into_wrapped_rws_vec::<'_, _, _, Ipv4UnicastAddpathNlri, BasicNlri, T>(parser, pa_map.clone())
                )
            },
            (AfiSafiType::Ipv6Multicast, false) => { 
                res.extend(
                    _into_wrapped_rws_vec::<'a, _, _,
                        Ipv6MulticastNlri, BasicNlri, T>(
                            parser, pa_map.clone()
                        )
                );
            },
            (AfiSafiType::Ipv6Multicast, true) => { 
                res.extend(
                    _into_wrapped_rws_vec::<'_, _, _,
                        Ipv6MulticastAddpathNlri, BasicNlri, T>(
                            parser, pa_map.clone()
                        )
                );
            },
            (AfiSafiType::Ipv4MplsUnicast, true) => todo!(),
            (AfiSafiType::Ipv4MplsUnicast, false) => todo!(),
            (AfiSafiType::Ipv6MplsUnicast, true) => todo!(),
            (AfiSafiType::Ipv6MplsUnicast, false) => todo!(),
            (AfiSafiType::Ipv4MplsVpnUnicast, true) => todo!(),
            (AfiSafiType::Ipv4MplsVpnUnicast, false) => todo!(),
            (AfiSafiType::Ipv6MplsVpnUnicast, true) => todo!(),
            (AfiSafiType::Ipv6MplsVpnUnicast, false) => todo!(),
            (AfiSafiType::Ipv4RouteTarget, true) => todo!(),
            (AfiSafiType::Ipv4RouteTarget, false) => todo!(),
            (AfiSafiType::Ipv4FlowSpec, true) => {
                res.extend(
                    _into_wrapped_rws_vec::<'_, _, _,
                        crate::bgp::nlri::afisafi::Ipv4FlowSpecNlri<O>,
                        crate::bgp::nlri::flowspec::FlowSpecNlri<O>, T>(
                            parser, pa_map.clone()
                    )
                );
            },
            (AfiSafiType::Ipv4FlowSpec, false) => todo!(),
            (AfiSafiType::Ipv6FlowSpec, true) => {
                res.extend(
                    _into_wrapped_rws_vec::<'_, _, _,
                        crate::bgp::nlri::afisafi::Ipv6FlowSpecNlri<O>,
                        crate::bgp::nlri::flowspec::FlowSpecNlri<O>, T>(
                            parser, pa_map.clone()
                    )
                );
            },
            (AfiSafiType::Ipv6FlowSpec, false) => todo!(),
            (AfiSafiType::L2VpnVpls, true) => todo!(),
            (AfiSafiType::L2VpnVpls, false) => todo!(),
            (AfiSafiType::L2VpnEvpn, true) => todo!(),
            (AfiSafiType::L2VpnEvpn, false) => todo!(),
            (AfiSafiType::Unsupported(_, _), _) => todo!()
        };
    }
    Ok(res)
}