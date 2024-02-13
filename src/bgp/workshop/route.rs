use std::fmt::Debug;
use std::hash::Hash;
use std::marker::PhantomData;
use std::net::Ipv4Addr;

use octseq::{Octets, OctetsFrom};
use serde::Serialize;

use crate::bgp::communities::Community;
use crate::bgp::message::update::MultiExitDisc;
use crate::bgp::message::update_builder::ComposeError;
use crate::bgp::message::UpdateMessage;
use crate::bgp::path_attributes::{Attribute, PathAttributesBuilder};
use crate::{
    asn::Asn,
    bgp::{
        aspath::HopPath,
        message::{
            nlri::Nlri, update::OriginType,
            update_builder::StandardCommunitiesBuilder,
        },
        path_attributes::{
            AggregatorInfo, As4Aggregator, AsPathLimitInfo, AtomicAggregate,
            AttributesMap, ClusterIds, ClusterList, Connector,
            ExtendedCommunitiesList, Ipv6ExtendedCommunitiesList,
            LargeCommunitiesList, NextHop, OriginatorId, Otc, PathAttribute,
            PathAttributeType,
        },
    },
};

use super::afisafi_nlri::AfiSafiNlri;

#[derive(Debug)]
pub enum TypedRoute<N: Clone + Debug + Hash + AfiSafiNlri<Octs>> {
    Announce(Route<N>),
    Withdraw(Nlri<N>),
}

#[derive(Debug, Eq, PartialEq, Clone, Hash, Serialize)]
pub struct Route<N: Clone + Debug + Hash>(N, AttributesMap);

impl<N: Clone + Debug + Hash> Route<N> {
    pub fn new(nlri: N, attrs: AttributesMap) -> Self {
        Self ( nlri, attrs )
    }

    pub fn nlri(&self) -> &N {
        &self.0
    }

    pub fn get_attr<A: FromAttribute>(&self) -> Option<A::Output> {
        self.1
            .get(&A::attribute_type())
            .and_then(|a| A::from_attribute(a.clone()))
    }

    pub fn attributes(&self) -> &AttributesMap {
        &self.1
    }

    pub fn attributes_mut(&mut self) -> &mut AttributesMap {
        &mut self.1
    }
}

pub trait FromAttribute {
    type Output;
    fn from_attribute(value: PathAttribute) -> Option<Self::Output>;
    fn attribute_type() -> PathAttributeType;
}

macro_rules! from_attributes_impl {
    (
        $( $variant:ident($output_ty:ty), $attr:ty )+
    ) => {
        $(
            impl FromAttribute for $attr {
                type Output = $output_ty;

                fn from_attribute(value: PathAttribute) -> Option<$output_ty> {
                    if let PathAttribute::$variant(pa) = value {
                        Some(pa.inner())
                    } else {
                        None
                    }
                }

                fn attribute_type() -> PathAttributeType {
                    PathAttributeType::$variant
                }
            }
        )+
    }
}

//        ident(ty)
// 1   => Origin(crate::bgp::types::OriginType), Flags::WELLKNOWN,
// 2   => AsPath(HopPath), Flags::WELLKNOWN,
// 3   => NextHop(Ipv4Addr), Flags::WELLKNOWN,
// 4   => MultiExitDisc(u32), Flags::OPT_NON_TRANS,
// 5   => LocalPref(u32), Flags::WELLKNOWN,
// 6   => AtomicAggregate(()), Flags::WELLKNOWN,
// 7   => Aggregator(AggregatorInfo), Flags::OPT_TRANS,
// 8   => Communities(StandardCommunitiesBuilder), Flags::OPT_TRANS,
// 9   => OriginatorId(Ipv4Addr), Flags::OPT_NON_TRANS,
// 10  => ClusterList(ClusterIds), Flags::OPT_NON_TRANS,
// 14  => MpReachNlri(MpReachNlriBuilder), Flags::OPT_NON_TRANS,
// 15  => MpUnreachNlri(MpUnreachNlriBuilder), Flags::OPT_NON_TRANS,
// 16  => ExtendedCommunities(ExtendedCommunitiesList), Flags::OPT_TRANS,
// 17  => As4Path(HopPath), Flags::OPT_TRANS,
// 18  => As4Aggregator(AggregatorInfo), Flags::OPT_TRANS,
// 20  => Connector(Ipv4Addr), Flags::OPT_TRANS,
// 21  => AsPathLimit(AsPathLimitInfo), Flags::OPT_TRANS,
// //22  => PmsiTunnel(todo), Flags::OPT_TRANS,
// 25  => Ipv6ExtendedCommunities(Ipv6ExtendedCommunitiesList), Flags::OPT_TRANS,
// 32  => LargeCommunities(LargeCommunitiesList), Flags::OPT_TRANS,
// // 33 => BgpsecAsPath,
// 35 => Otc(Asn), Flags::OPT_TRANS,
// //36 => BgpDomainPath(TODO), Flags:: , // https://datatracker.ietf.org/doc/draft-ietf-bess-evpn-ipvpn-interworking/06/
// //40 => BgpPrefixSid(TODO), Flags::OPT_TRANS, // https://datatracker.ietf.org/doc/html/rfc8669#name-bgp-prefix-sid-attribute
// 128 => AttrSet(AttributeSet), Flags::OPT_TRANS,
// 255 => Reserved(ReservedRaw), Flags::OPT_TRANS,

// PathAttribute variant(output type), impl for Attribute
from_attributes_impl!(
    AsPath(HopPath), crate::bgp::aspath::AsPath<bytes::Bytes>
    // NextHop(NextHop), crate::bgp::types::NextHop
    MultiExitDisc(u32), crate::bgp::message::update::MultiExitDisc
    Origin(OriginType), crate::bgp::types::OriginType
    LocalPref(crate::bgp::types::LocalPref), crate::bgp::message::update::LocalPref
    StandardCommunities(StandardCommunitiesBuilder), StandardCommunitiesBuilder
    As4Path(HopPath), crate::bgp::aspath::AsPath<Vec<u8>>
    AtomicAggregate(()), AtomicAggregate
    Aggregator(AggregatorInfo), AggregatorInfo
    OriginatorId(Ipv4Addr), OriginatorId
    ClusterList(ClusterIds), ClusterList
    ExtendedCommunities(ExtendedCommunitiesList), ExtendedCommunitiesList
    As4Aggregator(AggregatorInfo), As4Aggregator
    Connector(Ipv4Addr), Connector
    AsPathLimit(AsPathLimitInfo), AsPathLimitInfo
    Ipv6ExtendedCommunities(Ipv6ExtendedCommunitiesList), Ipv6ExtendedCommunitiesList
    LargeCommunities(LargeCommunitiesList), LargeCommunitiesList
    Otc(Asn), Otc
);

//------------ StandardCommunitiesList ---------------------------------------

// pub struct StandardCommunitiesList(Vec<StandardCommunity>);

// impl FromAttribute for StandardCommunitiesList {
//     type Output = StandardCommunitiesList;

//     fn attribute_type() -> PathAttributeType {
//         PathAttributeType::StandardCommunities
//     }

//     fn from_attribute(value: PathAttribute) -> Option<Self::Output> {
//         if let PathAttribute::StandardCommunities(comms) = value {
//             Some(StandardCommunitiesList(comms.0.communities().clone()))
//         } else {
//             None
//         }
//     }
// }

//------------ FromAttribute impls -------------------------------------------

impl FromAttribute for crate::bgp::aspath::HopPath {
    type Output = HopPath;

    fn attribute_type() -> PathAttributeType {
        PathAttributeType::AsPath
    }

    fn from_attribute(value: PathAttribute) -> Option<Self::Output> {
        if let PathAttribute::AsPath(as_path) = value {
            Some(as_path.0)
        } else {
            None
        }
    }
}

impl FromAttribute for crate::bgp::types::NextHop {
    type Output = NextHop;

    fn attribute_type() -> PathAttributeType {
        PathAttributeType::NextHop
    }

    fn from_attribute(value: PathAttribute) -> Option<Self::Output> {
        if let PathAttribute::NextHop(nh) = value {
            Some(nh)
        } else {
            None
        }
    }
}

impl FromAttribute for crate::bgp::path_attributes::MultiExitDisc {
    type Output = crate::bgp::path_attributes::MultiExitDisc;

    fn attribute_type() -> PathAttributeType {
        PathAttributeType::MultiExitDisc
    }

    fn from_attribute(value: PathAttribute) -> Option<Self::Output> {
        if let PathAttribute::MultiExitDisc(cl) = value {
            Some(cl)
        } else {
            None
        }
    }
}

impl FromAttribute for crate::bgp::path_attributes::ClusterIds {
    type Output = ClusterIds;

    fn attribute_type() -> PathAttributeType {
        PathAttributeType::ClusterList
    }

    fn from_attribute(value: PathAttribute) -> Option<Self::Output> {
        if let PathAttribute::ClusterList(cl) = value {
            Some(cl.inner())
        } else {
            None
        }
    }
}

//------------ From impls for PathAttribute ----------------------------------

// These conversions are used on the `set()` method of the
// PathAttributesBuilder, so not in the Workshop!

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

impl From<crate::bgp::aspath::HopPath> for PathAttribute {
    fn from(value: crate::bgp::aspath::HopPath) -> Self {
        PathAttribute::AsPath(crate::bgp::path_attributes::AsPath(value))
    }
}

// impl From<crate::bgp::types::NextHop> for PathAttribute {
//     fn from(value: crate::bgp::types::NextHop) -> Self {
//         if let crate::bgp::message::update::NextHop::Unicast(IpAddr::V4(
//             ipv4,
//         )) = value
//         {
//             PathAttribute::NextHop(NextHop(ipv4))
//         } else {
//             panic!("WHERE'S MY TRANSPARANT NEXTHOP IMPLEMENTATION!!@?!?");
//         }
//     }
// }

impl From<LargeCommunitiesList> for PathAttribute {
    fn from(value: LargeCommunitiesList) -> Self {
        PathAttribute::LargeCommunities(
            crate::bgp::path_attributes::LargeCommunities(value),
        )
    }
}

impl From<ExtendedCommunitiesList> for PathAttribute {
    fn from(value: ExtendedCommunitiesList) -> Self {
        PathAttribute::ExtendedCommunities(
            crate::bgp::path_attributes::ExtendedCommunities(value),
        )
    }
}

impl From<Ipv6ExtendedCommunitiesList> for PathAttribute {
    fn from(value: Ipv6ExtendedCommunitiesList) -> Self {
        PathAttribute::Ipv6ExtendedCommunities(
            crate::bgp::path_attributes::Ipv6ExtendedCommunities(value),
        )
    }
}

impl From<Asn> for PathAttribute {
    fn from(value: Asn) -> Self {
        PathAttribute::Otc(crate::bgp::path_attributes::Otc(value))
    }
}

impl From<StandardCommunitiesBuilder> for PathAttribute {
    fn from(value: StandardCommunitiesBuilder) -> Self {
        PathAttribute::StandardCommunities(crate::bgp::path_attributes::StandardCommunities(value))
    }
}

// impl From<CommunitiesWorkshop> for PathAttribute {
//     fn from(value: CommunitiesWorkshop) -> Self {
//         let mut std_comms = StandardCommunitiesBuilder::new();
//         for comm in value.0 {
//             if let Community::Standard(stdc) = comm {
//                 std_comms.add_community(stdc)
//             }
//         }

//         PathAttribute::Communities(crate::bgp::path_attributes::Communities(
//             std_comms,
//         ))
//     }
// }

// impl From<crate::bgp::path_attributes::MultiExitDisc> for PathAttribute {
//     fn from(value: crate::bgp::path_attributes::MultiExitDisc) -> Self {
//         PathAttribute::MultiExitDisc(
//             crate::bgp::path_attributes::MultiExitDisc(value.0),
//         )
//     }
// }

impl From<crate::bgp::types::OriginType> for PathAttribute {
    fn from(value: crate::bgp::types::OriginType) -> Self {
        PathAttribute::Origin(crate::bgp::path_attributes::Origin(value))
    }
}

impl From<crate::bgp::types::LocalPref> for PathAttribute {
    fn from(value: crate::bgp::types::LocalPref) -> Self {
        PathAttribute::LocalPref(crate::bgp::path_attributes::LocalPref(
            value,
        ))
    }
}

impl From<crate::bgp::path_attributes::AggregatorInfo> for PathAttribute {
    fn from(value: crate::bgp::path_attributes::AggregatorInfo) -> Self {
        PathAttribute::Aggregator(crate::bgp::path_attributes::Aggregator(
            value,
        ))
    }
}

impl From<crate::bgp::path_attributes::AsPathLimitInfo> for PathAttribute {
    fn from(value: crate::bgp::path_attributes::AsPathLimitInfo) -> Self {
        PathAttribute::AsPathLimit(crate::bgp::path_attributes::AsPathLimit(
            value,
        ))
    }
}

impl From<crate::bgp::path_attributes::ClusterIds> for PathAttribute {
    fn from(value: crate::bgp::path_attributes::ClusterIds) -> Self {
        PathAttribute::ClusterList(crate::bgp::path_attributes::ClusterList(
            value,
        ))
    }
}

// impl From<crate::bgp::path_attributes::StandardCommunities> for PathAttribute {
//     fn from(value: crate::bgp::path_attributes::StandardCommunities) -> Self {
//         let mut b = StandardCommunitiesBuilder::with_capacity(value.0.len());
//         value.0.into_iter().for_each(|c| b.add_community(c));
//         PathAttribute::StandardCommunities(crate::bgp::path_attributes::StandardCommunities(
//             b,
//         ))
//     }
// }

//------------ The Workshop --------------------------------------------------

#[derive(Debug)]
pub struct RouteWorkshop<N>(
    Option<N>,
    Option<PathAttributesBuilder>,
    // PhantomData<O>
);

impl<N: Clone + Debug + Hash> RouteWorkshop<N> {
    pub fn from_update_pdu<Octs: Octets>(
        pdu: &UpdateMessage<Octs>,
    ) -> Result<Self, ComposeError>
    where
        for<'a> Vec<u8>: OctetsFrom<Octs::Range<'a>>,
    {
        PathAttributesBuilder::from_update_pdu(pdu)
            .map(|r| Self(None, Some(r)))
    }

    pub fn nlri(&self) -> &Option<N> {
        &self.0
    }

    pub fn set_attr<A: Workshop<N> + FromAttribute>(
        &mut self,
        attr: A,
    ) -> Result<(), ComposeError> {
        let mut res = Err(ComposeError::InvalidAttribute);
        if let Some(b) = &mut self.1 {
            res = A::to_value(attr, b);
        }
        res
    }

    pub fn get_attr<A: FromAttribute>(
        &self,
    ) -> Option<<A as FromAttribute>::Output>
    where
        A::Output: Workshop<N>,
    {
        self.1
            .as_ref()
            .and_then(|b| b.get::<A>().map(|a| a.into_retrieved(b)))
    }

    pub fn make_route(&self) -> Option<Route<N>> {
        match self {
            RouteWorkshop(Some(nlri), Some(pab),) => Some(Route::<N>(
                nlri.clone(),
                pab.attributes().clone(),
            )),
            _ => None
        }
    }

    pub fn make_route_with_nlri(&self, nlri: N) -> Option<Route<N>> {
        match self {
            RouteWorkshop(_, Some(pab),) => Some(Route::<N>(
                nlri.clone(),
                pab.attributes().clone(),
            )),
            _ => None
        }
    }
}

macro_rules! impl_workshop {
    (
        $( $attr:ty )+
    ) => {
        $(
            impl<N: Clone + Hash + Debug + AfiSafiNlri<bytes::Bytes>> Workshop<N> for $attr {
                fn to_value(local_attrs: Self, attrs: &mut PathAttributesBuilder) ->
                    Result<(), ComposeError> { attrs.set(local_attrs); Ok(()) }
                fn into_retrieved(self, _attrs: &PathAttributesBuilder) ->
                    Self { self }
            }
        )+
    }
}

impl_workshop!(
    crate::bgp::aspath::AsPath<bytes::Bytes>
    crate::bgp::aspath::HopPath
    // crate::bgp::types::NextHop
    crate::bgp::types::LocalPref
    crate::bgp::path_attributes::MultiExitDisc
    crate::bgp::types::OriginType
    crate::bgp::path_attributes::OriginatorId
    crate::bgp::path_attributes::AggregatorInfo
    crate::bgp::path_attributes::ExtendedCommunitiesList
    crate::bgp::path_attributes::AsPathLimitInfo
    crate::bgp::path_attributes::Ipv6ExtendedCommunitiesList
    crate::bgp::path_attributes::LargeCommunitiesList
    crate::bgp::path_attributes::ClusterIds
    crate::bgp::message::update_builder::StandardCommunitiesBuilder
);

impl<N: Clone + Hash + AfiSafiNlri<bytes::Bytes>> Workshop<N> for () {
    // type Output = Self;

    fn into_retrieved(self, _attrs: &PathAttributesBuilder) -> Self {
        self
    }

    fn to_value(
        local_attrs: Self,
        attrs: &mut PathAttributesBuilder,
    ) -> Result<(), ComposeError> {
        attrs.set(crate::bgp::path_attributes::AtomicAggregate(local_attrs));
        Ok(())
    }
}

//------------ Workshop ------------------------------------------------------

pub trait Workshop<N> {
    fn into_retrieved(self, attrs: &PathAttributesBuilder) -> Self;
    fn to_value(
        local_attrs: Self,
        attrs: &mut PathAttributesBuilder,
    ) -> Result<(), ComposeError>;
}

//------------ CommunitiesWorkshop -------------------------------------------

impl<N: Clone + Hash + Debug + AfiSafiNlri<bytes::Bytes>> Workshop<N> for Vec<Community> {
    fn into_retrieved(self, attrs: &PathAttributesBuilder) -> Self {
        let mut c = attrs
            .get::<StandardCommunitiesBuilder>()
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

        c
    }

    fn to_value(
        local_attr: Self,
        attrs: &mut PathAttributesBuilder,
    ) -> Result<(), ComposeError> {
        for comm in local_attr {
            match comm {
                Community::Standard(c) => {
                    if let Some(mut b) =
                        attrs.get::<StandardCommunitiesBuilder>()
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

// pub struct CommunitiesWorkshop;

// impl CommunitiesWorkshop {
//     pub fn add_community(
//         attrs: &mut PathAttributesBuilder,
//         comm: Community,
//     ) -> Result<(), ComposeError> {
//         match comm {
//             Community::Standard(c) => {
//                 if let Some(mut b) = attrs.get::<StandardCommunitiesBuilder>() {
//                     b.add_community(c)
//                 }
//             },
//             Community::Extended(c) => {
//                 if let Some(mut b) = attrs.get::<ExtendedCommunitiesList>() {
//                     b.add_community(c)
//                 }
//             },
//             Community::Ipv6Extended(c) => {
//                 if let Some(mut b) = attrs.get::<Ipv6ExtendedCommunitiesList>() {
//                     b.add_community(c)
//                 }
//             },
//             Community::Large(c) => {
//                 if let Some(mut b) = attrs.get::<LargeCommunitiesList>() {
//                     b.add_community(c)
//                 }
//             },
//         };
//         Ok(())
//     }
// }

// impl<N: Clone + Hash + Octets> Workshop<N> for CommunitiesWorkshop {
//     type Output = Vec<Community>;

//     fn into_retrieved(self, attrs: &PathAttributesBuilder) -> Vec<Community> {
//         let mut c = attrs
//             .get::<StandardCommunitiesBuilder>()
//             .unwrap()
//             .fmap(|c| Community::Standard(*c));
//         c.append(
//             &mut attrs
//                 .get::<ExtendedCommunitiesList>()
//                 .unwrap()
//                 .fmap(Community::Extended),
//         );
//         c.append(
//             &mut attrs
//                 .get::<Ipv6ExtendedCommunitiesList>()
//                 .unwrap()
//                 .fmap(Community::Ipv6Extended),
//         );
//         c.append(
//             &mut attrs
//                 .get::<LargeCommunitiesList>()
//                 .unwrap()
//                 .fmap(Community::Large),
//         );

//         c
//     }

//     fn to_value(
//         local_attr: Vec<Community>,
//         attrs: &mut PathAttributesBuilder,
//     ) -> Result<(), ComposeError> {
//         for comm in local_attr {
//             match comm {
//                 Community::Standard(c) => {
//                     if let Some(mut b) = attrs.get::<StandardCommunitiesBuilder>() {
//                         b.add_community(c)
//                     }
//                 },
//                 Community::Extended(c) => {
//                     if let Some(mut b) = attrs.get::<ExtendedCommunitiesList>() {
//                         b.add_community(c)
//                     }
//                 },
//                 Community::Ipv6Extended(c) => {
//                     if let Some(mut b) = attrs.get::<Ipv6ExtendedCommunitiesList>() {
//                         b.add_community(c)
//                     }
//                 },
//                 Community::Large(_) => todo!(),
//             };
//         }

//         Ok(())
//     }
// }

// impl FromAttribute for CommunitiesWorkshop {
//     type Output = CommunitiesWorkshop;

//     fn attribute_type() -> PathAttributeType {
//         PathAttributeType::Communities
//     }

//     fn from_attribute(value: PathAttribute) -> Option<Self::Output> {
//         if let PathAttribute::Communities(_) = value {
//             Some(CommunitiesWorkshop)
//         } else {
//             None
//         }
//     }
// }

impl FromAttribute for Vec<Community> {
    type Output = Self;

    fn from_attribute(_value: PathAttribute) -> Option<Self::Output> {
        todo!()
    }

    fn attribute_type() -> PathAttributeType {
        todo!()
    }
}

//------------ NextHopWorkshop -----------------------------------------------

impl<N: Clone + Hash> Workshop<N> for crate::bgp::types::NextHop {
    fn into_retrieved(self, attrs: &PathAttributesBuilder) -> Self {
        if let Some(next_hop) = attrs.get::<crate::bgp::types::NextHop>() {
            crate::bgp::types::NextHop::Unicast(next_hop.inner().into())
        } else if let Some(PathAttribute::MpReachNlri(nlri)) =
            attrs.attributes().get(&PathAttributeType::MpReachNlri)
        {
            *(nlri.clone().inner().get_nexthop())
        } else {
            crate::bgp::types::NextHop::Empty
        }
    }

    fn to_value(
        local_attr: Self,
        attrs: &mut PathAttributesBuilder,
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
