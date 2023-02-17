//------------ AttributeList ------------------------------------------------

// A Set of BGP Path Attributes (its type name ends in `List` because there's
// a RFC-defined BGP attribute called `attr_set` ("attributes set")). Used to
// create and modify BGP Update messages.

use crate::{
    addr::Prefix,
    asn::{AsPath, Asn},
    bgp::communities::{
        Community, ExtendedCommunity, Ipv6ExtendedCommunity, LargeCommunity,
    },
};

use super::{
    update::{
        Aggregator, LocalPref, MultiExitDisc, NextHop, OriginType,
        PathAttributeType,
    },
    UpdateMessage,
};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AttributeList(Vec<AttributeTypeValue>);

impl AttributeList {
    pub fn new() -> Self {
        Self(vec![])
    }

    pub fn get(&self, key: PathAttributeType) -> Option<&AttributeTypeValue> {
        self.0
            .binary_search_by_key(&key, |item| item.get_type())
            .map(|idx| &self.0[idx])
            .ok()
    }

    pub fn get_owned(
        &mut self,
        key: PathAttributeType,
    ) -> Option<AttributeTypeValue> {
        self.0
            .binary_search_by_key(&key, |item| item.get_type())
            .map(|idx| self.0.remove(idx))
            .ok()
    }

    pub fn insert(
        &mut self,
        value: AttributeTypeValue,
    ) -> Option<&AttributeTypeValue> {
        match self
            .0
            .binary_search_by_key(&value.get_type(), |item| item.get_type())
        {
            Ok(_) => None,
            Err(idx) => {
                self.0.insert(idx, value);
                Some(&self.0[0])
            }
        }
    }

    pub fn replace(&mut self, new_list: AttributeList) {
        *self = new_list;
    }
}

impl FromIterator<AttributeTypeValue> for AttributeList {
    fn from_iter<T: IntoIterator<Item = AttributeTypeValue>>(
        iter: T,
    ) -> Self {
        let mut attr_list = AttributeList(vec![]);

        for attr in iter {
            let res = attr_list.insert(attr);
            if res.is_none() {
                panic!("Invalid Insert into MGP attributes list")
            }
        }

        attr_list
    }
}

//------------ Path Attribute TypeValues ------------------------------------

// Wrapper for all different values and their types that live in a BGP update
// message.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AttributeTypeValue {
    AsPath(Option<AsPath<Vec<Asn>>>),
    OriginType(Option<OriginType>),
    NextHop(Option<NextHop>),
    MultiExitDiscriminator(Option<MultiExitDisc>),
    LocalPref(Option<LocalPref>),
    AtomicAggregate(bool),
    Aggregator(Option<Aggregator>),
    Communities(Option<Vec<Community>>),
    MpReachNlri(Option<Vec<Prefix>>),
    MpUnReachNlri(Option<Vec<Prefix>>),
    OriginatorId(Option<u32>),
    ClusterList(Option<u32>),
    ExtendedCommunities(Option<Vec<ExtendedCommunity>>),
    As4Path(Option<u32>),
    As4Aggregator(Option<u32>),
    Connector,
    AsPathLimit(Option<(u8, u32)>),
    PmsiTunnel,
    Ipv6ExtendedCommunities(Option<Vec<Ipv6ExtendedCommunity>>),
    LargeCommunities(Option<Vec<LargeCommunity>>),
    BgpsecAsPath,
    AttrSet,
    RsrvdDevelopment,
}

impl AttributeTypeValue {
    pub fn get_type(&self) -> PathAttributeType {
        match self {
            AttributeTypeValue::AsPath(_) => PathAttributeType::AsPath,
            AttributeTypeValue::OriginType(_) => PathAttributeType::Origin,
            AttributeTypeValue::NextHop(_) => PathAttributeType::NextHop,
            AttributeTypeValue::MultiExitDiscriminator(_) => {
                PathAttributeType::MultiExitDisc
            }
            AttributeTypeValue::LocalPref(_) => PathAttributeType::LocalPref,
            AttributeTypeValue::AtomicAggregate(_) => {
                PathAttributeType::AtomicAggregate
            }
            AttributeTypeValue::Aggregator(_) => {
                PathAttributeType::Aggregator
            }
            AttributeTypeValue::Communities(_) => {
                PathAttributeType::Communities
            }
            AttributeTypeValue::MpReachNlri(_) => {
                PathAttributeType::MpReachNlri
            }
            AttributeTypeValue::MpUnReachNlri(_) => {
                PathAttributeType::MpUnreachNlri
            }
            AttributeTypeValue::OriginatorId(_) => {
                PathAttributeType::OriginatorId
            }
            AttributeTypeValue::ClusterList(_) => {
                PathAttributeType::ClusterList
            }
            AttributeTypeValue::ExtendedCommunities(_) => {
                PathAttributeType::ExtendedCommunities
            }
            AttributeTypeValue::As4Path(_) => PathAttributeType::As4Path,
            AttributeTypeValue::As4Aggregator(_) => {
                PathAttributeType::As4Aggregator
            }
            AttributeTypeValue::Connector => PathAttributeType::Connector,
            AttributeTypeValue::AsPathLimit(_) => {
                PathAttributeType::AsPathLimit
            }
            AttributeTypeValue::PmsiTunnel => PathAttributeType::PmsiTunnel,
            AttributeTypeValue::Ipv6ExtendedCommunities(_) => {
                PathAttributeType::Ipv6ExtendedCommunities
            }
            AttributeTypeValue::LargeCommunities(_) => {
                PathAttributeType::LargeCommunities
            }
            AttributeTypeValue::BgpsecAsPath => {
                PathAttributeType::BgpsecAsPath
            }
            AttributeTypeValue::AttrSet => PathAttributeType::AttrSet,
            AttributeTypeValue::RsrvdDevelopment => {
                PathAttributeType::RsrvdDevelopment
            }
        }
    }
}

//------------ Route Status -------------------------------------------------

// Status is piece of metadata that writes some (hopefully) relevant state of
// per-peer BGP session into every route. The goal is to be able to enable
// the logic in `rib-units` to decide whether routes should be send to its
// output and to be able output this information to API clients, without
// having to go back to the units that keep the per-peer session state.
#[derive(Debug, Eq, PartialEq, Copy, Clone, Default)]
pub enum RouteStatus {
    // Between start and EOR on a BGP peer-session
    InConvergence,
    // After EOR for a BGP peer-session, either `Graceful Restart` or EOR
    UpToDate,
    // After hold-timer expiry
    Stale,
    // After the request for a Route Refresh to a peer and the reception of a
    // new route
    StartOfRouteRefresh,
    // After the reception of a withdrawal
    Withdrawn,
    // Status not relevant, e.g. a RIB that holds archived routes.
    #[default]
    Empty,
}

impl UpdateMessage<bytes::Bytes> {
    // Collect the attributes on the raw message into an AttributeList.
    pub fn get_attribute_list(&self) -> AttributeList {
        self.path_attributes()
            .iter()
            .filter_map(|attr| self.get_attribute_value(attr.type_code()))
            .collect()
    }

    fn get_attribute_value(
        &self,
        key: PathAttributeType,
    ) -> Option<AttributeTypeValue> {
        match key {
            PathAttributeType::Origin => {
                Some(AttributeTypeValue::OriginType(self.origin()))
            }
            PathAttributeType::AsPath => {
                Some(AttributeTypeValue::AsPath(self.aspath()))
            }
            PathAttributeType::NextHop => {
                Some(AttributeTypeValue::NextHop(self.next_hop()))
            }
            PathAttributeType::MultiExitDisc => {
                Some(AttributeTypeValue::MultiExitDiscriminator(
                    self.multi_exit_desc(),
                ))
            }
            PathAttributeType::LocalPref => {
                Some(AttributeTypeValue::LocalPref(self.local_pref()))
            }
            PathAttributeType::AtomicAggregate => {
                Some(AttributeTypeValue::AtomicAggregate(
                    self.is_atomic_aggregate(),
                ))
            }
            PathAttributeType::Aggregator => {
                Some(AttributeTypeValue::Aggregator(self.aggregator()))
            }
            PathAttributeType::Communities => {
                Some(AttributeTypeValue::Communities(self.all_communities()))
            }
            PathAttributeType::OriginatorId => todo!(),
            PathAttributeType::ClusterList => todo!(),
            PathAttributeType::MpReachNlri => {
                Some(AttributeTypeValue::MpReachNlri(Some(
                    self.nlris().iter().filter_map(|n| n.prefix()).collect(),
                )))
            }
            PathAttributeType::MpUnreachNlri => {
                Some(AttributeTypeValue::MpUnReachNlri(Some(
                    self.withdrawals()
                        .iter()
                        .filter_map(|n| n.prefix())
                        .collect(),
                )))
            }
            PathAttributeType::ExtendedCommunities => todo!(),
            PathAttributeType::As4Path => todo!(),
            PathAttributeType::As4Aggregator => todo!(),
            PathAttributeType::Connector => todo!(),
            PathAttributeType::AsPathLimit => todo!(),
            PathAttributeType::PmsiTunnel => todo!(),
            PathAttributeType::Ipv6ExtendedCommunities => todo!(),
            PathAttributeType::LargeCommunities => todo!(),
            PathAttributeType::BgpsecAsPath => todo!(),
            PathAttributeType::AttrSet => todo!(),
            PathAttributeType::RsrvdDevelopment => todo!(),
            PathAttributeType::Reserved => todo!(),
            PathAttributeType::Unimplemented(_) => todo!(),
        }
    }
}
