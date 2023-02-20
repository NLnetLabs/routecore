use crate::{
    addr::Prefix,
    asn::{AsPath, Asn},
    bgp::communities::{
        Community, ExtendedCommunity, Ipv6ExtendedCommunity, LargeCommunity,
    },
};

use crate::bgp::message::{
    update::{
        Aggregator, LocalPref, MultiExitDisc, NextHop, OriginType,
        PathAttributeType,
    }
};

//------------ Path Attribute TypeValues ------------------------------------

// Wrapper for all different values of BGP Path Attributes (as listed in 
// https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml)
// that can be encountered in a BGP Update Message.
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
    As4Path(Option<AsPath<Vec<Asn>>>),
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


//------------ AttributeList ------------------------------------------------

// A Set of BGP Path Attributes (its type name ends in `List` because there's
// a RFC-defined BGP attribute called `attr_set` ("attributes set")).

// Used to create and modify changesets for (new) BGP Update messages. Since
// it's meant as a single transaction of changes to a BGP update, it is an
// insert-only structure, it only has an insert method, and no modify/remove
// methods.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AttributeList(Vec<AttributeTypeValue>);

impl AttributeList {
    pub fn new() -> Self {
        Self(vec![])
    }

    pub fn get_attr(
        &self,
        key: PathAttributeType,
    ) -> Option<&AttributeTypeValue> {
        self.0
            .binary_search_by_key(&key, |item| item.get_type())
            .map(|idx| &self.0[idx])
            .ok()
    }

    pub fn get_attr_owned(
        &mut self,
        key: PathAttributeType,
    ) -> Option<AttributeTypeValue> {
        self.0
            .binary_search_by_key(&key, |item| item.get_type())
            .map(|idx| self.0.remove(idx))
            .ok()
    }

    pub fn insert_attr(
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
}

impl FromIterator<AttributeTypeValue> for AttributeList {
    fn from_iter<T: IntoIterator<Item = AttributeTypeValue>>(
        iter: T,
    ) -> Self {
        let mut attr_list = AttributeList(vec![]);

        for attr in iter {
            let res = attr_list.insert_attr(attr);
            if res.is_none() {
                panic!("Invalid Insert into BGP attributes list")
            }
        }

        attr_list
    }
}
