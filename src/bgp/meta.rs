use std::borrow::Cow;
use std::fmt;

use crate::asn::Asn;
use crate::bgp::aspath::AsPath;
use crate::record::MergeUpdate;

use super::PrefixNlri;

/// BGP message metadata.
#[derive(Clone, Debug, Hash)]
pub struct BgpNlriMeta<'a> {
    pub nlri: PrefixNlri,
    pub attributes: Cow<'a, ExampleBgpPathAttributes>,
}

impl<'a> std::fmt::Display for BgpNlriMeta<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}, {}", self.nlri, self.attributes)
    }
}

impl<'a> MergeUpdate for BgpNlriMeta<'a> {
    fn merge_update(
        &mut self,
        update_meta: Self,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.attributes
            .to_mut()
            .merge_update(update_meta.attributes.into_owned())?;
        Ok(())
    }

    fn clone_merge_update(
        &self,
        update_meta: &Self,
    ) -> Result<Self, Box<dyn std::error::Error>>
    where
        Self: std::marker::Sized,
    {
        let mut updated_copy = self.clone();
        updated_copy.attributes
            .to_mut()
            .merge_update(update_meta.attributes.clone().into_owned())?;
        Ok(updated_copy)
    }
}

/// Example BGP Path Attributes
/// <https://tools.ietf.org/html/rfc4271#section-4.3>
/// TODO TODO!
#[derive(Clone, Debug, Hash)]
pub struct ExampleBgpPathAttributes {
    pub origin: Asn,
    pub as_path: AsPath<Vec<u8>>,
    pub next_hop: std::net::IpAddr,
    pub med: u32,
    pub local_pref: u32,
    pub atomic_aggregate: bool,
    pub aggregator: Option<(Asn, u32)>,
    pub community: Vec<u32>,
    pub ext_community: Vec<u32>,
    pub large_community: Vec<u32>,
    pub originator_id: Option<String>,
    pub cluster_list: Vec<u32>,
    pub mp_reach_nlri: Option<PrefixNlri>,
    pub mp_unreach_nlri: Option<PrefixNlri>,
    pub aigp: u64,
    pub unknown: Vec<u8>,
}

impl fmt::Display for ExampleBgpPathAttributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Origin: {}, AS_PATH: {}, NEXT_HOP: {}, MED: {}, LOCAL_PREF: {}, ATOMIC_AGGREGATE: {}, AGGREGATOR: {:?}, COMMUNITY: {:?}, EXT_COMMUNITY: {:?}, LARGE_COMMUNITY: {:?}, ORIGINATOR_ID: {:?}, CLUSTER_LIST: {:?}, MP_REACH_NLRI: {:?}, MP_UNREACH_NLRI: {:?}, AIGP: {}, UNKNOWN: {:?}",
            self.origin,
            self.as_path,
            self.next_hop,
            self.med,
            self.local_pref,
            self.atomic_aggregate,
            self.aggregator,
            self.community,
            self.ext_community,
            self.large_community,
            self.originator_id,
            self.cluster_list,
            self.mp_reach_nlri,
            self.mp_unreach_nlri,
            self.aigp,
            self.unknown
        )
    }
}

impl MergeUpdate for ExampleBgpPathAttributes {
    fn merge_update(
        &mut self,
        update_meta: Self,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.origin = update_meta.origin;
        self.as_path = update_meta.as_path;
        self.next_hop = update_meta.next_hop;
        self.med = update_meta.med;
        self.local_pref = update_meta.local_pref;
        self.atomic_aggregate = update_meta.atomic_aggregate;
        self.aggregator = update_meta.aggregator;
        self.community = update_meta.community;
        self.ext_community = update_meta.ext_community;
        self.large_community = update_meta.large_community;
        self.originator_id = update_meta.originator_id;
        self.cluster_list = update_meta.cluster_list;
        self.mp_reach_nlri = update_meta.mp_reach_nlri;
        self.mp_unreach_nlri = update_meta.mp_unreach_nlri;
        self.aigp = update_meta.aigp;
        self.unknown = update_meta.unknown;
        Ok(())
    }

    fn clone_merge_update(
        &self,
        update_meta: &Self,
    ) -> Result<Self, Box<dyn std::error::Error>>
    where
        Self: std::marker::Sized,
    {
        let mut updated_copy = self.clone();
        updated_copy.merge_update(update_meta.clone())?;
        Ok(updated_copy)
    }
}
