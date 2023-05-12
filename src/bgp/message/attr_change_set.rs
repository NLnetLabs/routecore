use crate::addr::Prefix;
use crate::bgp::aspath::AsPath;
use crate::bgp::communities::{
    ExtendedCommunity, Ipv6ExtendedCommunity, LargeCommunity,
    StandardCommunity,
};

use crate::bgp::message::update::{
    Aggregator, LocalPref, MultiExitDisc, NextHop, OriginType,
};

use crate::bgp::message::nlri::Nlri;

type Todo = ();

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChangedOption<T> {
    value: Option<T>,
    changed: bool
}

impl<T> ChangedOption<T> {
    pub fn new() -> ChangedOption<T> {
        ChangedOption {
            value: None,
            changed: false,
        }
    }

    pub fn into_opt(self) -> Option<T>
    {
        self.value
    }

    pub fn as_ref(&self) -> Option<&T> {
        self.value.as_ref()
    }

    pub fn is_changed(&self) -> bool {
        self.changed
    }

    pub fn set_cleared() -> ChangedOption<T> {
        ChangedOption {
            value: None,
            changed: true,
        }
    }

    pub fn set<S: Into<T>>(&mut self, value: S) {
        let val = &mut Some(value.into());
        std::mem::swap(&mut self.value, val);
        self.changed = true;
    }
}

// A attributes Change Set allows a user to create a set of changes to an
// existing (raw) BGP Update message.
#[derive(Debug)]
pub struct AttrChangeSet {
    // NLRI
    // Routecore gets to decide where the different parts of the NLRI go, in
    // the regular nlri or in MP_REACH_NLRI.
    pub nlri: ChangedOption<Nlri<Vec<u8>>>,
    pub withdrawals: ChangedOption<Vec<Prefix>>,

    // Path Attributes

    // PA: AS_PATH
    pub as_path: ChangedOption<AsPath<Vec<u8>>>,
    pub as4_path: ChangedOption<AsPath<Vec<u8>>>,

    // PA: communities
    pub standard_communities: ChangedOption<Vec<StandardCommunity>>,
    pub extended_communities: ChangedOption<Vec<ExtendedCommunity>>,
    pub ipv6_extended_communities: ChangedOption<Vec<Ipv6ExtendedCommunity>>,
    pub large_communities: ChangedOption<Vec<LargeCommunity>>,

    // PA: others
    pub origin_type: ChangedOption<OriginType>,
    pub next_hop: ChangedOption<NextHop>,
    pub multi_exit_discriminator: ChangedOption<MultiExitDisc>,
    pub local_pref: ChangedOption<LocalPref>,
    pub atomic_aggregate: ChangedOption<bool>,
    pub aggregator: ChangedOption<Aggregator>,

    // PA: unimplemented
    pub originator_id: Todo,
    pub cluster_list: Todo,
    pub as4_aggregator: Todo,
    pub connector: Todo,
    pub as_path_limit: Todo,
    pub pmsi_tunnel: Todo,
    pub bgpsec_as_path: Todo,
    pub attr_set: Todo,
    pub rsrvd_development: Todo,
}
