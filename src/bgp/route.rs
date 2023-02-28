//------------ Route Status -------------------------------------------------

use std::ops::Index;

use crate::asn::{AsPath, Asn, LongSegmentError, MaterializedPathSegment};

use super::{
    communities::{
        Community, ExtendedCommunity, Ipv6ExtendedCommunity, LargeCommunity,
    },
    message::update::{
        Aggregator, LocalPref, MultiExitDisc, NextHop, OriginType,
    },
};

// The values that live in a BGP Update message can be either Scalars or
// Vectors. The two traits, ScalarValue and VectorValue, supply the methods
// to modify and inspect them and creating new BGP Update messages with them

//------------ VectorValue Trait --------------------------------------------
pub trait VectorValue: Index<usize> + From<Vec<Self::Item>>
where
    Self::Item: Sized + Clone,
{
    type Item;

    fn prepend_vec(
        &mut self,
        vector: Vec<Self::Item>,
    ) -> Result<(), LongSegmentError>;
    fn append_vec(
        &mut self,
        vector: Vec<Self::Item>,
    ) -> Result<(), LongSegmentError>;
    fn insert_vec(
        &mut self,
        pos: u8,
        vector: Vec<Self::Item>,
    ) -> Result<(), LongSegmentError>;
    fn vec_len(&self) -> u8;
    // fn get(&self, pos: u8) -> Option<&Self::Item>;
    fn vec_is_empty(&self) -> bool;
}

//------------ ScalarValue Trait --------------------------------------------

pub trait ScalarValue: Copy {}

impl ScalarValue for NextHop {}
impl ScalarValue for OriginType {}
impl ScalarValue for bool {}
impl ScalarValue for MultiExitDisc {}
impl ScalarValue for LocalPref {}
impl ScalarValue for Aggregator {}
impl ScalarValue for (u8, u32) {}

//------------ Attributes Change Set ----------------------------------------

// A attributes Change Set allows a user to create a set of changes to an
// existing (raw) BGP Update message.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AttrChangeSet {
    pub as_path: ChangedOption<AsPath<Vec<MaterializedPathSegment>>>,
    pub origin_type: ChangedOption<OriginType>,
    pub next_hop: ChangedOption<NextHop>,
    pub multi_exit_discriminator: ChangedOption<MultiExitDisc>,
    pub local_pref: ChangedOption<LocalPref>,
    pub atomic_aggregate: ChangedOption<bool>,
    pub aggregator: ChangedOption<Aggregator>,
    pub communities: ChangedOption<Vec<Community>>,
    // mp_reach_nlri: Vec<Prefix>,
    // mp_unreach_nlri: Vec<Prefix>,
    pub originator_id: ChangedOption<Todo>,
    pub cluster_list: ChangedOption<Todo>,
    pub extended_communities: ChangedOption<Vec<ExtendedCommunity>>,
    pub as4_path: ChangedOption<AsPath<Vec<Asn>>>,
    pub as4_aggregator: ChangedOption<Todo>,
    pub connector: ChangedOption<Todo>, // Connector,
    pub as_path_limit: ChangedOption<(u8, u32)>,
    pub pmsi_tunnel: ChangedOption<Todo>, // PmsiTunnel,
    pub ipv6_extended_communities: ChangedOption<Vec<Ipv6ExtendedCommunity>>,
    pub large_communities: ChangedOption<Vec<LargeCommunity>>,
    pub bgpsec_as_path: ChangedOption<Todo>, // BgpsecAsPath,
    pub attr_set: ChangedOption<Todo>,       // AttrSet,
    pub rsrvd_development: ChangedOption<Todo>, // RsrvdDevelopment,
}

//------------ ChangedOption ------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChangedOption<T> {
    pub value: Option<T>,
    pub changed: bool,
}

impl<T> ChangedOption<T> {
    pub fn into_opt(self) -> Option<T>
    where
        T: Copy,
    {
        self.value
    }

    pub fn as_ref(&self) -> Option<&T> {
        self.value.as_ref()
    }

    pub fn changed(&self) -> bool {
        self.changed
    }

    pub fn empty() -> ChangedOption<T> {
        ChangedOption {
            value: None,
            changed: false,
        }
    }

    pub fn cleared() -> ChangedOption<T> {
        ChangedOption {
            value: None,
            changed: true,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Todo;

impl<V: VectorValue> ChangedOption<V> {
    pub fn new(vector: Vec<V::Item>) -> Self {
        Self {
            value: Some(vector.into()),
            changed: false,
        }
    }

    pub fn get_from_vec(&self, pos: u8) -> Option<<V as Index<usize>>::Output>
    where
        <V as Index<usize>>::Output: Clone + Sized,
    {
        self.value.as_ref().map(|c| c[pos as usize].clone())
    }

    pub fn replace(
        &mut self,
        vector: Vec<V::Item>,
    ) -> Result<(), LongSegmentError> {
        self.value = Some(vector.into());
        self.changed = true;
        Ok(())
    }

    pub fn prepend(
        &mut self,
        vector: Vec<V::Item>,
    ) -> Result<(), LongSegmentError> {
        if let Some(v) = self.value.as_mut() {
            v.prepend_vec(vector)?
        }
        self.changed = true;

        Ok(())
    }

    pub fn append(
        &mut self,
        vector: Vec<V::Item>,
    ) -> Result<(), LongSegmentError> {
        if let Some(v) = self.value.as_mut() {
            v.append_vec(vector)?
        }
        self.changed = true;

        Ok(())
    }

    pub fn insert(
        &mut self,
        pos: u8,
        vector: Vec<V::Item>,
    ) -> Result<(), LongSegmentError> {
        if let Some(v) = self.value.as_mut() {
            v.insert_vec(pos, vector)?
        }
        self.changed = true;

        Ok(())
    }

    pub fn len(&self) -> Option<u8> {
        self.value.as_ref().map(|v| v.vec_len())
    }
}

impl<T: ScalarValue> ChangedOption<T> {
    pub fn get(&self) -> Option<T> {
        self.value
    }

    // Sets the scalar and returns the current value
    pub fn set(&mut self, next_hop: T) -> Option<T> {
        let val = &mut Some(next_hop);
        std::mem::swap(&mut self.value, val);
        self.changed = true;
        *val
    }

    // Clears and sets the changed bool, so this is
    // a deliberate wipe of the value.
    pub fn clear(&mut self) {
        *self = ChangedOption::cleared()
    }
}

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

impl std::fmt::Display for RouteStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteStatus::InConvergence => write!(f, "in convergence"),
            RouteStatus::UpToDate => write!(f, "up to date"),
            RouteStatus::Stale => write!(f, "stale"),
            RouteStatus::StartOfRouteRefresh => {
                write!(f, "start of route refresh")
            }
            RouteStatus::Withdrawn => write!(f, "withdrawn"),
            RouteStatus::Empty => write!(f, "empty"),
        }
    }
}
