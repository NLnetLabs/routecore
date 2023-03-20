// //------------ Route Status -------------------------------------------------

// use std::ops::Index;
// use crate::asn::{AsPath, Asn, LongSegmentError, OwnedPathSegment2};

// use super::{
//     message::update::{
//         Aggregator, LocalPref, MultiExitDisc, NextHop, OriginType,
//     },
// };

// // The values that live in a BGP Update message can be either Scalars or
// // Vectors. The two traits, ScalarValue and VectorValue, supply the methods
// // to modify and inspect them and creating new BGP Update messages with them

// //------------ VectorValue Trait --------------------------------------------
// pub trait VectorValue: Index<usize> + From<Vec<Self::Item>>
// where
//     Self::Item: Sized + Clone,
// {
//     type Item;

//     fn prepend_vec(
//         &mut self,
//         vector: Vec<Self::Item>,
//     ) -> Result<(), LongSegmentError>;
//     fn append_vec(
//         &mut self,
//         vector: Vec<Self::Item>,
//     ) -> Result<(), LongSegmentError>;
//     fn insert_vec(
//         &mut self,
//         pos: u8,
//         vector: Vec<Self::Item>,
//     ) -> Result<(), LongSegmentError>;
//     fn vec_len(&self) -> u8;
//     // fn get(&self, pos: u8) -> Option<&Self::Item>;
//     fn vec_is_empty(&self) -> bool;
// }

// //------------ ScalarValue Trait --------------------------------------------

// pub trait ScalarValue: Clone {}

// impl ScalarValue for NextHop {}
// impl ScalarValue for OriginType {}
// impl ScalarValue for bool {}
// impl ScalarValue for MultiExitDisc {}
// impl ScalarValue for LocalPref {}
// impl ScalarValue for Aggregator {}
// impl ScalarValue for (u8, u32) {}

// //------------ Attributes Change Set ----------------------------------------

// // A attributes Change Set allows a user to create a set of changes to an
// // existing (raw) BGP Update message.
// #[derive(Debug, PartialEq, Eq, Clone)]
// pub struct AttrChangeSet<T> {
//     pub as_path: VectorOption<T>,
//     pub origin_type: ScalarOption<T>,
//     pub next_hop: ScalarOption<T>,
//     pub multi_exit_discriminator: ScalarOption<T>,
//     pub local_pref: ScalarOption<T>,
//     pub atomic_aggregate: ScalarOption<bool>,
//     pub aggregator: ScalarOption<T>,
//     pub communities: VectorOption<T>,
//     // mp_reach_nlri: Vec<Prefix>,
//     // mp_unreach_nlri: Vec<Prefix>,
//     pub originator_id: ScalarOption<T>,
//     pub cluster_list: VectorOption<T>,
//     pub extended_communities: VectorOption<T>,
//     pub as4_path: VectorOption<T>,
//     pub as4_aggregator: ScalarOption<T>,
//     pub connector: ScalarOption<T>, // Connector,
//     pub as_path_limit: ScalarOption<T>,
//     pub pmsi_tunnel: ScalarOption<T>, // PmsiTunnel,
//     pub ipv6_extended_communities: VectorOption<T>,
//     pub large_communities: VectorOption<T>,
//     pub bgpsec_as_path: VectorOption<T>, // BgpsecAsPath,
//     pub attr_set: VectorOption<T>,       // AttrSet,
//     pub rsrvd_development: VectorOption<T>, // RsrvdDevelopment,
// }


// //------------ ScalarOption ------------------------------------------------

// #[derive(Clone, Copy, Debug, PartialEq, Eq)]
// pub struct ScalarOption<T> {
//     pub value: Option<T>,
//     pub changed: bool,
// }

// impl<T: ScalarValue> ScalarOption<T> {
//     pub fn into_opt(self) -> Option<T>
//     where
//         T: Copy,
//     {
//         self.value
//     }

//     pub fn as_ref(&self) -> Option<&T> {
//         self.value.as_ref()
//     }

//     pub fn changed(&self) -> bool {
//         self.changed
//     }

//     pub fn empty() -> ScalarOption<T> {
//         ScalarOption {
//             value: None,
//             changed: false,
//         }
//     }

//     pub fn cleared() -> ScalarOption<T> {
//         ScalarOption {
//             value: None,
//             changed: true,
//         }
//     }
// }

// #[derive(Debug, PartialEq, Eq, Copy, Clone)]
// pub struct Todo;

// #[derive(Clone, Copy, Debug, PartialEq, Eq)]
// pub struct VectorOption<V> {
//     pub value: Option<V>,
//     pub changed: bool
// }

// impl<V: VectorValue> VectorOption<V> {
//     pub fn new(vector: Vec<V::Item>) -> Self {
//         Self {
//             value: Some(vector.into()),
//             changed: false,
//         }
//     }

//     pub fn as_ref(&self) -> Option<&V> {
//         self.value.as_ref()
//     }

//     pub fn get_from_vec(&self, pos: u8) -> Option<<V as Index<usize>>::Output>
//     where
//         <V as Index<usize>>::Output: Clone + Sized,
//     {
//         self.value.as_ref().map(|c| c[pos as usize].clone())
//     }

//     pub fn replace(
//         &mut self,
//         vector: Vec<V::Item>,
//     ) -> Result<(), LongSegmentError> {
//         self.value = Some(vector.into());
//         self.changed = true;
//         Ok(())
//     }

//     pub fn prepend<T: Into<V::Item>>(
//         &mut self,
//         value: T,
//     ) -> Result<(), LongSegmentError> {
//         if let Some(v) = self.value.as_mut() {
//             v.prepend_vec(vec![value.into()])?
//         }
//         self.changed = true;

//         Ok(())
//     }

//     pub fn append(
//         &mut self,
//         vector: Vec<V::Item>,
//     ) -> Result<(), LongSegmentError> {
//         if let Some(v) = self.value.as_mut() {
//             v.append_vec(vector)?
//         }
//         self.changed = true;

//         Ok(())
//     }

//     pub fn insert(
//         &mut self,
//         pos: u8,
//         vector: Vec<V::Item>,
//     ) -> Result<(), LongSegmentError> {
//         if let Some(v) = self.value.as_mut() {
//             v.insert_vec(pos, vector)?
//         }
//         self.changed = true;

//         Ok(())
//     }

//     pub fn len(&self) -> Option<u8> {
//         self.value.as_ref().map(|v| v.vec_len())
//     }

//     pub fn is_empty(&self) -> bool {
//         self.value
//             .as_ref()
//             .map_or_else(|| true, |v| v.vec_is_empty())
//     }
// }


// impl VectorOption<AsPath<Vec<u8>>> {

//     pub fn new(vector: Vec<Asn>) -> Self {
//         Self { value: vector.as_slice().try_into().ok(), changed: false } 
//     }

//     pub fn get_from_vec(&self, pos: u8) -> Option<OwnedPathSegment2> {
//         self.value.as_ref()?.iter().nth(pos as usize).map(|s| s.into_owned2())
//     }

//     pub fn replace(
//         &mut self,
//         vector: Vec<Asn>,
//     ) -> Result<(), LongSegmentError> {
//         self.value = AsPath::<Vec<u8>>::try_from(vector.as_slice()).ok();
//         self.changed = true;
//         Ok(())
//     }

//     pub fn prepend(
//         &mut self,
//         asn: Asn,
//     ) -> Result<(), LongSegmentError> {
//         if let Some(v) = self.value.as_mut() {
//             v.prepend_n::<1>(asn).map_err(|_| LongSegmentError)?;
//         }
//         self.changed = true;

//         Ok(())
//     }

//     pub fn append(
//         &mut self,
//         asn: Asn,
//     ) -> Result<(), LongSegmentError> {
//         if let Some(v) = self.value.as_mut() {
//             let v = std::mem::take(v);
//             let mut aspb = v.into_builder();
//             aspb.append(asn);
//             self.value = aspb.finalize().ok();
//         }
//         self.changed = true;

//         Ok(())
//     }

//     // pub fn insert(
//     //     &mut self,
//     //     pos: u8,
//     //     vector: Vec<Asn>,
//     // ) -> Result<(), LongSegmentError> {
//     //     if let Some(v) = self.value.as_mut() {
//     //         v.insert_vec(pos, vector)?
//     //     }
//     //     self.changed = true;

//     //     Ok(())
//     // }

//     pub fn len(&self) -> Option<usize> {
//         self.value.as_ref().map(|v| v.path_len())
//     }

//     // pub fn is_empty(&self) -> bool {
//     //     self.value
//     //         .as_ref()
//     //         .map_or_else(|| true, |v| v.is_empty())
//     // }
// }


// impl<T: ScalarValue> ScalarOption<T> {
//     pub fn get(&self) -> Option<T> {
//         self.value.clone()
//     }

//     // Sets the scalar and returns the current value
//     pub fn set<V: Into<T>>(&mut self, value: V) -> Option<T> {
//         let val = &mut Some(value.into());
//         std::mem::swap(&mut self.value, val);
//         self.changed = true;
//         val.clone()
//     }

//     // Clears and sets the changed bool, so this is
//     // a deliberate wipe of the value.
//     pub fn clear(&mut self) {
//         *self = ScalarOption::cleared()
//     }
// }

// // Status is piece of metadata that writes some (hopefully) relevant state of
// // per-peer BGP session into every route. The goal is to be able to enable
// // the logic in `rib-units` to decide whether routes should be send to its
// // output and to be able output this information to API clients, without
// // having to go back to the units that keep the per-peer session state.
// #[derive(Debug, Eq, PartialEq, Copy, Clone, Default)]
// pub enum RouteStatus {
//     // Between start and EOR on a BGP peer-session
//     InConvergence,
//     // After EOR for a BGP peer-session, either `Graceful Restart` or EOR
//     UpToDate,
//     // After hold-timer expiry
//     Stale,
//     // After the request for a Route Refresh to a peer and the reception of a
//     // new route
//     StartOfRouteRefresh,
//     // After the reception of a withdrawal
//     Withdrawn,
//     // Status not relevant, e.g. a RIB that holds archived routes.
//     #[default]
//     Empty,
// }

// impl ScalarValue for RouteStatus {}

// impl std::fmt::Display for RouteStatus {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         match self {
//             RouteStatus::InConvergence => write!(f, "in convergence"),
//             RouteStatus::UpToDate => write!(f, "up to date"),
//             RouteStatus::Stale => write!(f, "stale"),
//             RouteStatus::StartOfRouteRefresh => {
//                 write!(f, "start of route refresh")
//             }
//             RouteStatus::Withdrawn => write!(f, "withdrawn"),
//             RouteStatus::Empty => write!(f, "empty"),
//         }
//     }
// }
