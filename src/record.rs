use std::fmt;
use std::fmt::{Debug, Display};

use crate::asn::{AsId, AsPath};
use crate::prefix::Prefix;
use crate::addr::AddressFamily;

use num::PrimInt;

//------------ Traits for Record ---------------------------------------------

pub trait Key {}
impl Key for Prefix where Self: Copy + Sized {}
impl Key for (u64, u32) where Self: Copy + Sized {}

pub trait Nlri
where
    Self: Clone,
{
}

#[derive(Clone, Debug)]
pub struct PrefixNlri {
    nlri: Vec<Prefix>,
}

impl Display for PrefixNlri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PrefixNlri")
    }
}

impl Nlri for PrefixNlri {}
pub trait SenderId
where
    Self: Copy + Sized,
{
}

impl SenderId for u32 {}

type SenderIdInt = u32;
type LogicalTime = u64;

pub trait Record
where
    Self: Clone,
{
    type SenderId: crate::record::SenderId;
    type Key: crate::record::Key;
    type Meta: crate::record::Meta;

    fn new(sender_id: Self::SenderId, key: Self::Key, meta: Self::Meta, ltime: u64) -> Self;
    fn sender_id(&self) -> Self::SenderId;
    fn key(&self) -> Self::Key;
    fn meta(&self) -> Self::Meta;
    fn ltime(&self) -> u64;
    fn set_ltime(&mut self, ltime: u64) -> u64;
    fn inc_ltime(&mut self) -> u64 {
        let ltime = self.ltime();
        self.set_ltime(ltime + 1)
    }
    fn timestamp(&self) -> u64;
}

//----------------- Route -------------------------------------------------------------

#[derive(Clone)]
pub struct Route<Nlri, Meta>
where
    Nlri: crate::record::Nlri,
    Meta: crate::record::Meta,
{
    sender_id: SenderIdInt,
    key: (LogicalTime, SenderIdInt),
    nlri: Nlri,
    attributes: Meta,
    ltime: LogicalTime,
}

impl Record for Route<PrefixNlri, ExampleBgpPathAttributes> {
    type Meta = BgpNlriMeta;
    type Key = (LogicalTime, SenderIdInt);
    type SenderId = SenderIdInt;

    fn new(sender_id: Self::SenderId, key: Self::Key, meta: Self::Meta, ltime: u64) -> Self {
        Route {
            sender_id,
            key,
            nlri: meta.nlri,
            attributes: meta.attributes,
            ltime,
        }
    }

    fn sender_id(&self) -> Self::SenderId {
        self.sender_id
    }

    fn key(&self) -> Self::Key {
        (self.ltime, self.sender_id)
    }

    fn meta(&self) -> crate::record::BgpNlriMeta {
        BgpNlriMeta {
            nlri: self.nlri.clone(),
            attributes: self.attributes.clone(),
        }
    }

    fn ltime(&self) -> LogicalTime {
        self.ltime
    }

    fn set_ltime(&mut self, ltime: LogicalTime) -> LogicalTime {
        self.ltime = ltime;
        ltime
    }

    fn timestamp(&self) -> LogicalTime {
        self.ltime
    }
}

//-------------------- SinglePrefixRoute -----------------------------------------------

#[derive(Clone, Copy)]
pub struct SinglePrefixRoute<Meta>
where
    Meta: crate::record::Meta,
{
    pub sender_id: SenderIdInt,
    pub ltime: LogicalTime,
    pub prefix: Prefix,
    pub meta: Meta,
}

impl<Meta: crate::record::Meta> Record for SinglePrefixRoute<Meta>
where
    Meta: crate::record::Meta + Copy,
{
    type Meta = Meta;
    type Key = Prefix;
    type SenderId = SenderIdInt;

    fn new(sender_id: Self::SenderId, key: Self::Key, meta: Self::Meta, ltime: u64) -> Self {
        SinglePrefixRoute {
            sender_id,
            ltime,
            prefix: key,
            meta,
        }
    }

    fn sender_id(&self) -> Self::SenderId {
        self.sender_id
    }

    fn key(&self) -> Self::Key {
        self.prefix
    }

    fn meta(&self) -> Self::Meta {
        self.meta
    }

    fn ltime(&self) -> u64 {
        self.ltime
    }

    fn set_ltime(&mut self, ltime: u64) -> u64 {
        self.ltime = ltime;
        ltime
    }

    fn timestamp(&self) -> u64 {
        self.ltime
    }
}

impl<Meta> std::fmt::Display for SinglePrefixRoute<Meta>
where
    Meta: crate::record::Meta,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{} {}",
            self.prefix.addr(),
            self.prefix.len(),
            self.meta.summary()
        )
    }
}

impl<T> Debug for SinglePrefixRoute<T>
where
    T: Meta,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "{}/{} with {:?}",
            self.prefix.addr(),
            self.prefix.len(),
            self.meta
        ))
    }
}

//---------------------------- Meta ------------------------------------------------
pub trait MergeUpdate {
    fn merge_update(&mut self, update_meta: Self) -> Result<(), Box<dyn std::error::Error>>;
}

pub trait Meta
where
    Self: Debug + Sized + Display + Clone + MergeUpdate,
{
    fn summary(&self) -> String;
}

impl<T> Meta for T
where
    T: Debug + Display + Clone + MergeUpdate,
{
    fn summary(&self) -> String {
        format!("{}", self)
    }
}

#[derive(Clone, Copy)]
pub enum NoMeta {
    Empty,
}

impl fmt::Debug for NoMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("")
    }
}

impl Display for NoMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("")
    }
}

impl MergeUpdate for NoMeta {
    fn merge_update(&mut self, _: NoMeta) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct BgpNlriMeta {
    nlri: PrefixNlri,
    attributes: ExampleBgpPathAttributes,
}

impl Display for BgpNlriMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}, {}", self.nlri, self.attributes)
    }
}

impl MergeUpdate for BgpNlriMeta {
    fn merge_update(&mut self, update_meta: Self) -> Result<(), Box<dyn std::error::Error>> {
        self.attributes.merge_update(update_meta.attributes)?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ExampleBgpPathAttributes {
    pub origin: AsId,
    pub as_path: AsPath,
    pub next_hop: std::net::IpAddr,
    pub med: u32,
    pub local_pref: u32,
    pub atomic_aggregate: bool,
    pub aggregator: Option<(AsId, u32)>,
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

impl Display for ExampleBgpPathAttributes {
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
    fn merge_update(&mut self, update_meta: Self) -> Result<(), Box<dyn std::error::Error>> {
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
}
