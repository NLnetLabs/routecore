use std::borrow::Cow;
use std::fmt;
use std::fmt::{Debug, Display};

use crate::asn::{AsId, AsPath};
use crate::addr::Prefix;

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

pub trait Record<'a>
where
    Self: Clone,
{
    type Key: crate::record::Key;
    type Meta: crate::record::Meta;

    fn new(key: Self::Key, meta: &'a Self::Meta) -> Self;
    fn new_with_local_meta(key: Self::Key, local_meta: Self::Meta) -> Self;
    fn key(&'a self) -> Self::Key;
    fn meta(&'a self) -> Cow<'a, Self::Meta>;
}

pub trait MessageRecord<'a>
where
    Self: Clone + Record<'a>,
{
    type SenderId: crate::record::SenderId;

    fn new(
        key: <Self as Record<'a>>::Key,
        meta: <Self as Record<'a>>::Meta,
        sender_id: Self::SenderId,
        ltime: u64,
    ) -> Self;
    fn new_from_record(record: Self, sender_id: Self::SenderId, ltime: u64) -> Self;
    fn into_message(self, sender_id: Self::SenderId, ltime: u64) -> Self;
    fn sender_id(&self) -> Self::SenderId;
    fn key(&'a self) -> <Self as Record<'a>>::Key {
        <Self as Record>::key(self)
    }
    fn meta(&'a self) -> Cow<<Self as Record<'a>>::Meta> {
        Cow::Owned(<Self as Record>::meta(self).into_owned())
    }
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
pub struct Route<'a, Nlri, Meta>
where
    Nlri: crate::record::Nlri,
    Meta: crate::record::Meta,
{
    sender_id: SenderIdInt,
    key: (LogicalTime, SenderIdInt),
    nlri: Nlri,
    attributes: Cow<'a, Meta>,
    ltime: LogicalTime,
}

impl<'a> Record<'a> for Route<'a, PrefixNlri, ExampleBgpPathAttributes> {
    type Meta = BgpNlriMeta<'a>;
    type Key = (LogicalTime, SenderIdInt);

    fn key(&'a self) -> <Self as Record<'a>>::Key {
        (self.ltime, self.sender_id)
    }

    fn meta(&'a self) -> Cow<crate::record::BgpNlriMeta<'a>> {
        Cow::Owned(BgpNlriMeta {
            attributes: Cow::Borrowed(&self.attributes),
            nlri: self.nlri.clone(),
        })
    }

    fn new(key: Self::Key, meta: &'a Self::Meta) -> Self {
        Route {
            sender_id: key.1,
            key,
            nlri: meta.nlri.clone(),
            attributes: Cow::Borrowed(&meta.attributes),
            ltime: key.0,
        }
    }

    fn new_with_local_meta(key: Self::Key, local_meta: Self::Meta) -> Self {
        Route {
            sender_id: key.1,
            key,
            nlri: local_meta.nlri,
            attributes: local_meta.attributes,
            ltime: key.0,
        }
    }
}

impl<'a> MessageRecord<'a> for Route<'a, PrefixNlri, ExampleBgpPathAttributes> {
    type SenderId = SenderIdInt;

    fn new(
        key: <Self as Record<'a>>::Key,
        meta: <Self as Record<'a>>::Meta,
        sender_id: Self::SenderId,
        ltime: u64,
    ) -> Self {
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

    fn new_from_record(record: Self, sender_id: Self::SenderId, ltime: u64) -> Self {
        Self {
            key: record.key,
            nlri: record.nlri,
            attributes: record.attributes,
            sender_id,
            ltime,
        }
    }

    fn into_message(mut self, sender_id: SenderIdInt, ltime: u64) -> Self {
        self.sender_id = sender_id;
        self.ltime = ltime;
        self
    }
}

//-------------------- SinglePrefixRoute -----------------------------------------------

#[derive(Clone)]
pub struct SinglePrefixRoute<'a, Meta>
where
    Meta: crate::record::Meta,
{
    pub sender_id: SenderIdInt,
    pub ltime: LogicalTime,
    pub prefix: Prefix,
    pub meta: Cow<'a, Meta>,
}

impl<'a, Meta: crate::record::Meta> Record<'a> for SinglePrefixRoute<'a, Meta> {
    type Meta = Meta;
    type Key = Prefix;

    fn key(&'a self) -> <Self as Record<'a>>::Key {
        self.prefix
    }

    fn meta(&'a self) -> Cow<<Self as Record<'a>>::Meta> {
        Cow::Borrowed(&self.meta)
    }

    fn new(prefix: Self::Key, meta: &'a Self::Meta) -> Self {
        Self {
            prefix,
            meta: Cow::Borrowed(meta),
            sender_id: SenderIdInt::default(),
            ltime: LogicalTime::default(),
        }
    }

    fn new_with_local_meta(prefix: Self::Key, meta: Self::Meta) -> Self {
        Self {
            prefix,
            meta: Cow::Owned(meta),
            sender_id: SenderIdInt::default(),
            ltime: LogicalTime::default(),
        }
    }
}

impl<'a, Meta: crate::record::Meta> MessageRecord<'a> for SinglePrefixRoute<'a, Meta>
where
    Meta: crate::record::Meta,
{
    type SenderId = SenderIdInt;

    fn new(key: Self::Key, meta: Self::Meta, sender_id: Self::SenderId, ltime: u64) -> Self {
        SinglePrefixRoute {
            prefix: key,
            meta: Cow::Owned(meta),
            sender_id,
            ltime,
        }
    }

    fn sender_id(&self) -> Self::SenderId {
        self.sender_id
    }

    fn key(&'a self) -> Self::Key {
        self.prefix
    }

    fn meta(&'a self) -> Cow<'a, Self::Meta> {
        Cow::Borrowed(&self.meta)
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

    fn new_from_record(record: Self, sender_id: Self::SenderId, ltime: u64) -> Self {
        Self {
            sender_id,
            ltime,
            prefix: record.prefix,
            meta: record.meta,
        }
    }

    fn into_message(mut self, sender_id: Self::SenderId, ltime: u64) -> Self {
        self.sender_id = sender_id;
        self.ltime = ltime;
        self
    }

    fn inc_ltime(&mut self) -> u64 {
        let ltime = self.ltime();
        self.set_ltime(ltime + 1)
    }
}

impl<'a, Meta> std::fmt::Display for SinglePrefixRoute<'a, Meta>
where
    Meta: crate::record::Meta,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{}-{}",
            self.prefix.addr(),
            self.prefix.len(),
            self.meta.summary()
        )
    }
}

impl<'a, T> Debug for SinglePrefixRoute<'a, T>
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
    Self: Debug + Sized + Display + Clone,
{
    fn summary(&self) -> String;
}

impl<T> Meta for T
where
    T: Debug + Display + Clone,
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
pub struct BgpNlriMeta<'a> {
    nlri: PrefixNlri,
    attributes: Cow<'a, ExampleBgpPathAttributes>,
}

impl<'a> Display for BgpNlriMeta<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}, {}", self.nlri, self.attributes)
    }
}

impl<'a> MergeUpdate for BgpNlriMeta<'a> {
    fn merge_update(&mut self, update_meta: Self) -> Result<(), Box<dyn std::error::Error>> {
        self.attributes
            .to_mut()
            .merge_update(update_meta.attributes.into_owned())?;
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
