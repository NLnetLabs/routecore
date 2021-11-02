use std::fmt;
use std::borrow::Cow;

use crate::{
    addr::Prefix,
    record::{Key, LogicalTime, MessageRecord, Meta, Record, SenderIdInt},
};

impl Key for Prefix where Self: Copy + Sized {}


//-------------------- PrefixRecord -----------------------------------------------

/// Record with a single prefix as key and arbitrary meta-data
/// 
/// PrefixRecord is the `atomic record` type that has a single prefix as the key,
/// and the path attributes of the NLRI it is contained in.
/// Useful to disassemble BGP packets into several atomic records.

#[derive(Clone)]
pub struct PrefixRecord<'a, Meta>
where
    Meta: crate::record::Meta,
{
    pub sender_id: SenderIdInt,
    pub ltime: LogicalTime,
    pub prefix: Prefix,
    pub meta: Cow<'a, Meta>,
}

impl<'a, Meta: crate::record::Meta> Record<'a> for PrefixRecord<'a, Meta> {
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

impl<'a, Meta: crate::record::Meta> MessageRecord<'a> for PrefixRecord<'a, Meta>
where
    Meta: crate::record::Meta,
{
    type SenderId = SenderIdInt;

    fn new(key: Self::Key, meta: Self::Meta, sender_id: Self::SenderId, ltime: u64) -> Self {
        PrefixRecord {
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

impl<'a, Meta> std::fmt::Display for PrefixRecord<'a, Meta>
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

impl<'a, T> fmt::Debug for PrefixRecord<'a, T>
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
