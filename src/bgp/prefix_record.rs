use std::borrow::Cow;
use std::fmt;

use crate::{
    addr::Prefix,
    record::{Key, LogicalTime, Meta, Record, SenderIdInt},
};

impl Key for Prefix where Self: Copy + Sized {}

//------------ PrefixRecord -------------------------------------------------

/// Record with a single prefix as key and arbitrary meta-data
///
/// PrefixRecord is the `atomic record` type that has a single prefix as the
/// key, and the path attributes of the NLRI it is contained in. Useful to
/// disassemble BGP packets into several atomic records.

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

impl<'a, Meta: crate::record::Meta> crate::record::MessageRecord<'a>
    for PrefixRecord<'a, Meta>
where
    Meta: crate::record::Meta,
{
    type SenderId = SenderIdInt;

    fn new(
        key: Self::Key,
        meta: Self::Meta,
        sender_id: Self::SenderId,
        ltime: u64,
    ) -> Self {
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

    fn new_from_record(
        record: Self,
        sender_id: Self::SenderId,
        ltime: u64,
    ) -> Self {
        Self {
            sender_id,
            ltime,
            prefix: record.prefix,
            meta: record.meta,
        }
    }

    #[must_use]
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

impl<'a, Meta> From<(Prefix, &'a Meta)> for PrefixRecord<'a, Meta>
where
    Meta: crate::record::Meta,
{
    fn from((prefix, meta): (Prefix, &'a Meta)) -> Self {
        Self {
            prefix,
            meta: Cow::Borrowed(meta),
            sender_id: SenderIdInt::default(),
            ltime: LogicalTime::default(),
        }
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

//------------ RecordSet ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct RecordSet<'a, Meta: crate::record::Meta> {
    pub v4: Vec<PrefixRecord<'a, Meta>>,
    pub v6: Vec<PrefixRecord<'a, Meta>>,
}

impl<'a, Meta: crate::record::Meta> RecordSet<'a, Meta> {
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub fn iter(&self) -> RecordSetIter<Meta> {
        RecordSetIter {
            v4: if self.v4.is_empty() {
                None
            } else {
                Some(self.v4.iter())
            },
            v6: self.v6.iter(),
        }
    }

    #[must_use]
    pub fn reverse(mut self) -> RecordSet<'a, Meta> {
        self.v4.reverse();
        self.v6.reverse();
        self
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }
}

impl<'a, Meta: crate::record::Meta> fmt::Display for RecordSet<'a, Meta> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let arr_str_v4 =
            self.v4.iter().fold("".to_string(), |pfx_arr, pfx| {
                format!("{} {}", pfx_arr, *pfx)
            });
        let arr_str_v6 =
            self.v6.iter().fold("".to_string(), |pfx_arr, pfx| {
                format!("{} {}", pfx_arr, *pfx)
            });

        write!(f, "V4: [{}], V6: [{}]", arr_str_v4, arr_str_v6)
    }
}

impl<'a, Meta: crate::record::Meta>
    From<(Vec<PrefixRecord<'a, Meta>>, Vec<PrefixRecord<'a, Meta>>)>
    for RecordSet<'a, Meta>
{
    fn from(
        (v4, v6): (Vec<PrefixRecord<'a, Meta>>, Vec<PrefixRecord<'a, Meta>>),
    ) -> Self {
        Self { v4, v6 }
    }
}

impl<'a, Meta: crate::record::Meta>
    std::iter::FromIterator<&'a PrefixRecord<'a, Meta>>
    for RecordSet<'a, Meta>
{
    fn from_iter<I: IntoIterator<Item = &'a PrefixRecord<'a, Meta>>>(
        iter: I,
    ) -> Self {
        let mut v4 = vec![];
        let mut v6 = vec![];
        for pfx in iter {
            let u_pfx = pfx.prefix;
            match u_pfx.addr() {
                std::net::IpAddr::V4(_) => {
                    v4.push(PrefixRecord::new(u_pfx, pfx.meta.as_ref()));
                }
                std::net::IpAddr::V6(_) => {
                    v6.push(PrefixRecord::new(u_pfx, pfx.meta.as_ref()));
                }
            }
        }
        Self { v4, v6 }
    }
}

impl<'a, Meta: crate::record::Meta> std::ops::Index<usize>
    for RecordSet<'a, Meta>
{
    type Output = PrefixRecord<'a, Meta>;

    fn index(&self, index: usize) -> &Self::Output {
        if index < self.v4.len() {
            &self.v4[index]
        } else {
            &self.v6[index - self.v4.len()]
        }
    }
}

//------------ RecordSetIter ------------------------------------------------

#[derive(Clone, Debug)]
pub struct RecordSetIter<'a, Meta: crate::record::Meta> {
    v4: Option<std::slice::Iter<'a, PrefixRecord<'a, Meta>>>,
    v6: std::slice::Iter<'a, PrefixRecord<'a, Meta>>,
}

impl<'a, Meta: crate::record::Meta> Iterator for RecordSetIter<'a, Meta> {
    type Item = PrefixRecord<'a, Meta>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.v4.is_none() {
            return self.v6.next().map(|res| res.to_owned());
        }

        if let Some(res) = self.v4.as_mut().and_then(|v4| v4.next()) {
            return Some(res.to_owned());
        }
        self.v4 = None;
        self.next()
    }
}

//------------ MetaDataSet ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct MetaDataSet<'a, M: crate::record::Meta>(Vec<&'a M>);

impl<'a, M: crate::record::Meta> MetaDataSet<'a, M> {
    pub fn new(v: Vec<&'a M>) -> Self {
        Self(v)
    }
}

impl<'a, M: crate::record::Meta> fmt::Display for MetaDataSet<'a, M> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let arr_str = self.0.iter().fold("".to_string(), |pfx_arr, pfx| {
            format!("{} {}", pfx_arr, *pfx)
        });

        write!(f, "[{}]", arr_str)
    }
}

impl<'a, M: crate::record::Meta + 'a> std::iter::FromIterator<&'a M>
    for MetaDataSet<'a, M>
{
    fn from_iter<I: IntoIterator<Item = &'a M>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl<'a, M: crate::record::Meta + 'a> std::ops::Index<usize>
    for MetaDataSet<'a, M>
{
    type Output = &'a M;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}
