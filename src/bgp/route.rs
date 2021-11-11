use std::borrow::Cow;
use std::fmt;

use crate::addr::Prefix;
use crate::bgp::{BgpNlriMeta, ExampleBgpPathAttributes};
use crate::record::{LogicalTime, MessageRecord, Record, SenderIdInt};

/// Network Layer Reachability Information (NLRI)
///
/// NLRI can be pretty generic, it's not only a bunch of prefixes, it can
/// also be FlowSpec data etc.
pub trait Nlri
where
    Self: Clone,
{
}

//----------------- Route ---------------------------------------------------

/// Record based on a RFC 4271 Route.
///
<<<<<<< HEAD
/// Route is a record that holds a route as described in RFC 4271, which is a NRLI used
/// as a key and a set of (path) attributes.
=======
/// Route is a record that holds a route as described in RFC 4271, which is a
/// NRLI used as a key and a set of (path) attributes.
>>>>>>> 072d476 (reflow 78)
#[derive(Clone)]
pub struct Route<'a, Nlri, Meta>
where
    Nlri: crate::bgp::Nlri,
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

    fn meta(&'a self) -> Cow<BgpNlriMeta<'a>> {
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

impl<'a> MessageRecord<'a>
    for Route<'a, PrefixNlri, ExampleBgpPathAttributes>
{
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

    fn new_from_record(
        record: Self,
        sender_id: Self::SenderId,
        ltime: u64,
    ) -> Self {
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

/// NLRI that consists of multiple prefixes.
#[derive(Clone, Debug)]
pub struct PrefixNlri {
    nlri: Vec<Prefix>,
}

impl fmt::Display for PrefixNlri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PrefixNlri")
    }
}

impl Nlri for PrefixNlri {}
