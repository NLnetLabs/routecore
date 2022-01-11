//! Generic record types
//!
//! Records hold snippets of information that are contained in a
//! BGP packet. The type of the key is variable: it can be an NLRI, or the
//! NLRI can be disassembled into several records with the prefixes contained
//! in the NLRI as key.
//!
//! A record can be turned into a message (MessageRecord trait) to be ready
//! to be send to other units, or external systems. A message has no
//! references (anymore).
//!
//! example:
//! BGP packet → disassemble into records → turn into message → send to other
//! units
//!
//! See ```bgp``` module for records specific to BGP.
use std::borrow::Cow;
use std::fmt;

//------------ Traits for Record --------------------------------------------

/// Trait for types that act as keys for records.
///
/// These traits must be implemented by all record types.

/// Trait that describes the record key, a key can be a NLRI (or a part of
/// that), but it can also be other TLVs originating from a BGP packet.

/// Key of a record
pub trait Key {}
impl Key for (u64, u32) where Self: Copy + Sized {}

/// Trait for a type to act as the identity of the message sender
pub trait SenderId
where
    Self: Copy + Sized,
{
}

impl SenderId for u32 {}

/// Sender ID type
pub type SenderIdInt = u32;

/// Lamport Timestamp. Used to order messages between units/systems.
pub type LogicalTime = u64;

/// Generic Record trait
///
/// The Record trait describes any type that has a key and metadata, and that
/// it is not a message (yet). The type should accomodate both holding
/// metadata as a reference, as well as storing the metadata inside itself.
///
/// Types implementing this trait should be used to disassemble BGP packets
/// into storable data points.
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

/// Record as a stand-alone message
///
/// The MessageRecord trait describes a record turned message. It should have
/// at least two fields, `sender_id` and `ltime` (or be able to synthesize
/// those).
///
/// A generic record type (that implements the Record trait) should be able
/// to be turned into a message record. The message should own all the data
/// it holds so it can be cut loose and send off to other systems through
/// cloning and/or serialization.
///
/// The MessageRecord type should be used to send messages to other units or
/// external systems.
pub trait MessageRecord<'a>
where
    Self: Clone + Record<'a>,
{
    type SenderId: crate::record::SenderId;

    fn new(
        key: <Self as Record<'a>>::Key,
        meta: <Self as Record<'a>>::Meta,
        sender_id: Self::SenderId,
        // Logical Time of this message (Lamport timestamp)
        ltime: u64,
    ) -> Self;
    fn new_from_record(
        record: Self,
        sender_id: Self::SenderId,
        ltime: u64,
    ) -> Self;
    #[must_use]
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

//----------------------- meta-data traits/types-----------------------------

/// Trait that describes how an existing record gets merged
///
/// MergeUpdate must be implemented by a type that implements Meta if it
/// wants to be able to be stored. It should describe how the metadata for an
/// existing record should be merged with newly arriving records for the same
/// key.
pub trait MergeUpdate {
    fn merge_update(
        &mut self,
        update_meta: Self,
    ) -> Result<(), Box<dyn std::error::Error>>;

    // This is part of the Read-Copy-Update pattern for updating a record
    // concurrently. The Read part should be done by the caller and then
    // the result should be passed in into this function together with
    // the new meta-data that updates it. This function will then create
    // a copy (in the pattern lingo, but in Rust that would be a Clone,
    // since we're not requiring Copy for Meta) and update that with a
    // copy of the new meta-data. It then returns the result of that merge.
    // The caller should then proceed to insert that as a new entry
    // in the global store.
    fn clone_merge_update(
        &self,
        update_meta: &Self,
    ) -> Result<Self, Box<dyn std::error::Error>>
    where
        Self: std::marker::Sized;
}

/// Trait for types that can be used as metadata of a record
pub trait Meta
where
    Self: fmt::Debug + Sized + fmt::Display + Clone,
{
    fn summary(&self) -> String;
}

impl<T> Meta for T
where
    T: fmt::Debug + fmt::Display + Clone,
{
    fn summary(&self) -> String {
        format!("{}", self)
    }
}

/// Tree-wide empty meta-data type
///
/// A special type that indicates that there's no metadata in the tree
/// storing the prefixes. Note that this is different from a tree with
/// optional meta-data.
#[derive(Clone, Copy)]
pub enum NoMeta {
    Empty,
}

impl fmt::Debug for NoMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("")
    }
}

impl fmt::Display for NoMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("")
    }
}

impl MergeUpdate for NoMeta {
    fn merge_update(
        &mut self,
        _: NoMeta,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    fn clone_merge_update(
        &self,
        _: &NoMeta,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(NoMeta::Empty)
    }
}
