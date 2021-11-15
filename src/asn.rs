//! Types for Autonomous Systems Numbers (ASN) and ASN collections

use std::str::FromStr;
use std::{borrow, error, fmt, ops};


//------------ AsId ----------------------------------------------------------

/// An AS number (ASN).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct AsId(u32);

impl AsId {
    pub const MIN: AsId = AsId(std::u32::MIN);
    pub const MAX: AsId = AsId(std::u32::MAX);

    /// Creates an AS number from a `u32`.
    pub fn from_u32(value: u32) -> Self {
        AsId(value)
    }

    /// Converts an AS number into a `u32`.
    pub fn into_u32(self) -> u32 {
        self.0
    }

    /// Converts the AS number into a segment type and length.
    ///
    /// This is an internal method used by `AsPath` below to encode all
    /// segments into a single sequence of ASNs.
    fn into_type_and_len(self) -> (SegmentType, u8) {
        (((self.0 >> 8) as u8).into(), self.0 as u8)
    }

    /// Converts segment type and length into an AS number.
    fn from_type_and_len(t: SegmentType, len: u8) -> Self {
        AsId((u8::from(t) as u32) << 8 | (len as u32))
    }
}

#[cfg(feature = "bcder")]
impl AsId {
    /// Takes an AS number from the beginning of an encoded value.
    pub fn take_from<S: bcder::decode::Source>(
        cons: &mut bcder::decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_u32().map(AsId)
    }

    /// Skips over an AS number at the beginning of an encoded value.
    pub fn skip_in<S: bcder::decode::Source>(
        cons: &mut bcder::decode::Constructed<S>
    ) -> Result<(), S::Err> {
        cons.take_u32().map(|_| ())
    }

    /// Parses the content of an AS number value.
    pub fn parse_content<S: bcder::decode::Source>(
        content: &mut bcder::decode::Content<S>,
    ) -> Result<Self, S::Err> {
        content.to_u32().map(AsId)
    }

    /// Skips the content of an AS number value.
    pub fn skip_content<S: bcder::decode::Source>(
        content: &mut bcder::decode::Content<S>
    ) -> Result<(), S::Err> {
        content.to_u32().map(|_| ())
    }

    pub fn encode(self) -> impl bcder::encode::Values {
        bcder::encode::PrimitiveContent::encode(self.0)
    }
}

//--- From

impl From<u32> for AsId {
    fn from(id: u32) -> Self {
        AsId(id)
    }
}

impl From<AsId> for u32 {
    fn from(id: AsId) -> Self {
        id.0
    }
}

//--- FromStr

impl FromStr for AsId {
    type Err = ParseAsIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = if s.len() > 2 && s[..2].eq_ignore_ascii_case("as") {
            &s[2..]
        } else {
            s
        };

        u32::from_str(s).map(AsId).map_err(|_| ParseAsIdError)
    }
}

//--- Serialize and Deserialize

/// # Serialization
///
/// Because there is no commonly agreed upon standard serialization format for
/// AS numbers, we are offering three methods that can be used with Serde’s
/// `serialize_with` field attribute. The implementation of the `Deserialize`
/// trait understands all three options, so no special treatment is necessary.
///
/// There also is a implementation for `Serialize` which will use the
/// derived implementation, i.e., it serializes as a newtype struct with an
/// `u32`. This, of course, is also understood by the `Deserialize` impl.
#[cfg(feature = "serde")]
impl AsId {
    /// Serializes an AS number as an `u32`.
    pub fn serialize_as_u32<S: serde::Serializer>(
        &self, serializer: S
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_u32(self.0)
    }

    /// Seriaizes an AS number as a string without prefix.
    pub fn serialize_as_bare_str<S: serde::Serializer>(
        &self, serializer: S
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("{}", self.0))
    }

    /// Seriaizes an AS number as a string with a `AS` prefix.
    pub fn serialize_as_prefix_str<S: serde::Serializer>(
        &self, serializer: S
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("AS{}", self.0))
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for AsId {
    /// Deserialize an AS number.
    ///
    /// This implementation is extremely flexible with regards to how the AS
    /// number can be encoded. It allows integers as well as string with and
    /// without the `AS` prefix.
    fn deserialize<D: serde::de::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = AsId;

            fn expecting(
                &self, formatter: &mut fmt::Formatter
            ) -> fmt::Result {
                write!(formatter, "an AS number")
            }

            fn visit_str<E: serde::de::Error>(
                self, v: &str
            ) -> Result<Self::Value, E> {
                AsId::from_str(v).map_err(E::custom)
            }

            fn visit_u32<E: serde::de::Error>(
                self, v: u32
            ) -> Result<Self::Value, E> {
                Ok(v.into())
            }

            fn visit_newtype_struct<D: serde::Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                <u32 as serde::Deserialize>::deserialize(
                    deserializer
                ).map(AsId)
            }
        }

        deserializer.deserialize_newtype_struct(
            "AsId", Visitor
        )
    }
}

//--- Add

impl ops::Add<u32> for AsId {
    type Output = Self;

    fn add(self, rhs: u32) -> Self {
        AsId(self.0.checked_add(rhs).unwrap())
    }
}

//--- Display

impl fmt::Display for AsId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AS{}", self.0)
    }
}


//------------ AsSet ---------------------------------------------------------

/// An unordered set of AS numbers.
/// 
/// This type is one of the variants of an [`AsSegment`] in an [`AsPath`]. It
/// describes an unordered set of ASes a route has traversed.
///
/// The type is a thin wrapper around a slice of [`AsId`]s, either as an
/// actual (unsized) slice or an owned form, e.g., a vec.
#[derive(Debug)]
pub struct AsSet([AsId]);

impl AsSet {
    /// Creates a reference to an AS set slice from an `AsId` slice.
    fn from_slice(slice: &[AsId]) -> &Self {
        unsafe { &*(slice as *const [AsId] as *const AsSet) }
    }

    /// Returns a reference to a slice of the AS numbers.
    pub fn as_slice(&self) -> &[AsId] {
        self.0.as_ref()
    }
}

//--- AsRef and Borrow

impl AsRef<[AsId]> for AsSet {
    fn as_ref(&self) -> &[AsId] {
        self.as_slice()
    }
}

impl borrow::Borrow<[AsId]> for AsSet {
    fn borrow(&self) -> &[AsId] {
        self.as_slice()
    }
}


//--- Display

impl fmt::Display for AsSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for item in self.as_slice() {
            write!(f, "{} ", item)?;
        }
        Ok(())
    }
}


//------------ AsSequence ----------------------------------------------------

/// An ordered set of AS numbers.
/// 
/// This type is one of the variants of an [`PathSegment`] in an [`AsPath`].
/// It describes an ordered set of ASes a route has traversed.
///
/// The type is a thin wrapper around a slice of [`AsId`]s, either as an
/// actual (unsized) slice or an owned form, e.g., a vec.
#[derive(Debug)]
pub struct AsSequence([AsId]);

impl AsSequence {
    /// Creates a reference to an AS set slice from an `AsId` slice.
    fn from_slice(slice: &[AsId]) -> &Self {
        unsafe { &*(slice as *const [AsId] as *const AsSequence) }
    }

    /// Returns a reference to a slice of the AS numbers.
    pub fn as_slice(&self) -> &[AsId] {
        self.0.as_ref()
    }
}


//--- AsRef and Borrow

impl AsRef<[AsId]> for AsSequence {
    fn as_ref(&self) -> &[AsId] {
        self.as_slice()
    }
}

impl borrow::Borrow<[AsId]> for AsSequence {
    fn borrow(&self) -> &[AsId] {
        self.as_slice()
    }
}


//--- Display

impl fmt::Display for AsSequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for item in self.as_slice() {
            write!(f, "{},", item)?;
        }
        Ok(())
    }
}


//------------ PathSegment ---------------------------------------------------

/// A segment of an AS path.
///
/// This is either an AS set or an AS sequence.
#[derive(Debug, Clone, Copy)]
pub enum PathSegment<'a> {
    Set(&'a AsSet),
    Sequence(&'a AsSequence),
}

impl<'a> PathSegment<'a> {
    /// Returns whether the segment is a set.
    pub fn is_set(self) -> bool {
        matches!(self, PathSegment::Set(_))
    }

    /// Returns whether the segment is a set.
    pub fn is_sequence(self) -> bool {
        matches!(self, PathSegment::Sequence(_))
    }

    /// Returns a reference to the slice of AS numbers in the segment.
    pub fn as_slice(self) -> &'a [AsId] {
        match self {
            PathSegment::Set(inner) => inner.as_slice(),
            PathSegment::Sequence(inner) => inner.as_slice(),
        }
    }
}

//--- From

impl<'a> From<&'a AsSet> for PathSegment<'a> {
    fn from(set: &'a AsSet) -> Self {
        PathSegment::Set(set)
    }
}

impl<'a> From<&'a AsSequence> for PathSegment<'a> {
    fn from(seq: &'a AsSequence) -> Self {
        PathSegment::Sequence(seq)
    }
}

//--- AsRef and Borrow

impl AsRef<[AsId]> for PathSegment<'_> {
    fn as_ref(&self) -> &[AsId] {
        self.as_slice()
    }
}

impl borrow::Borrow<[AsId]> for PathSegment<'_> {
    fn borrow(&self) -> &[AsId] {
        self.as_slice()
    }
}


//--- Display

impl fmt::Display for PathSegment<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            PathSegment::Set(inner) => inner.fmt(f),
            PathSegment::Sequence(inner) => inner.fmt(f),
        }
    }
}


//-------- AsPath ------------------------------------------------------------

/// An AS path.
///
/// An AS path is a sequence of path segments. The type is generic over some
/// type that provides access to a slice of `AsId`s.
#[derive(Clone, Debug)]
pub struct AsPath<T> {
    /// The segments of the path.
    segments: T,
}

impl<T: AsRef<[AsId]>> AsPath<T> {
    /// Returns an iterator over the segments of the path.
    pub fn iter(&self) -> AsPath<&[AsId]> {
        AsPath { segments: self.segments.as_ref() }
    }
}


//--- IntoIterator and Iterator

impl<'a, T: AsRef<[AsId]>> IntoIterator for &'a AsPath<T> {
    type Item = PathSegment<'a>;
    type IntoIter = AsPath<&'a [AsId]>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> Iterator for AsPath<&'a [AsId]> {
    type Item = PathSegment<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (tpe, len) = self.segments.first()?.into_type_and_len();
        self.segments = self.segments.split_first().unwrap().1;
        let (res, tail) = self.segments.split_at(len as usize);
        self.segments = tail;
        Some(match tpe {
            SegmentType::Set => AsSet::from_slice(res).into(),
            SegmentType::Sequence => AsSequence::from_slice(res).into(),
        })
    }
}


//--- Display

impl<T: AsRef<[AsId]>> fmt::Display for AsPath<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for item in self {
            write!(f, "{}", item)?;
        }
        Ok(())
    }
}


//------------ AsPathBuilder -------------------------------------------------

#[derive(Clone, Debug)]
pub struct AsPathBuilder {
    /// A vec with the elements we have so far.
    segments: Vec<AsId>,

    /// The index of the head element of the currently build segment.
    curr_start: usize,

    /// The type of the currently built segment.
    curr_type: SegmentType,
}

impl AsPathBuilder {
    /// Creates a new, empty AS path builder.
    ///
    /// The builder will start out with building an initial segement of
    /// sequence type.
    pub fn new() -> Self {
        AsPathBuilder {
            segments: vec![AsId(0)],
            curr_start: 0,
            curr_type: SegmentType::Sequence,
        }
    }

    /// Starts a new set segment.
    ///
    /// Finishes the currently built segment if it isn’t empty.
    pub fn start_set(&mut self) {
        self.start(SegmentType::Set)
    }

    /// Starts a new sequence segment.
    ///
    /// Finishes the currently built segment if it isn’t empty.
    pub fn start_sequence(&mut self) {
        self.start(SegmentType::Sequence)
    }

    /// Internal version of the two start methods.
    fn start(&mut self, tpe: SegmentType) {
        let len = self.segment_len();
        if len > 0 {
            self.segments[self.curr_start] = AsId::from_type_and_len(
                self.curr_type, len as u8
            );
            self.curr_start = self.segments.len();
            self.segments.push(AsId(0));
        }
        self.curr_type = tpe;
    }

    /// Returns the length of the currently built segment.
    fn segment_len(&self) -> usize {
        self.segments.len() - self.curr_start - 1
    }

    /// Appends an AS number to the currently built segment.
    ///
    /// This can fail if it would result in a segment that is longer than
    /// 255 ASNs.
    pub fn push(&mut self, asn: AsId) -> Result<(), LongSegmentError> {
        if self.segment_len() == 255 {
            return Err(LongSegmentError)
        }
        self.segments.push(asn);
        Ok(())
    }

    /// Appends the content of a slice of ASNs to the currently built segment.
    ///
    /// This can fail if it would result in a segment that is longer than
    /// 255 ASNs.
    pub fn extend_from_slice(
        &mut self, other: &[AsId]
    ) -> Result<(), LongSegmentError> {
        if self.segment_len() + other.len() > 255 {
            return Err(LongSegmentError)
        }
        self.segments.extend_from_slice(other);
        Ok(())
    }

    /// Finalizes and returns the AS path.
    pub fn finalize<U: From<Vec<AsId>>>(mut self) -> AsPath<U> {
        let len = self.segment_len();
        if len > 0 {
            self.segments[self.curr_start] = AsId::from_type_and_len(
                self.curr_type, len as u8
            );
        }
        AsPath { segments: self.segments.into() }
    }
}


//--- Default

impl Default for AsPathBuilder {
    fn default() -> Self {
        Self::new()
    }
}


//------------ SegmentType ---------------------------------------------------

/// The type of a path segment.
///
/// This is a private helper type for encoding the type into, er, other
/// things.
#[derive(Clone, Copy, Debug)]
enum SegmentType {
    Set,
    Sequence,
}

impl From<u8> for SegmentType {
    fn from(value: u8) -> SegmentType {
        match value {
            0 => SegmentType::Set,
            1 => SegmentType::Sequence,
            _ => unreachable!()
        }
    }
}

impl From<SegmentType> for u8 {
    fn from(value: SegmentType) -> u8 {
        match value {
            SegmentType::Set => 0,
            SegmentType::Sequence => 1
        }
    }
}


//============ Error Types ===================================================

//------------ ParseAsIdError ------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseAsIdError;

impl fmt::Display for ParseAsIdError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid AS number")
    }
}

impl error::Error for ParseAsIdError {}


#[derive(Clone, Copy, Debug)]
pub struct LongSegmentError;

impl fmt::Display for LongSegmentError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("path segment too long")
    }
}

impl error::Error for LongSegmentError { }


//============ Tests =========================================================

#[cfg(all(test, feature = "serde"))]
mod test_serde {
    use super::*;
    use serde_test::{Token, assert_tokens, assert_de_tokens};
    
    #[test]
    fn as_id() {
        assert_tokens(
            &AsId(0),
            &[Token::NewtypeStruct { name: "AsId" }, Token::U32(0)]
        );
        assert_de_tokens(
            &AsId(0),
            &[Token::U32(0)]
        );
        assert_de_tokens(
            &AsId(0),
            &[Token::Str("0")]
        );
        assert_de_tokens(
            &AsId(0),
            &[Token::Str("AS0")]
        );
        assert_de_tokens(
            &AsId(0),
            &[Token::Str("as0")]
        );
    }
}

