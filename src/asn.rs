//! Types for Autonomous Systems Numbers (ASN) and ASN collections

use std::str::FromStr;
use std::convert::{TryFrom, TryInto};
use std::{error, fmt, ops};


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


//------------ PathSegment ---------------------------------------------------

/// A segment of an AS path.
#[derive(Debug, Clone, Copy)]
pub struct PathSegment<'a> {
    /// The type of the path segment.
    stype: SegmentType,

    /// The elements of the path segment.
    elements: &'a [AsId],
}

impl<'a> PathSegment<'a> {
    /// Creates a path segment from a type and a slice of elements.
    fn new(stype: SegmentType, elements: &'a [AsId]) -> Self {
        PathSegment { stype, elements }
    }

    /// Returns the type of the segment.
    pub fn segment_type(self) -> SegmentType {
        self.stype
    }

    /// Returns a slice with the elements of the segment.
    pub fn elements(self) -> &'a [AsId] {
        self.elements
    }
}


//--- Display

impl fmt::Display for PathSegment<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}(", self.stype)?;
        if let Some((first, tail)) = self.elements.split_first() {
            write!(f, "{}", first)?;
            for elem in tail {
                write!(f, ", {}", elem)?;
            }
        }
        write!(f, ")")
    }
}


//------------ SegmentType ---------------------------------------------------

/// The type of a path segment.
///
/// This is a private helper type for encoding the type into, er, other
/// things.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SegmentType {
    /// The segment is an AS_SET.
    ///
    /// An AS_SET is an unordered set of autonomous systems that a route in
    /// an UPDATE BGP message has traversed.
    Set,

    /// The segment is an AS_SEQUENCE.
    ///
    /// An AS_SET is an ordered set of autonomous systems that a route in
    /// an UPDATE BGP message has traversed.
    Sequence,

    /// The segment is an AS_CONFED_SEQUENCE.
    ///
    /// An AS_CONFED_SEQUENCE is an ordered set of Member Autonomous Systems
    /// in the local confederation that the UPDATE message has traversed.
    ConfedSequence,

    /// The segment is an AS_CONFED_SET.
    ///
    /// An AS_CONFED_SET is an unordered set of Member Autonomous Systems
    /// in the local confederation that the UPDATE message has traversed.
    ConfedSet,
}


//--- TryFrom and From

impl TryFrom<u8> for SegmentType {
    type Error = InvalidSegmentTypeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(SegmentType::Set),
            2 => Ok(SegmentType::Sequence),
            3 => Ok(SegmentType::ConfedSequence),
            4 => Ok(SegmentType::ConfedSet),
            _ => Err(InvalidSegmentTypeError)
        }
    }
}

impl From<SegmentType> for u8 {
    fn from(value: SegmentType) -> u8 {
        match value {
            SegmentType::Set => 1,
            SegmentType::Sequence => 2,
            SegmentType::ConfedSequence => 3,
            SegmentType::ConfedSet => 4,
        }
    }
}


//--- Display

impl fmt::Display for SegmentType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            SegmentType::Set => "AS_SET",
            SegmentType::Sequence => "AS_SEQUENCE",
            SegmentType::ConfedSequence => "AS_CONFED_SEQUENCE", 
            SegmentType::ConfedSet => "AS_CONFED_SET",
        })
    }
}


//-------- AsPath ------------------------------------------------------------

/// An AS path.
///
/// An AS path is a sequence of path segments. The type is generic over some
/// type that provides access to a slice of `AsId`s.
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize)
)]
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
        let (&first, segments) = self.segments.split_first()?;
        let (stype, len) = decode_sentinel(first);
        let (res, tail) = segments.split_at(len as usize);
        self.segments = tail;
        Some(PathSegment::new(stype, res))
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
}

impl AsPathBuilder {
    /// Creates a new, empty AS path builder.
    ///
    /// The builder will start out with building an initial segement of
    /// sequence type.
    pub fn new() -> Self {
        AsPathBuilder {
            segments: vec![encode_sentinel(SegmentType::Sequence, 0)],
            curr_start: 0,
        }
    }

    /// Internal version of the two start methods.
    pub fn start(&mut self, stype: SegmentType) {
        let len = self.segment_len();
        if len > 0 {
            update_sentinel_len(
                &mut self.segments[self.curr_start], len as u8
            );
            self.curr_start = self.segments.len();
            self.segments.push(encode_sentinel(stype, 0));
        }
        else {
            self.segments[self.curr_start] = encode_sentinel(stype, 0);
        }
    }

    /// Returns the length of the currently built segment.
    pub fn segment_len(&self) -> usize {
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
            update_sentinel_len(
                &mut self.segments[self.curr_start], len as u8
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


//------------ AsID as path segment sentinel ---------------------------------

/// Converts a sentinel `AsId` into a segment type and length.
fn decode_sentinel(sentinel: AsId) -> (SegmentType, u8) {
    (
        ((sentinel.0 >> 8) as u8)
            .try_into().expect("illegally encoded AS path"),
        sentinel.0 as u8
    )
}

/// Converts segment type and length into a sentinel `AsId`.
fn encode_sentinel(t: SegmentType, len: u8) -> AsId {
    AsId((u8::from(t) as u32) << 8 | (len as u32))
}

/// Updates the length portion of a sentinel `AsId`.
fn update_sentinel_len(sentinel: &mut AsId, len: u8) {
    sentinel.0 = (sentinel.0 & 0xFFFF_FF00) | len as u32
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


//------------ LongSegmentError ----------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct LongSegmentError;

impl fmt::Display for LongSegmentError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("path segment too long")
    }
}

impl error::Error for LongSegmentError { }


//------------ InvalidSegmentTypeError ---------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct InvalidSegmentTypeError;

impl fmt::Display for InvalidSegmentTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid segment type")
    }
}

impl error::Error for InvalidSegmentTypeError { }


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

