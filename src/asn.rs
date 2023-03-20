//! Types for Autonomous Systems Numbers (ASN) and ASN collections

use std::str::FromStr;
use std::convert::{TryFrom, TryInto};
use std::{error, fmt, ops, vec};
use std::ops::Index;

use octseq::{Octets, Parser};
use octseq::builder::OctetsBuilder;

#[cfg(feature = "bcder")]
use bcder::decode::{self, DecodeError, Source};


//------------ Asn -----------------------------------------------------------

/// An AS number (ASN).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Asn(u32);

impl Asn {
    pub const MIN: Asn = Asn(std::u32::MIN);
    pub const MAX: Asn = Asn(std::u32::MAX);

    /// Creates an AS number from a `u32`.
    pub fn from_u32(value: u32) -> Self {
        Asn(value)
    }

    /// Converts an AS number into a `u32`.
    pub fn into_u32(self) -> u32 {
        self.0
    }

    /// Converts an AS number into a network-order byte array.
    pub fn to_raw(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

impl AsRef<Asn> for Asn {
    fn as_ref(&self) -> &Asn {
        &self
    }
}

#[cfg(feature = "bcder")]
impl Asn {
    /// Takes an AS number from the beginning of an encoded value.
    pub fn take_from<S: Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_u32().map(Asn)
    }

    /// Skips over an AS number at the beginning of an encoded value.
    pub fn skip_in<S: Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<(), DecodeError<S::Error>> {
        cons.take_u32().map(|_| ())
    }

    /// Parses the content of an AS number value.
    pub fn parse_content<S: Source>(
        content: &mut decode::Content<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        content.to_u32().map(Asn)
    }

    /// Skips the content of an AS number value.
    pub fn skip_content<S: Source>(
        content: &mut decode::Content<S>
    ) -> Result<(), DecodeError<S::Error>> {
        content.to_u32().map(|_| ())
    }

    pub fn encode(self) -> impl bcder::encode::Values {
        bcder::encode::PrimitiveContent::encode(self.0)
    }
}

//--- From

impl From<u32> for Asn {
    fn from(id: u32) -> Self {
        Asn(id)
    }
}

impl From<Asn> for u32 {
    fn from(id: Asn) -> Self {
        id.0
    }
}

//--- FromStr

impl FromStr for Asn {
    type Err = ParseAsnError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = if s.len() > 2 && s[..2].eq_ignore_ascii_case("as") {
            &s[2..]
        } else {
            s
        };

        u32::from_str(s).map(Asn).map_err(|_| ParseAsnError)
    }
}


//--- Serialize and Deserialize

/// # Serialization
///
/// With the `"serde"` feature enabled, `Asn` implements the `Serialize` and
/// `Deserialize` traits via _serde-derive_ as a newtype wrapping a `u32`.
///
/// However, ASNs are often serialized as a string prefix with `AS`. In order
/// to allow this, a number of methods are provided that can be used with
/// Serde’s field attributes to choose how to serialize an ASN as part of a
/// struct.
#[cfg(feature = "serde")]
impl Asn {
    /// Serializes an AS number as a simple `u32`.
    ///
    /// Normally, you wouldn’t need to use this method, as the default
    /// implementation serializes the ASN as a newtype struct with a `u32`
    /// inside which most serialization formats will turn into a sole `u32`.
    /// However, in case your format doesn’t, you can use this method.
    pub fn serialize_as_u32<S: serde::Serializer>(
        &self, serializer: S
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_u32(self.0)
    }

    /// Serializes an AS number as a string without prefix.
    pub fn serialize_as_bare_str<S: serde::Serializer>(
        &self, serializer: S
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("{}", self.0))
    }

    /// Seriaizes an AS number as a string with a `AS` prefix.
    pub fn serialize_as_str<S: serde::Serializer>(
        &self, serializer: S
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("AS{}", self.0))
    }

    /// Deserializes an AS number from a simple `u32`.
    ///
    /// Normally, you wouldn’t need to use this method, as the default
    /// implementation deserializes the ASN from a newtype struct with a
    /// `u32` inside for which most serialization formats will use a sole
    /// `u32`. However, in case your format doesn’t, you can use this method.
    pub fn deserialize_from_u32<'de, D: serde::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        <u32 as serde::Deserialize>::deserialize(deserializer).map(Into::into)
    }

    /// Deserializes an AS number from a string.
    ///
    /// The string may or may not have a case-insensitive `"AS"` prefix.
    pub fn deserialize_from_str<'de, D: serde::de::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Asn;

            fn expecting(
                &self, formatter: &mut fmt::Formatter
            ) -> fmt::Result {
                write!(formatter, "an AS number")
            }

            fn visit_str<E: serde::de::Error>(
                self, v: &str
            ) -> Result<Self::Value, E> {
                Asn::from_str(v).map_err(E::custom)
            }
        }
        deserializer.deserialize_str(Visitor)
    }

    /// Deserializes an AS number as either a string or `u32`.
    ///
    /// This function can only be used with self-describing serialization
    /// formats as it uses `Deserializer::deserialize_any`. It accepts an
    /// AS number as any kind of integer as well as a string with or without
    /// a case-insensitive `"AS"` prefix.
    pub fn deserialize_from_any<'de, D: serde::de::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Asn;

            fn expecting(
                &self, formatter: &mut fmt::Formatter
            ) -> fmt::Result {
                write!(formatter, "an AS number")
            }

            fn visit_u8<E: serde::de::Error>(
                self, v: u8
            ) -> Result<Self::Value, E> {
                Ok(Asn(v.into()))
            }

            fn visit_u16<E: serde::de::Error>(
                self, v: u16
            ) -> Result<Self::Value, E> {
                Ok(Asn(v.into()))
            }

            fn visit_u32<E: serde::de::Error>(
                self, v: u32
            ) -> Result<Self::Value, E> {
                Ok(Asn(v))
            }

            fn visit_u64<E: serde::de::Error>(
                self, v: u64
            ) -> Result<Self::Value, E> {
                Ok(Asn(v.try_into().map_err(E::custom)?))
            }

            fn visit_i8<E: serde::de::Error>(
                self, v: i8
            ) -> Result<Self::Value, E> {
                Ok(Asn(v.try_into().map_err(E::custom)?))
            }

            fn visit_i16<E: serde::de::Error>(
                self, v: i16
            ) -> Result<Self::Value, E> {
                Ok(Asn(v.try_into().map_err(E::custom)?))
            }

            fn visit_i32<E: serde::de::Error>(
                self, v: i32
            ) -> Result<Self::Value, E> {
                Ok(Asn(v.try_into().map_err(E::custom)?))
            }

            fn visit_i64<E: serde::de::Error>(
                self, v: i64
            ) -> Result<Self::Value, E> {
                Ok(Asn(v.try_into().map_err(E::custom)?))
            }

            fn visit_str<E: serde::de::Error>(
                self, v: &str
            ) -> Result<Self::Value, E> {
                Asn::from_str(v).map_err(E::custom)
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

//--- Add

impl ops::Add<u32> for Asn {
    type Output = Self;

    fn add(self, rhs: u32) -> Self {
        Asn(self.0.checked_add(rhs).unwrap())
    }
}

//--- Display

impl fmt::Display for Asn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AS{}", self.0)
    }
}


//------------ PathSegment ---------------------------------------------------

/// A segment of an AS path.
#[derive(Debug, Clone, Copy)]
pub struct PathSegment<'a, Octets> {
    /// The type of the path segment.
    stype: SegmentType,

    /// The elements of the path segment.
    parser: Parser<'a, Octets>,
}

impl<'a, Octs: Octets> PathSegment<'a, Octs> {
    /// Creates a path segment from a type and a slice of elements.
    fn new(stype: SegmentType, parser: Parser<'a, Octs>) -> Self {
        PathSegment { stype, parser }
    }

    /// Returns the type of the segment.
    pub fn segment_type(&self) -> SegmentType {
        self.stype
    }

    /// Returns a slice with the elements of the segment.
    pub fn elements(&self) -> SegmentElementIter<'a, Octs> {
        SegmentElementIter { parser: self.parser }
    }

    pub fn len(&self) -> usize {
        self.elements().count()
    }

    /*
    pub fn elements_ref(self) -> SegmentElementRefIter<'a, Octs> {
        SegmentElementRefIter { parser: self.parser }
    }
    */

    pub fn into_owned(self) -> OwnedPathSegment {
        OwnedPathSegment {
            stype: self.stype,
            elements: self.elements().collect()
        }
    }

    pub fn into_owned2(self) -> OwnedPathSegment2 {
        let inner = self.elements().collect();
        match self.stype {
            SegmentType::Set => OwnedPathSegment2::Set(inner),
            SegmentType::Sequence => OwnedPathSegment2::Sequence(inner),
            SegmentType::ConfedSequence => OwnedPathSegment2::ConfedSequence(inner),
            SegmentType::ConfedSet => OwnedPathSegment2::ConfedSet(inner),
        }
    }
}

/// Another go at an Owned version of PathSegment.
///
/// By implementing Deref and DerefMut, we get Index and IndexMut like
/// features for free.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum OwnedPathSegment2 {
    Set(Vec<Asn>),
    Sequence(Vec<Asn>),
    ConfedSequence(Vec<Asn>),
    ConfedSet(Vec<Asn>),
}

use std::ops::{Deref, DerefMut};

impl Deref for OwnedPathSegment2 {
    type Target = Vec<Asn>;
    fn deref(&self) -> &Self::Target {
        match self {
            OwnedPathSegment2::Set(a) => a,
            OwnedPathSegment2::Sequence(a) => a,
            OwnedPathSegment2::ConfedSequence(a) => a,
            OwnedPathSegment2::ConfedSet(a) => a,
        }
    }
}

impl DerefMut for OwnedPathSegment2 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            OwnedPathSegment2::Set(a) => a,
            OwnedPathSegment2::Sequence(a) => a,
            OwnedPathSegment2::ConfedSequence(a) => a,
            OwnedPathSegment2::ConfedSet(a) => a,
        }
    }
}

impl OwnedPathSegment2 {

    /// Returns the type code.
    pub fn typecode(&self) -> u8 {
        match self {
            OwnedPathSegment2::Set(_) => 1,
            OwnedPathSegment2::Sequence(_) => 2,
            OwnedPathSegment2::ConfedSequence(_) => 3,
            OwnedPathSegment2::ConfedSet(_) => 4,
        }
    }

    /// Appends `asn` to this segment, or throws a LongSegmentError if this
    /// exceeds the maximum of 255 elements per segment.
    pub fn append(&mut self, asn: Asn) -> Result<(), LongSegmentError> {
        if self.len() == 255 {
            return Err(LongSegmentError)
        }
        self.push(asn);
        Ok(())
    }

    /// Prepends `asn` to this segment, or throws a LongSegmentError if this
    /// exceeds the maximum of 255 elements per segment.
    pub fn prepend(&mut self, asn: Asn) -> Result<(), LongSegmentError>  {
        if self.len() == 255 {
            return Err(LongSegmentError)
        }
        self.insert(0, asn);
        Ok(())
    }

    /// Appends the `Asn`s in `slice` to this segment, or throws a
    /// LongSegmentError if this exceeds the maximum of 255 elements per
    /// segment.
    pub fn append_slice(&mut self, slice: &[Asn]) -> Result<(), LongSegmentError>  {
        if self.len() + slice.len() > 255 {
            return Err(LongSegmentError)
        }
        self.extend_from_slice(slice);
        Ok(())
    }

    /// Prepends the `Asn`s in `slice` to this segment, or throws a
    /// LongSegmentError if this exceeds the maximum of 255 elements per
    /// segment.
    pub fn prepend_slice(&mut self, asns: &[Asn]) -> Result<(), LongSegmentError>  {
        if self.len() + asns.len() > 255 {
            return Err(LongSegmentError)
        }
        let mut new = asns.to_vec();
        new.append(self);
        *(*self) = new;
        Ok(())
    }

    // --- convenience methods -----------------------------------------------
    /// Creates a Sequence variant containing `asns`.
    pub fn sequence_from<T: AsRef<[Asn]>>(asns: T)
        -> Result<Self, LongSegmentError>
    {
        if asns.as_ref().len() > 255 { return Err(LongSegmentError); }
        Ok(OwnedPathSegment2::Sequence(asns.as_ref().to_vec()))
    }

    /// Creates a ConfedSequence variant containing `asns`.
    pub fn confed_sequence_from<T: AsRef<[Asn]>>(asns: T)
        -> Result<Self, LongSegmentError>
    {
        if asns.as_ref().len() > 255 { return Err(LongSegmentError); }
        Ok(OwnedPathSegment2::ConfedSequence(asns.as_ref().to_vec()))
    }
 
    /// Creates a Set variant containing `asns`.
    pub fn set_from<T: AsRef<[Asn]>>(asns: T)
        -> Result<Self, LongSegmentError>
    {
        if asns.as_ref().len() > 255 { return Err(LongSegmentError); }
        Ok(OwnedPathSegment2::Set(asns.as_ref().to_vec()))
    }

    /// Creates a ConfedSet variant containing `asns`.
    pub fn confed_set_from<T: AsRef<[Asn]>>(asns: T)
        -> Result<Self, LongSegmentError>
    {
        if asns.as_ref().len() > 255 { return Err(LongSegmentError); }
        Ok(OwnedPathSegment2::ConfedSet(asns.as_ref().to_vec()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedPathSegment {
    stype: SegmentType,
    elements: Vec<Asn>,
}


impl OwnedPathSegment {

    pub fn segment_type(self) -> SegmentType {
        self.stype
    }

    pub fn append(&mut self, asn: Asn) -> Result<(), LongSegmentError> {
        if self.elements.len() == 255 {
            return Err(LongSegmentError)
        }
        self.elements.push(asn);
        Ok(())
    }

    pub fn append_slice(&mut self, slice: &[Asn]) -> Result<(), LongSegmentError>  {
        if self.elements.len() + slice.len() > 255 {
            return Err(LongSegmentError)
        }
        self.elements.extend_from_slice(slice);
        Ok(())
    }

    pub fn prepend_slice(&mut self, asns: &[Asn]) -> Result<(), LongSegmentError>  {
        if self.elements.len() + asns.len() > 255 {
            return Err(LongSegmentError)
        }
        let mut new = asns.to_vec();
        new.append(&mut self.elements);
        self.elements = new;
        Ok(())
    }


    pub fn len(&self) -> usize {
        self.elements.len()
    }

    pub fn prepend(&mut self, asn: Asn) -> Result<(), LongSegmentError>  {
        if self.elements.len() == 255 {
            return Err(LongSegmentError)
        }
        self.elements.insert(0, asn);
        Ok(())
    }

    // --- convenience methods -----------------------------------------------
    
    pub fn sequence_from_slice(asns: &[Asn]) -> Self {
        OwnedPathSegment {
            stype: SegmentType::Sequence,
            elements: asns.to_vec()
        }
    }

    pub fn confed_sequence_from_slice(asns: &[Asn]) -> Self {
        OwnedPathSegment {
            stype: SegmentType::ConfedSequence,
            elements: asns.to_vec()
        }
    }

    pub fn set_from_slice(asns: &[Asn]) -> Self {
        OwnedPathSegment {
            stype: SegmentType::Set,
            elements: asns.to_vec()
        }
    }

    pub fn confed_set_from_slice(asns: &[Asn]) -> Self {
        OwnedPathSegment {
            stype: SegmentType::ConfedSet,
            elements: asns.to_vec()
        }
    }
}

impl Index<usize> for OwnedPathSegment {
    type Output = Asn;

    fn index(&self, i: usize) -> &Self::Output {
        &self.elements[i]
    }

}

impl<'a, Octs: Octets> FromIterator<PathSegment<'a, Octs>> for Vec<OwnedPathSegment> {
    fn from_iter<I: IntoIterator<Item = PathSegment<'a, Octs>>>(it: I) -> Self {
        let mut res = Vec::new();

        for s in it {
            res.push(s.into_owned())
        }
        res
    }
}

impl<'a, Octs: Octets> FromIterator<PathSegment<'a, Octs>> for Vec<OwnedPathSegment2> {
    fn from_iter<I: IntoIterator<Item = PathSegment<'a, Octs>>>(it: I) -> Self {
        let mut res = Vec::new();

        for s in it {
            res.push(s.into_owned2())
        }
        res
    }
}


#[derive(Copy, Clone)]
pub struct SegmentElementIter<'a, Octets> {
    parser: Parser<'a, Octets>
}


impl<'a, Octs: Octets> Iterator for SegmentElementIter<'a, Octs> {
    type Item = Asn;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None
        }
        let n = self.parser.parse_u32().expect("parsed before");
        Some(Asn::from(n))
    }
}


//--- Display

impl<'a, Octs: Octets> fmt::Display for PathSegment<'a, Octs> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}(", self.stype)?;
        let mut elems = self.elements();
        if let Some(e) = elems.next() {
            write!(f, "{}", e)?;
        }
        for elem in elems {
            write!(f, ", {}", elem)?;
        }
        write!(f, ")")
    }
}


//------------ SegmentType ---------------------------------------------------

/// The type of a path segment.
///
/// This is a private helper type for encoding the type into, er, other
/// things.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
/// An AS path is a sequence of path segments, generic over Octets.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Default)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct AsPath<Octets> {
    /// The segments of the path.
    octets: Octets,
}

impl<Octs: Octets> AsPath<Octs> {
    /// Returns an iterator over the segments of the path.
    pub fn iter(&self) -> PathSegmentIter<'_, Octs> {
        let parser = Parser::from_ref(&self.octets);
        PathSegmentIter{ parser } 
    }
    
    /// Returns true if the path contains the given ASN.
    pub fn contains(&self, asn: Asn) -> bool {
        for segment in self.iter() {
            if segment.elements().any(|a| a == asn) {
                return true
            }
        }
        false
    }

    /// Converts this AsPath into an `AsPathBuilder`.
    pub fn into_builder(self) -> AsPathBuilder<Vec<u8>> {
        AsPathBuilder {
            segments: self.iter().collect(),
            target: vec![],
        }
    }

    /// Returns the right-most ASN in the right-most segment.
    ///
    /// A valid path will never have a (Confed) Set as its  right-most
    /// segment, but in that case, a single ASN is returned.
    pub fn origin(&self) -> Option<Asn> {
        if let Some(seg) = self.iter().last() {
            seg.elements().last()
        } else {
            None
        }
    }

    /// Returns true if this AS Path consists of a single segment of type
    /// Sequence.
    pub fn is_single_sequence(&self) -> bool {
        let mut segs = self.iter();
        if let Some(maybe_seq) = segs.next() {
            segs.next().is_none() &&
                maybe_seq.segment_type() == SegmentType::Sequence
        } else {
            false
        }
    }

    /// Returns the length of this AS Path in terms of AS hops.
    ///
    /// Every ASN in a Sequence counts as 1. A non-empty Set counts as 1.
    /// Confederated segments count as 0, as per RFC6065 sec 5.3 point 3.
    pub fn path_len(&self) -> usize {
        self.iter().fold(0, |res, s| {
            match s.segment_type() {
                SegmentType::Sequence => res + s.len(),
                SegmentType::Set => {
                    if s.len() > 0 { res + 1 } else { res }
                }
                _ => res
            }
        })
    }

    /// Prepends `Asn` N times.
    ///
    /// If the left-most segment in the current path is not a Sequence, or if
    /// the maximum number of elements would be exceeded after adding N more
    /// elements, this method returns a PrependError.
    pub fn prepend_n<const N: u8>(&self, asn: Asn)
        -> Result<AsPath<Vec<u8>>, PrependError>
    {
        if let Some(&[cur_type, cur_len]) = self.octets.as_ref().get(0..2) {
            if cur_type != SegmentType::Sequence.into() ||
                cur_len.checked_add(N).is_none() {
                return Err(PrependError);
            }
        }
        let mut new: Vec<u8> = Vec::with_capacity(
            self.octets.as_ref().len() + 4*N as usize //FIXME 16bit ASN case
        ); 
        new.push(SegmentType::Sequence.into());
        new.push(self.octets.as_ref()[1] + N as u8);
        for _ in 0..N {
            new.extend_from_slice(&asn.to_raw());
        }
        new.extend_from_slice(&self.octets.as_ref()[2..]);
        Ok(AsPath { octets: new })
    }
}


//TODO impl Index<usize> for AsPath

// impl Index<usize> for AsPath<Vec<u8>> {
//     type Output = OwnedPathSegment2;

//     fn index(&self, i: usize) -> &Self::Output {
//         &self.iter().nth(i).map(|s| s.into_owned2()).expect("out of bounds")
//     }
// }

//TODO
//impl <T: AsRef<[Asn]>>TryFrom<T> for AsPath<Vec<u8>>
impl TryFrom<&[Asn]> for AsPath<Vec<u8>> {
    type Error = LongSegmentError;
    fn try_from(t: &[Asn]) -> Result<Self, Self::Error> {
        if t.len() > 255 {
            return Err(LongSegmentError)
        }
        let mut octets = Vec::with_capacity(2 + 4*t.as_ref().len());
        octets.push(SegmentType::Sequence.into());
        octets.push(t.as_ref().len() as u8);
        for asn in t {
            octets.extend_from_slice(&asn.to_raw());
        }

        Ok(AsPath { octets })
    }
}

//struct If<const B: bool>;
//trait True { }
//impl True for If<true> { }

//XXX can we limit N to 0..255 at compile time in any way here?
impl <const N: usize>From<[Asn; N]> for AsPath<Vec<u8>> {
    fn from(t: [Asn; N]) -> Self {
        let mut octets = Vec::with_capacity(2 + 4*t.as_ref().len());
        octets.push(SegmentType::Sequence.into());
        octets.push(t.as_ref().len() as u8);
        for asn in t {
            octets.extend_from_slice(&asn.to_raw());
        }

        AsPath { octets }
    }
}



/// Iterator for PathSegments, generic over Octets.
pub struct PathSegmentIter<'a, Octets> {
    parser: Parser<'a, Octets>,
}

//--- IntoIterator and Iterator

impl<'a, Octs: Octets> IntoIterator for &'a AsPath<Octs> {
    type Item = PathSegment<'a, Octs>;
    type IntoIter = PathSegmentIter<'a, Octs>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, Octs: Octets> Iterator for PathSegmentIter<'a, Octs> {
    type Item = PathSegment<'a, Octs>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None;
        }

        let stype = self.parser.parse_u8().expect("parsed before")
            .try_into().expect("illegally encoded AS path");

        let len = self.parser.parse_u8().expect("parsed before");
        // XXX 4 for 32bit ASNs, how can we support 16bit ASNs nicely?
        let res = self.parser.parse_parser(len as usize * 4).expect("parsed before");
        Some(PathSegment::new(stype, res))
    }
}


//--- Display

impl<Octs: Octets> fmt::Display for AsPath<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for item in self.iter() {
            if first {
                write!(f, "{}", item)?;
                first = false;
            } else {
                write!(f, ", {}", item)?;
            }
        }
        Ok(())
    }
}

//------------ AsPathBuilder -------------------------------------------------


// Luuk (after talking with Jasper):
// we might want to get rid of 'start' and 'push', because those are unclear
// about where things are added (i.e. on the left or the right side of the
// path).
// Instead, everything should be either prepend, or append.
// There will be no 'current segment' to alter.
// For confederation, specific methods are introduced, e.g. append_confed or
// something alike.

/// Builder for `AsPath`s.
///
/// To minimize ambiguity, methods are named to explicitly include the type of
/// segment they operate on (e.g. `_as_sequence`) and whether the modification
/// should happen at the left (`prepend_`) or the right (`append_`) of the path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AsPathBuilder<Target> { // XXX use FreezeBuilder?
    /// The (owned) segments of the path being built.
    segments: Vec<OwnedPathSegment2>,
   
    /// The destination once completely built.
    target: Target,
}

impl<Target: OctetsBuilder> AsPathBuilder<Target> {
    /// Creates a new, empty AS path builder.
    ///
    /// The builder will start out without any segments: those have to be
    /// added explicitly to disambiguate segment types.
    pub fn from_target(target: Target) -> Self {
        AsPathBuilder {
            segments: vec![],
            target,
        }
    }

    pub fn segments_len(&self) -> usize {
        self.segments.len()
    }
    /// Appends ASNs in forms of an AS_SEQUENCE segment type.
    ///
    /// If there is no segment yet, or the right-most segment is not of type
    /// Sequence, a new Sequence is created. If the right-most segment is a
    /// Sequence, the ASNs are appended to that segment. If we go over the
    /// maximum number of ASNs for that segment, new segments are created
    /// accordingly and everything is shifted to the right, i.e. the full
    /// segments are on the right and the non-full segment is on the left. 
    pub fn append_as_sequence(&mut self, asns: &[Asn]) {
        let mut tail = Vec::new();
        // fill up the right most segment, if that is a Sequence
        if let Some(rms @ OwnedPathSegment2::Sequence(_)) = self.segments.last_mut() {
            match rms.append_slice(asns) {
                Ok(_) => return,
                Err(LongSegmentError) => {
                    tail = (*self).segments.pop().unwrap().to_vec();
                }
            }
        }

        tail.extend(asns);

        // add new segments from the remainder
        // the 'first' segment should be the incomplete one!
        let pos = tail.len() % 255; 
        if pos != 0 {
            self.segments.push(
                OwnedPathSegment2::sequence_from(&tail[..pos]).unwrap()
            );
        }
        for c in (&tail[pos..]).chunks(255) {
            self.segments.push(OwnedPathSegment2::sequence_from(c).unwrap());
        }
    }

    // Sets are deprecated or at least their use is discouraged, so instead of
    // trying to deal with Sets bigger than 255, we simply error out.
    pub fn append_as_set(&mut self, asns: &[Asn])
        -> Result<(), LongSegmentError>
    {
        if asns.len() > 255 {
            return Err(LongSegmentError)
        }

        if let Some(rms @ OwnedPathSegment2::Set(_)) = self.segments.last_mut() {
            return rms.append_slice(asns)
        } 

        self.segments.push(OwnedPathSegment2::set_from(asns).unwrap());
        Ok(())
    }


    /// Prepends ASNs in forms of an AS_SEQUENCE segment type.
    ///
    /// If there is no segment yet, or the left-most segment is not of type
    /// Sequence, a new Sequence is created. If the left-most segment is a
    /// Sequence, the ASNs are prepended to that segment.
    /// If the (existing) Sequence goes over 255 elements, additional Sequence
    /// segments are prepended. The order of the ASNs passed to this method is
    /// maintained, so the first elements of the ASNs passed in will end up in
    /// the new, left-most segment of the AS path.
    // TODO add doctest showcasing this
    pub fn prepend_as_sequence<T: AsRef<[Asn]>>(&mut self, asns: T) {

        let mut head = &asns.as_ref()[..];

        // fill up the right most segment, if that is a Sequence
        if let Some(lms @ OwnedPathSegment2::Sequence(_)) = self.segments.first_mut() {
            match lms.prepend_slice(asns.as_ref()) {
                Ok(_) => return,
                Err(LongSegmentError) => {
                    // Fill up the existing segment, `head` contains the
                    // remainder to prepend after this block. 
                    let chunk;
                    (head, chunk) = head.split_at(
                        head.len() - (255 - lms.len())
                        );
                    lms.prepend_slice(chunk).expect("should fit now");
                }
            }
        }

        // We'll create a new vec to eventually replace self.segments.
        let mut new = Vec::with_capacity(
            head.len() / 255 + self.segments.len()
        );

        // First, push what will be the new left most (likely less-than-255
        // long) segment.
        let mut pos = head.len() % 255; 
        if pos != 0 {
            new.push(OwnedPathSegment2::sequence_from(&head[0..pos]).unwrap());
        }

        // Now, we have a multiple of 255 elements left, and we push a
        // segment for each of those:
        while pos < head.len() {
            new.push(
                OwnedPathSegment2::sequence_from(&head[pos..pos+255]).unwrap()
            );
            pos += 255;
        }

        new.append(&mut self.segments);
        self.segments = new;
    }

    pub fn prepend_as_confed_sequence<T: AsRef<[Asn]>>(&mut self, asns: T) {

        let mut head = &asns.as_ref()[..];

        // fill up the right most segment, if that is a Sequence
        if let Some(lms @ OwnedPathSegment2::ConfedSequence(_)) = self.segments.first_mut() {
            match lms.prepend_slice(asns.as_ref()) {
                Ok(_) => return,
                Err(LongSegmentError) => {
                    // Fill up the existing segment, `head` contains the
                    // remainder to prepend after this block. 
                    let chunk;
                    (head, chunk) = head.split_at(
                        head.len() - (255 - lms.len())
                        );
                    lms.prepend_slice(chunk).expect("should fit now");
                }
            }
        }

        // We'll create a new vec to eventually replace self.segments.
        let mut new = Vec::with_capacity(
            head.len() / 255 + self.segments.len()
        );

        // First, push what will be the new left most (likely less-than-255
        // long) segment.
        let mut pos = head.len() % 255; 
        if pos != 0 {
            new.push(OwnedPathSegment2::confed_sequence_from(&head[0..pos]).unwrap());
        }

        // Now, we have a multiple of 255 elements left, and we push a
        // segment for each of those:
        while pos < head.len() {
            new.push(
                OwnedPathSegment2::confed_sequence_from(&head[pos..pos+255]).unwrap()
            );
            pos += 255;
        }

        new.append(&mut self.segments);
        self.segments = new;
    }



    pub fn prepend_as_set<T: AsRef<[Asn]>>(&mut self, asns: T)
        -> Result<(), LongSegmentError>
    {
        if asns.as_ref().len() > 255 {
            return Err(LongSegmentError)
        }

        if let Some(lms @ OwnedPathSegment2::Set(_)) = self.segments.first_mut() {
            return lms.append_slice(asns.as_ref());
        } 

        self.segments.insert(0, OwnedPathSegment2::set_from(asns).unwrap());
        Ok(())
    }

    //pub fn prepend_as(&mut self, stype: SegmentType, asns: &[Asn]) {
    //fixme?
    //    match stype {
    //        SegmentType::Sequence => self.prepend_as_sequence(asns),
    //        SegmentType::Set => self.prepend_as_set(asns),
    //        SegmentType::ConfedSequence => self.prepend_as_confed_sequence(asns),
    //        SegmentType::Sequence => self.prepend_as_sequence(asns),
    //    }
    //}


    /// Alias for `append_as_sequence`.
    pub fn append(&mut self, asn: Asn) {
        self.append_as_sequence(&[asn]);
    }

    /// TODO?
    pub fn extend_from_aspath() { todo!() }
    /// TODO?
    pub fn insert_vec() { todo!() }

    /// Alias for `prepend_as_sequence`.
    pub fn prepend(&mut self, asn: Asn) {
        self.prepend_as_sequence(&[asn]);
    }

    /// Returns the length of this AS Path in terms of AS hops.
    ///
    /// Every ASN in a Sequence counts as 1. A non-empty Set counts as 1.
    /// Confederated segments count as 0, as per RFC6065 sec 5.3 point 3.
    pub fn path_len(&self) -> usize {
        self.segments.iter().fold(0, |res, s| {
            match s {
                OwnedPathSegment2::Sequence(_) => res + s.len(),
                OwnedPathSegment2::Set(a) if a.len() > 0 => res + 1,
                _ => res
            }
        })
    }

    /// Convert this builder into an immutable `AsPath`.
    pub fn finalize(mut self) -> Result<AsPath<Target>, Target::AppendError> {
        for s in self.segments {
            if s.len() == 0 {
                continue;
            }
            self.target.append_slice(&[s.typecode()])?;
            self.target.append_slice(&[s.len() as u8])?;
            //self.target.append_slice(&[s.stype.into()])?;
            //self.target.append_slice(&[s.elements.len() as u8])?;
            for e in &(*s) {
                self.target.append_slice(&e.to_raw())?;
            }
        }

        Ok(AsPath { octets: self.target })
    }
}



impl AsPathBuilder<Vec<u8>> {
    pub fn new_vec() -> Self {
        Self::from_target(Vec::new())
    }
}


//--- Default

impl<Target: Default + OctetsBuilder> Default for AsPathBuilder<Target> {
    fn default() -> Self {
        Self::from_target(Target::default())
    }
}

//============ Error Types ===================================================

//------------ ParseAsnError ------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseAsnError;

impl fmt::Display for ParseAsnError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid AS number")
    }
}

impl error::Error for ParseAsnError {}


//------------ LongSegmentError ----------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct LongSegmentError;

impl fmt::Display for LongSegmentError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("path segment too long")
    }
}

impl error::Error for LongSegmentError { }

//------------ PrependError ----------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct PrependError;

impl fmt::Display for PrependError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("prepending invalid")
    }
}

impl error::Error for PrependError { }


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
    use serde_test::{Token, assert_de_tokens, assert_tokens};
    
    #[test]
    fn asn() {
        #[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
        struct AsnTest(
            Asn,

            #[serde(
                deserialize_with = "Asn::deserialize_from_u32",
                serialize_with = "Asn::serialize_as_u32",
            )]
            Asn,

            #[serde(
                deserialize_with = "Asn::deserialize_from_str",
                serialize_with = "Asn::serialize_as_str",
            )]
            Asn,
        );

        assert_tokens(
            &AsnTest ( Asn(0), Asn(0), Asn(0) ),
            &[
                Token::TupleStruct { name: "AsnTest", len: 3 },
                Token::NewtypeStruct { name: "Asn" }, Token::U32(0),
                Token::U32(0),
                Token::Str("AS0"),
                Token::TupleStructEnd,
            ]
        );
    }

    #[test]
    fn asn_any() {
        #[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
        struct AsnTest(
            #[serde(deserialize_with = "Asn::deserialize_from_any")]
            Asn,
            #[serde(deserialize_with = "Asn::deserialize_from_any")]
            Asn,
            #[serde(deserialize_with = "Asn::deserialize_from_any")]
            Asn,
            #[serde(deserialize_with = "Asn::deserialize_from_any")]
            Asn,
            #[serde(deserialize_with = "Asn::deserialize_from_any")]
            Asn,
            #[serde(deserialize_with = "Asn::deserialize_from_any")]
            Asn,
        );

        assert_de_tokens(
            &AsnTest(Asn(0), Asn(0), Asn(0), Asn(0), Asn(0), Asn(0)),
            &[
                Token::TupleStruct { name: "AsnTest", len: 5 },
                Token::U32(0),
                Token::U64(0),
                Token::I64(0),
                Token::Str("0"),
                Token::Str("AS0"),
                Token::Str("As0"),
                Token::TupleStructEnd,
            ]
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asn() {
        assert_eq!(Asn::from_u32(1234), Asn(1234));
        assert_eq!(Asn(1234).into_u32(), 1234);

        assert_eq!(Asn::from(1234_u32), Asn(1234));
        assert_eq!(u32::from(Asn(1234)), 1234_u32);

        assert_eq!(format!("{}", Asn(1234)).as_str(), "AS1234");

        assert_eq!("0".parse::<Asn>(), Ok(Asn(0)));
        assert_eq!("AS1234".parse::<Asn>(), Ok(Asn(1234)));
        assert_eq!("as1234".parse::<Asn>(), Ok(Asn(1234)));
        assert_eq!("As1234".parse::<Asn>(), Ok(Asn(1234)));
        assert_eq!("aS1234".parse::<Asn>(), Ok(Asn(1234)));
        assert_eq!("1234".parse::<Asn>(), Ok(Asn(1234)));

        assert_eq!("".parse::<Asn>(), Err(ParseAsnError));
        assert_eq!("-1234".parse::<Asn>(), Err(ParseAsnError));
        assert_eq!("4294967296".parse::<Asn>(), Err(ParseAsnError));
    }

    #[test]
    fn path_segment() {
        assert!(SegmentType::try_from(1_u8).is_ok());
        assert_eq!(
            SegmentType::try_from(1_u8).unwrap(),
            SegmentType::Set
        );
        assert_eq!(
            SegmentType::try_from(2_u8).unwrap(),
            SegmentType::Sequence
        );
        assert_eq!(
            SegmentType::try_from(3_u8).unwrap(),
            SegmentType::ConfedSequence
        );
        assert_eq!(
            SegmentType::try_from(4_u8).unwrap(),
            SegmentType::ConfedSet
        );
        for i in 5_u8..=255 {
            assert!(SegmentType::try_from(i).is_err());
        }

        assert_eq!(u8::from(SegmentType::Set), 1);
        assert_eq!(u8::from(SegmentType::Sequence), 2);
        assert_eq!(u8::from(SegmentType::ConfedSequence), 3);
        assert_eq!(u8::from(SegmentType::ConfedSet), 4);

        assert_eq!(
            format!("{}", SegmentType::Set).as_str(),
            "AS_SET"
        );
        assert_eq!(
            format!("{}", SegmentType::Sequence).as_str(),
            "AS_SEQUENCE"
        );
        assert_eq!(
            format!("{}", SegmentType::ConfedSequence).as_str(),
            "AS_CONFED_SEQUENCE"
        );
        assert_eq!(
            format!("{}", SegmentType::ConfedSet).as_str(),
            "AS_CONFED_SET"
        );
    }

    #[test]
    fn as_path_builder() {
        let default_pb = AsPathBuilder::default();
        let mut pb = AsPathBuilder::new_vec();
        assert_eq!(default_pb, pb);

        //pb.append_segment(
        //    OwnedPathSegment::confed_set_from([])
        //);

        pb.append(Asn(1234));

        pb.append_as_sequence(&[Asn(2000), Asn(3000)]);

        pb.append_as_sequence(&[Asn(4000), Asn(5000), Asn(6000)]);
        
        assert_eq!(pb.path_len(), 6);

        let asp = pb.finalize().unwrap();

        let mut seg_iter = asp.iter();
        assert_eq!(
            seg_iter.next().unwrap().segment_type(),
            SegmentType::Sequence,
        );

        let ps = asp.iter().collect::<Vec<PathSegment<'_, _>>>();

        assert_eq!(ps.len(), 1);
        assert!(ps[0].elements().eq([
                Asn(1234),
                Asn(2000), Asn(3000),
                Asn(4000), Asn(5000), Asn(6000)
        ]));

        assert_eq!(
            format!("{}", ps[0]).as_str(),
            "AS_SEQUENCE(AS1234, AS2000, AS3000, AS4000, AS5000, AS6000)"
        );

        assert_eq!(
            format!("{}", asp).as_str(),
            "AS_SEQUENCE(AS1234, AS2000, AS3000, AS4000, AS5000, AS6000)"
        );

    }

    #[test]
    fn max_size_segments_append() {
        let mut pb = AsPathBuilder::new_vec();
        assert_eq!(pb.segments.len(), 0);
        pb.append_as_sequence(&[Asn(1234); 255]);
        assert_eq!(pb.segments.len(), 1);
        pb.append_as_sequence(&[Asn(1235)]);

        pb.append_as_set(&[Asn(2345); 255]).unwrap();

        let asp = pb.finalize().unwrap();

        let mut segment_cnt = 0;
        let mut as_cnt = 0;
        for ps in asp.into_iter() {
            segment_cnt += 1;
            for _asn in ps.elements() {
                as_cnt += 1;
            }
        }
        
        assert_eq!(segment_cnt, 3);
        assert_eq!(as_cnt, 255 + 255 + 1);

        // Appending the second Sequence should shift the existing ASNs to the
        // right, resulting in the right most segment begin full, filled with
        // all but one of its original ASNs (1234), and the just-appended
        // AS1235. The new Sequence contains a single ASN, being one AS1234
        // coming from the original segment.

        let mut segs = asp.iter();
        let seg1 = segs.next().unwrap();
        assert_eq!(seg1.segment_type(), SegmentType::Sequence);
        assert_eq!(seg1.len(), 1);
        assert!(seg1.elements().eq([Asn(1234)]));

        let seg2 = segs.next().unwrap();
        assert_eq!(seg2.segment_type(), SegmentType::Sequence);
        assert_eq!(seg2.len(), 255);
        let elems2: Vec<_> = seg2.elements().collect();
        assert_eq!(elems2[0], Asn(1234));
        assert_eq!(elems2[254], Asn(1235));

        let seg3 = segs.next().unwrap();
        assert_eq!(seg3.segment_type(), SegmentType::Set);
        assert_eq!(seg3.len(), 255);
    }

    #[test]
    fn max_size_segments_prepend() {
        let mut pb = AsPathBuilder::new_vec();
        assert_eq!(pb.segments.len(), 0);
        pb.prepend_as_sequence(&[Asn(1234); 255]);
        assert_eq!(pb.segments.len(), 1);
        pb.prepend_as_sequence(&[Asn(1235)]);

        pb.prepend_as_set(&[Asn(2345); 255]).unwrap();

        let asp = pb.finalize().unwrap();

        let mut segment_cnt = 0;
        let mut as_cnt = 0;
        for ps in asp.into_iter() {
            segment_cnt += 1;
            for _asn in ps.elements() {
                as_cnt += 1;
            }
        }
        
        assert_eq!(segment_cnt, 3);
        assert_eq!(as_cnt, 255 + 255 + 1);

        // Appending the second Sequence should shift the existing ASNs to the
        // right, resulting in the right most segment begin full, filled with
        // all but one of its original ASNs (1234), and the just-appended
        // AS1235. The new Sequence contains a single ASN, being one AS1234
        // coming from the original segment.

        let mut segs = asp.iter();
        let seg1 = segs.next().unwrap();
        assert_eq!(seg1.segment_type(), SegmentType::Set);
        assert_eq!(seg1.len(), 255);

        let seg2 = segs.next().unwrap();
        assert_eq!(seg2.segment_type(), SegmentType::Sequence);
        assert_eq!(seg2.len(), 1);
        assert!(seg2.elements().eq([Asn(1235)]));

        let seg3 = segs.next().unwrap();
        assert_eq!(seg3.segment_type(), SegmentType::Sequence);
        assert_eq!(seg3.len(), 255);
        //let elems3: Vec<_> = seg3.elements().collect();
        assert!(seg3.elements().eq([Asn(1234); 255]));
    }

    #[test]
    fn max_size_prepend_append() {
        let mut pb = AsPathBuilder::new_vec();
        pb.append_as_sequence(&[Asn(200); 255]);
        pb.append_as_sequence(&[Asn(300); 3]);
        pb.prepend_as_sequence(&[Asn(100); 3]);
        assert_eq!(pb.segments.len(), 2);

        let asp = pb.finalize().unwrap();
        let mut segs = asp.iter();

        let seg1 = segs.next().unwrap();
        assert_eq!(seg1.segment_type(), SegmentType::Sequence);
        assert!(seg1.elements().eq(
                [Asn(100), Asn(100), Asn(100), Asn(200), Asn(200), Asn(200)]
        ));

        let seg2 = segs.next().unwrap();
        let elems2: Vec<_> = seg2.elements().collect();
        assert_eq!(elems2[0], Asn(200));
        assert_eq!(elems2[254], Asn(300));

        assert!(segs.next().is_none());

    }

    #[test]
    fn aspath_octets() {
        // AS path comprised of a single segment:
        // AS_SEQUENCE(AS2027, AS35280, AS263903, AS271373)
        let raw = vec![
            0x02, 0x04, 0x00, 0x00, 0x07, 0xeb, 0x00, 0x00,
            0x89, 0xd0, 0x00, 0x04, 0x06, 0xdf, 0x00, 0x04,
            0x24, 0x0d
        ];

        let asp = AsPath{ octets: &raw };

        assert_eq!(
            format!("{}", asp).as_str(),
            "AS_SEQUENCE(AS2027, AS35280, AS263903, AS271373)"
        );

        assert!(asp.contains(Asn::from(2027)));
        assert!(asp.contains(Asn::from(35280)));
        assert!(asp.contains(Asn::from(263903)));
        assert!(asp.contains(Asn::from(271373)));
        assert!(!asp.contains(Asn::from(12345)));

    }

    #[test]
    fn aspath_octets_multiseg() {
        let raw = vec![
            0x02, 0x05, 0x00, 0x00,
            0x19, 0x2f, 0x00, 0x00, 0x97, 0xe0, 0x00, 0x00,
            0x23, 0x2a, 0x00, 0x00, 0x32, 0x9c, 0x00, 0x00,
            0x59, 0x8f, 0x01, 0x04, 0x00, 0x00, 0xcc, 0x8f,
            0x00, 0x04, 0x00, 0x1f, 0x00, 0x04, 0x0a, 0x6a,
            0x00, 0x04, 0x16, 0x0a
        ];

        let asp = AsPath{ octets: &raw };

        assert_eq!(
            format!("{asp}").as_str(), 
            "AS_SEQUENCE(AS6447, AS38880, AS9002, AS12956, AS22927), \
             AS_SET(AS52367, AS262175, AS264810, AS267786)"
        );

        assert!(asp.contains(Asn::from(52367)));
    }

    #[test]
    fn owned_path_segment() {
        let raw = vec![
            0x02, 0x05, 0x00, 0x00,
            0x19, 0x2f, 0x00, 0x00, 0x97, 0xe0, 0x00, 0x00,
            0x23, 0x2a, 0x00, 0x00, 0x32, 0x9c, 0x00, 0x00,
            0x59, 0x8f, 0x01, 0x04, 0x00, 0x00, 0xcc, 0x8f,
            0x00, 0x04, 0x00, 0x1f, 0x00, 0x04, 0x0a, 0x6a,
            0x00, 0x04, 0x16, 0x0a
        ];

        let asp = AsPath{ octets: &raw };
        let mut pb = asp.into_builder();

        pb.prepend(Asn::from_u32(12345));

        let asp2 = pb.finalize().unwrap();
        assert_eq!(format!("{}", asp2).as_str(),
            "AS_SEQUENCE(AS12345, AS6447, AS38880, AS9002, AS12956, AS22927), \
             AS_SET(AS52367, AS262175, AS264810, AS267786)"
        );
    }

    #[test]
    fn prepend() {
        let mut pb = AsPathBuilder::new_vec();
        pb.append_as_set(&[Asn(500), Asn(600)]).unwrap();
        pb.append_as_sequence(&[Asn(100), Asn(200)]);
        pb.prepend(Asn(12345));
        let asp = pb.finalize().unwrap();

        assert_eq!(format!("{}", asp).as_str(),
            "AS_SEQUENCE(AS12345), \
             AS_SET(AS500, AS600), \
             AS_SEQUENCE(AS100, AS200)"
        );
    }

    #[test]
    fn path_len() {
        //TODO
    }

    #[test]
    fn prepend_n() {
        let mut pb = AsPathBuilder::new_vec();
        pb.append_as_sequence(&[Asn(100), Asn(200)]);
        let asp = pb.finalize().unwrap();

        let new_asp = asp.prepend_n::<10>(Asn(1234)).unwrap();

        const N: u8 = 25;
        let new_asp2 = new_asp.prepend_n::<N>(Asn(9000)).unwrap();

        let new_asp3 = new_asp2.prepend_n::<3>(Asn(600)).unwrap();

        assert!(new_asp3.is_single_sequence());

        assert_eq!(new_asp3.path_len(), 2 + 10 + N as usize + 3);

        assert!(new_asp3.prepend_n::<250>(Asn(1)).is_err());

        let mut pb2 = AsPathBuilder::new_vec();
        pb2.append_as_set(&[Asn(100), Asn(200)]).unwrap();
        let asp2 = pb2.finalize().unwrap();
        assert!(asp2.prepend_n::<10>(Asn(1)).is_err());
        assert!(!asp2.is_single_sequence());
    }

    #[test]
    fn try_from_into_aspath() {
        let asp: Result<AsPath<_>, _> = (&[Asn(10), Asn(20)][..]).try_into();
        assert!(asp.is_ok());

        assert!(AsPath::try_from(&[Asn(2000); 300][..]).is_err());
    }

    #[test]
    fn owned_path_segment_index() {
        let mut ps = OwnedPathSegment2::sequence_from(
            &[Asn(100), Asn(200)]
        ).unwrap();
        assert_eq!(ps[0], Asn(100));
        assert_eq!(ps[1], Asn(200));
        ps[0] = Asn(9000);
        assert_eq!(ps[0], Asn(9000));
    }

    #[test]
    fn sequence_from_generic() {
        assert_eq!(
            OwnedPathSegment2::sequence_from([Asn(100), Asn(200)]).unwrap(),
            OwnedPathSegment2::sequence_from(&[Asn(100), Asn(200)]).unwrap()
        );
        let mut pb = AsPathBuilder::new_vec();
        pb.prepend_as_sequence(&[Asn(100)]);
        pb.prepend_as_sequence([Asn(100)]);
        pb.prepend_as_set([Asn(100)]).unwrap();
    }

}
