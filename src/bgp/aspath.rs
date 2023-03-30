//! AS Path generic over Octets
//!
//! Using Hop etc etc

use crate::asn::Asn;
use octseq::{
    EmptyBuilder, FromBuilder, Octets, OctetsBuilder, OctetsFrom, OctetsInto,
    Parser, ShortInput,
};
use std::{error, fmt};
use core::ops::{Index, IndexMut};
use std::slice::SliceIndex;


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SegmentType {
    Set,
    Sequence,
    ConfedSequence,
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

//--- Segment ----------------------------------------------------------------
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Segment<Octs> {
    stype: SegmentType,
    four_byte_asns: bool,
    octets: Octs,
}

impl<Octs> Segment<Octs> {
    fn new(stype: SegmentType, four_byte_asns: bool, octets: Octs) -> Self {
        Segment { stype, four_byte_asns, octets }
    }
}

impl Segment<Vec<u8>> {
    pub fn new_set(asns: impl IntoIterator<Item = Asn>) -> Self {
        let iter = asns.into_iter();
        let mut set = Vec::with_capacity(iter.size_hint().0);
        for a in iter.map(|a| a.to_raw()) {
            set.extend_from_slice(&a);
        }
        Segment::new(SegmentType::Set, true, set)
    }

    pub fn new_confed_set(asns: impl IntoIterator<Item = Asn>) -> Self {
        let iter = asns.into_iter();
        let mut set = Vec::with_capacity(iter.size_hint().0);
        for a in iter.map(|a| a.to_raw()) {
            set.extend_from_slice(&a);
        }
        Segment::new(SegmentType::ConfedSet, true, set)
    }

    pub fn new_confed_sequence(asns: impl IntoIterator<Item = Asn>) -> Self {
        let iter = asns.into_iter();
        let mut seq = Vec::with_capacity(iter.size_hint().0);
        for a in iter.map(|a| a.to_raw()) {
            seq.extend_from_slice(&a);
        }
        Segment::new(SegmentType::ConfedSequence, true, seq)
    }
}

impl<Octs: AsRef<[u8]>> Segment<Octs> {
    pub fn asns(&self) -> Asns<Octs> {
        Asns::new(Parser::from_ref(&self.octets), self.four_byte_asns)
    }

    pub fn asn_count(&self) -> u8 {
        u8::try_from(
            self.octets.as_ref().len() / asn_size(self.four_byte_asns)
        ).expect("long AS path segment")
    }

    /// Append the wire-format of the segment to the target.
    ///
    /// This method will always produce four-byte ASNs.
    pub fn compose<Target: OctetsBuilder>(
        &self, target: &mut Target,
    ) -> Result<(), Target::AppendError>
    where Octs: Octets {
        target.append_slice(
            &[
                self.stype.into(),
                self.asn_count(),
            ]
        )?;
        if self.four_byte_asns {
            target.append_slice(self.octets.as_ref())?;
        }
        else {
            self.asns().try_for_each(|asn| asn.compose(target))?;
        }
        Ok(())
    }
}

impl<Source, Octs> OctetsFrom<Segment<Source>> for Segment<Octs>
    where
    Octs: OctetsFrom<Source>
{
    type Error = Octs::Error;

    fn try_octets_from(source: Segment<Source>) -> Result<Self, Self::Error> {
        Ok(Segment::new(
            source.stype,
            source.four_byte_asns,
            Octs::try_octets_from(source.octets)?
        ))
    }
}

impl<Octs: Octets> fmt::Display for Segment<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}(", self.stype)?;

        let mut asns = self.into_iter();
        if let Some(first) = asns.next() {
            write!(f, "{}", first)?;
            for elem in asns {
                write!(f, ", {}", elem)?;
            }
        }
        write!(f, ")")
    }
}

impl<'a, Octs: 'a + Octets> IntoIterator for &'a Segment<Octs> {
    type Item = Asn;
    type IntoIter = Asns<'a, Octs>;
    fn into_iter(self) -> Self::IntoIter {
        self.asns()
    }
}



//--- Hop --------------------------------------------------------------------
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Hop<Octs> {
    Asn(Asn),
    Segment(Segment<Octs>),
}

impl<Octs> Hop<Octs> {
    pub fn try_into_asn(self) -> Result<Asn, <Self as TryInto<Asn>>::Error> {
        TryInto::<Asn>::try_into(self)
    }
}
impl<Octs> From<Asn> for Hop<Octs> {
    fn from(a: Asn) -> Self {
        Hop::Asn(a)
    }
}

impl<Octs> TryFrom<Hop<Octs>> for Asn {
    type Error = InvalidSegmentTypeError;
    fn try_from(hop: Hop<Octs>) -> Result<Asn, Self::Error> {
        match hop {
            Hop::Asn(asn) => Ok(asn),
            _ => Err(InvalidSegmentTypeError)
        }
    }
}

impl<Octs> From<Segment<Octs>> for Hop<Octs> {
    fn from(seg: Segment<Octs>) -> Self {
        Hop::Segment(seg)
    }
}

impl<Source, Octs> OctetsFrom<Hop<Source>> for Hop<Octs>
    where
    Octs: OctetsFrom<Source>
{
    type Error = Octs::Error;

    fn try_octets_from(source: Hop<Source>) -> Result<Self, Self::Error> {
        match source {
            Hop::Asn(asn) => Ok(Hop::Asn(asn)),
            Hop::Segment(seg) => Ok(Hop::Segment(Segment::try_octets_from(seg)?))
        }
    }
}


impl<Octs: Octets> fmt::Display for Hop<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Hop::Asn(a) => fmt::Display::fmt(a, f),
            Hop::Segment(s) => fmt::Display::fmt(s, f)
        }
    }
}


//--- AsPath -----------------------------------------------------------------

#[derive(Debug)]
pub struct AsPath<Octs> {
    /// The octets of the AS_PATH attribute.
    octets: Octs,

    /// Does `octets` contain four byte ASNs?
    four_byte_asns: bool,
}

impl<Octs: AsRef<[u8]>> AsPath<Octs> {
    pub fn new(
        octets: Octs,
        four_byte_asns: bool,
    ) -> Result<Self, ShortInput> {
        AsPath::check(octets.as_ref(), four_byte_asns)?;
        Ok(unsafe {
            Self::new_unchecked(octets, four_byte_asns)
        })
    }

    /// Create an AsPath from `octets` without performing validity checks. 
    ///
    /// # Safety
    /// 
    /// This assumes the caller has verified the `octets` passed in validly
    /// represent an AS Path. Calling methods on the resulting `AsPath` will
    /// panic if that is not the case.
    pub unsafe fn new_unchecked(
        octets: Octs,
        four_byte_asns: bool,
    ) -> Self {
        AsPath { octets, four_byte_asns }
    }
}

impl AsPath<()> {
    pub fn check(
        octets: &[u8], four_byte_asns: bool
    ) -> Result<(), ShortInput> {
        let mut parser = Parser::from_ref(octets);
        while parser.remaining() > 0 {
            // XXX Should this error on an unknown segment type?
            parser.advance(1)?; // segment type
            let len = usize::from(parser.parse_u8()?); // segment length
            parser.advance(len * asn_size(four_byte_asns))?; // ASNs.
        }
        Ok(())
    }
}


impl<Octs: Octets> AsPath<Octs> {
    pub fn hops(&self) -> PathHops<Octs> {
        PathHops::new(&self.octets, self.four_byte_asns)
    }
    
    pub fn segments(&self) -> PathSegments<Octs> {
        PathSegments::new(&self.octets, self.four_byte_asns)
    }

    pub fn origin(&self) -> Option<Hop<Octs::Range<'_>>> {
        self.hops().last()
    }

    pub fn prepend(
        &self, asn: Asn, n: usize
    ) -> Result<
        AsPath<Octs>,
        <<Octs as FromBuilder>::Builder as OctetsBuilder>::AppendError
    >
    where
        Octs: FromBuilder,
        <Octs as FromBuilder>::Builder: EmptyBuilder,
        for<'a> Vec<u8>: From<Octs::Range<'a>>
    {
        let mut hops = self.to_hop_path();
        hops.prepend_n(asn, n);
        hops.to_as_path()
    }

    pub fn prepend_arr<const N: usize>(
        &self,
        arr: [Asn; N]
    ) -> Result<
        AsPath<Octs>,
        <<Octs as FromBuilder>::Builder as OctetsBuilder>::AppendError
    >
    where
    Octs: FromBuilder,
    <Octs as FromBuilder>::Builder: EmptyBuilder,
    for<'a> Vec<u8>: From<Octs::Range<'a>>
    {
        let mut hops = self.to_hop_path();
        hops.prepend_arr(arr);
        hops.to_as_path()
    }

    pub fn to_hop_path(&self) -> HopPath
    where for<'a> Vec<u8>: From<Octs::Range<'a>> {
        HopPath { hops: self.hops().map(OctetsInto::octets_into).collect() }
    }

}

impl<Octs: Octets> fmt::Display for AsPath<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut first = true;
        for s in self.segments() {
            if first {
                write!(f, "{}", s)?;
                first = false;
            } else {
                write!(f, ", {}", s)?;
            }
        }
        Ok(())
    }
}

//----------- PathHops -------------------------------------------------------

/// Iterators over `Hop`s in a Path.
pub struct PathHops<'a, Octs> {
    segments: PathSegments<'a, Octs>,
    current: Option<Asns<'a, Octs>>,
}

impl<'a, Octs: AsRef<[u8]>> PathHops<'a, Octs> {
    fn new(octets: &'a Octs, four_byte_asns: bool) -> Self {
        PathHops {
            segments: PathSegments::new(octets, four_byte_asns),
            current: None,
        }
    }
}

impl<'a, Octs: Octets> Iterator for PathHops<'a, Octs> {
    type Item = Hop<Octs::Range<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(sequence) = &mut self.current {
            if let Some(asn) = sequence.next() {
                return Some(Hop::Asn(asn))
            }
            self.current = None
        }
        if let Some((stype, mut asns)) = self.segments.next_asns() {
            if stype == SegmentType::Sequence {
                if let Some(asn) = asns.next() {
                    self.current = Some(asns);
                    Some(Hop::Asn(asn))
                }
                else {
                    // For consistency with the other segment types, we do
                    // return an empty Sequence if encountered, even though
                    // such a thing is meaningless in an AS_PATH.
                    Some(Hop::Segment(asns.into_segment(stype)))
                }
            }
            else {
                Some(Hop::Segment(asns.into_segment(stype)))
            }
        }
        else {
            None
        }
    }
}

//--- PathSegments --------------------------------------------------------
/// Iterates over Segments in a Path.
pub struct PathSegments<'a, Octs> {
    parser: Parser<'a, Octs>,
    four_byte_asns: bool,
}

impl<'a, Octs: AsRef<[u8]>> PathSegments<'a, Octs> {
    fn new(octets: &'a Octs, four_byte_asns: bool) -> Self {
        Self { parser: Parser::from_ref(octets), four_byte_asns }
    }
}

impl<'a, Octs: Octets> PathSegments<'a, Octs> {
    fn next_asns(&mut self) -> Option<(SegmentType, Asns<'a, Octs>)> {
        if self.parser.remaining() == 0 {
            return None;
        }
        let stype = self.parser.parse_u8().expect("parsed before")
            .try_into().expect("illegally encoded AS path");
        let len = usize::from(
            self.parser.parse_u8().expect("parsed before")
        ) * asn_size(self.four_byte_asns);
        let parser = self.parser.parse_parser(len).expect("parsed before");
        Some((stype, Asns::new(parser, self.four_byte_asns)))
    }
}

impl<'a, Octs: Octets> Iterator for PathSegments<'a, Octs> {
    type Item = Segment<Octs::Range<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        self.next_asns().map(|(stype, asns)| asns.into_segment(stype))
    }
}


//------------ Asns ----------------------------------------------------------

/// Iterates over ASNs in a Segment.
pub struct Asns<'a, Octs> {
    parser: Parser<'a, Octs>,
    four_byte_asns: bool,
}
impl<'a, Octs> Asns<'a, Octs> {
    fn new(parser: Parser<'a, Octs>, four_byte_asns: bool) -> Self {
        Asns { parser, four_byte_asns }
    }

    pub fn into_segment(
        mut self, stype: SegmentType
    ) -> Segment<Octs::Range<'a>>
    where Octs: Octets {
        Segment::new(
            stype, self.four_byte_asns,
            self.parser.parse_octets(
                self.parser.remaining()
            ).expect("parsed before")
        )
    }
}

impl<'a, Octs: Octets> Iterator for Asns<'a, Octs> {
    type Item = Asn;
    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None
        }
        let n = if self.four_byte_asns {
            self.parser.parse_u32().expect("parsed before")
        }
        else {
            u32::from(self.parser.parse_u16().expect("parsed before"))
        };
        Some(Asn::from(n))
    }
}


//--- Building / composing ---------------------------------------------------


#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HopPath {
    hops: Vec<Hop<Vec<u8>>>,
}

impl HopPath {
    pub fn new() -> Self {
        Self { hops: vec![] }
    }

    pub fn origin(&self) -> Option<&Hop<Vec<u8>>> {
        self.hops.last()
    }

    pub fn contains(&self, hop: &Hop<Vec<u8>>) -> bool {
        self.hops.iter().any(|h| h == hop)
    }

    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Hop<Vec<u8>>> {
        self.hops[..].iter()
    }

    pub fn prepend(&mut self, hop: impl Into<Hop<Vec<u8>>>) {
        self.hops.insert(0, hop.into());
    }

    pub fn prepend_n(&mut self, asn: Asn, n: usize) {
        for _ in 0..n {
            self.prepend(asn)
        }
    }

    pub fn prepend_arr<const N: usize>(
        &mut self,
        arr: [Asn; N]
    ) {
        let mut new = Vec::with_capacity(N + self.hops.len());

        new.extend_from_slice(&arr.map(Hop::Asn));
        new.extend_from_slice(&self.hops);

        self.hops = new;
    }


    pub fn prepend_set(&mut self, set: impl IntoIterator<Item = Asn>) {
        self.prepend(Hop::Segment(Segment::new_set(set)))
    }

    pub fn prepend_confed_sequence(
        &mut self, seq: impl IntoIterator<Item = Asn>)
    {
        self.prepend(Hop::Segment(Segment::new_confed_sequence(seq)))
    }

    pub fn prepend_confed_set(
        &mut self, set: impl IntoIterator<Item = Asn>)
    {
        self.prepend(Hop::Segment(Segment::new_confed_set(set)))
    }

    pub fn append(&mut self, hop: Hop<Vec<u8>>) {
        self.hops.push(hop);
    }

    pub fn append_asn(&mut self, asn: Asn) {
        self.hops.push(Hop::Asn(asn))
    }

    pub fn append_set(&mut self, set: impl IntoIterator<Item = Asn>) {
        self.append(Hop::Segment(Segment::new_set(set)))
    }

    pub fn append_confed_sequence(
        &mut self, seq: impl IntoIterator<Item = Asn>)
    {
        self.append(Hop::Segment(Segment::new_confed_sequence(seq)))
    }

    pub fn append_confed_set(
        &mut self, set: impl IntoIterator<Item = Asn>)
    {
        self.append(Hop::Segment(Segment::new_confed_set(set)))
    }

    pub fn to_as_path<Octs>(
        &self
    ) -> Result<
        AsPath<Octs>,
        <<Octs as FromBuilder>::Builder as OctetsBuilder>::AppendError
    >
    where
        Octs: FromBuilder,
        <Octs as FromBuilder>::Builder: EmptyBuilder
    {
        let mut target = EmptyBuilder::empty();
        Self::compose_hops(&self.hops, &mut target)?;
        Ok(unsafe {
            AsPath::new_unchecked(Octs::from_builder(target), true)
        })
    }

    fn compose_hops<Octs: Octets, Target: OctetsBuilder>(
        mut hops: &[Hop<Octs>], target: &mut Target
    ) -> Result<(), Target::AppendError> {
        while !hops.is_empty() {
            let i = hops.iter().position(|h| !matches!(h, Hop::Asn(_))).unwrap_or(hops.len());
            let (head, tail) = hops.split_at(i);

            if !head.is_empty() {
                // hops[0..idx] represents |idx| ASNs in a Sequence
                let (head, tail) = head.split_at(head.len() % 256);
                target.append_slice(
                    &[
                        SegmentType::Sequence.into(),
                        u8::try_from(head.len()).expect("long sequence")
                    ]
                )?;
                head.iter().try_for_each(|h| {
                    match h {
                        Hop::Asn(asn) => asn.compose(target),
                        _ => unreachable!()
                    }
                })?;

                for c in tail.chunks(255) {
                    target.append_slice(
                        &[
                            SegmentType::Sequence.into(),
                            u8::try_from(c.len()).expect("long sequence")
                        ]
                    )?;
                    c.iter().try_for_each(|h| {
                        match h {
                            Hop::Asn(asn) => asn.compose(target),
                            _ => unreachable!()
                        }
                    })?;

                }
            }
            if let Some((first, tail)) = tail.split_first() {
                match first {
                    Hop::Asn(_) => unreachable!(),
                    Hop::Segment(seg) => seg.compose(target)?
                }
                hops = tail;
            }
            else {
                hops = tail;
            }
        }
        Ok(())
    }
}

impl IntoIterator for HopPath {
    type Item = Hop<Vec<u8>>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.hops.into_iter()
    }
}

impl<I: SliceIndex<[Hop<Vec<u8>>]>> Index<I> for HopPath {
    type Output = I::Output;
    fn index(&self, i: I) -> &Self::Output {
        &self.hops[i]
    }
}

impl<I: SliceIndex<[Hop<Vec<u8>>]>> IndexMut<I> for HopPath {
    fn index_mut(&mut self, i: I) -> &mut Self::Output {
        &mut self.hops[i]
    }
}

/*
impl<T> From<T> for HopPath where T: IntoIterator<Item = Asn> {
    fn from(asns: T) -> HopPath {
        HopPath { hops: asns.into_iter().map(Hop::Asn).collect() }  
    }
}
*/

impl From<Vec<Hop<Vec<u8>>>> for HopPath {
    fn from(hops: Vec<Hop<Vec<u8>>>) -> HopPath {
        HopPath { hops }
    }
}

impl From<Vec<Asn>> for HopPath {
    fn from(asns: Vec<Asn>) -> HopPath {
        HopPath { hops: asns.into_iter().map(Hop::Asn).collect() }  
    }
}

impl From<&[Asn]> for HopPath {
    fn from(asns: &[Asn]) -> HopPath {
        HopPath { hops: asns.iter().map(|&a| Hop::Asn(a)).collect() }  
    }
}

impl<const N: usize> From<[Asn; N]> for HopPath {
    fn from(asns: [Asn; N]) -> HopPath {
        HopPath { hops: asns.into_iter().map(Hop::Asn).collect() }  
    }
}

impl fmt::Display for HopPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut first = true;
        for s in &self.hops {
            if first {
                write!(f, "{}", s)?;
                first = false;
            } else {
                write!(f, " {}", s)?;
            }
        }
        Ok(())
    }
}

//------------ Helper Functions ----------------------------------------------

fn asn_size(four_byte_asns: bool) -> usize {
    if four_byte_asns {
        4
    }
    else {
        2
    }
}

//============ Error Types ===================================================

//------------ InvalidSegmentTypeError ---------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidSegmentTypeError;

impl fmt::Display for InvalidSegmentTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid segment type")
    }
}

impl error::Error for InvalidSegmentTypeError { }



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_iter() {
        // AS path comprised of a single segment:
        // AS_SEQUENCE(AS2027, AS35280, AS263903, AS271373)
        let raw = vec![
            0x02, 0x04, 0x00, 0x00, 0x07, 0xeb, 0x00, 0x00,
            0x89, 0xd0, 0x00, 0x04, 0x06, 0xdf, 0x00, 0x04,
            0x24, 0x0d
        ];

        let path = AsPath::new(&raw, true).unwrap();
        assert_eq!(
            path.to_string(),
            "AS_SEQUENCE(AS2027, AS35280, AS263903, AS271373)"
        );
    }

    #[test]
    fn path_iter_with_set() {
        //AS_SEQUENCE(AS6447, AS38880, AS9002, AS12956, AS22927), 
        //  AS_SET(AS52367, AS262175, AS264810, AS267786)
        let raw = vec![
            0x02, 0x05, 0x00, 0x00,
            0x19, 0x2f, 0x00, 0x00, 0x97, 0xe0, 0x00, 0x00,
            0x23, 0x2a, 0x00, 0x00, 0x32, 0x9c, 0x00, 0x00,
            0x59, 0x8f, 0x01, 0x04, 0x00, 0x00, 0xcc, 0x8f,
            0x00, 0x04, 0x00, 0x1f, 0x00, 0x04, 0x0a, 0x6a,
            0x00, 0x04, 0x16, 0x0a
        ];

        let path = AsPath::new(&raw, true).unwrap();
        assert_eq!(
            path.to_string(),
            "AS_SEQUENCE(AS6447, AS38880, AS9002, AS12956, AS22927), \
             AS_SET(AS52367, AS262175, AS264810, AS267786)"
        );
    }

    #[test]
    fn prepend() {
        let mut hp = HopPath::new();
        hp.prepend(Asn::from_u32(100));
        hp.prepend_n(Asn::from_u32(200), 3);
        hp.prepend(Segment::new_set([Asn::from_u32(98), Asn::from_u32(99)]));
        hp.prepend_arr([Asn::from_u32(300), Asn::from_u32(400)]);

        let asp = hp.to_as_path::<Vec<u8>>().unwrap();

        assert_eq!(
            asp.to_string(),
            "AS_SEQUENCE(AS300, AS400), AS_SET(AS98, AS99), \
             AS_SEQUENCE(AS200, AS200, AS200, AS100)"
        );
    }

    #[test]
    fn new_segments() {
        let set = Segment::new_set([Asn::from_u32(100), Asn::from_u32(200)]);
        let confed_set = Segment::new_confed_set(
            [Asn::from_u32(300), Asn::from_u32(400)]
        );
        let confed_sequence = Segment::new_confed_sequence(
            [Asn::from_u32(500), Asn::from_u32(600)]
        );
        
        let mut hp = HopPath::new();
        hp.prepend(set);
        hp.prepend(confed_set);
        hp.prepend(confed_sequence);
        let asp = hp.to_as_path::<Vec<u8>>().unwrap();
        assert_eq!(
            asp.to_string(),
            "AS_CONFED_SEQUENCE(AS500, AS600), AS_CONFED_SET(AS300, AS400), \
             AS_SET(AS100, AS200)"
        );
    }

    #[test]
    fn origin() {
        let mut hp = HopPath::new();
        hp.prepend(Asn::from_u32(1234));
        hp.prepend(Asn::from_u32(1235));
        assert_eq!(hp.origin(), Some(&Hop::Asn(Asn::from_u32(1234))));

        let asp: AsPath<Vec<u8>> = hp.to_as_path().unwrap();
        assert_eq!(asp.origin(), Some(Hop::Asn(Asn::from_u32(1234))));
    }

    #[test]
    fn contains() {
        let mut hp = HopPath::new();
        hp.prepend_arr([Asn::from_u32(10), Asn::from_u32(20)]);
        assert!(hp.contains(&Hop::Asn(Asn::from_u32(10))));
        assert!(!hp.contains(&Hop::Asn(Asn::from_u32(30))));
    }

    #[test]
    fn froms_and_intos()  {
        let asns = vec![Asn::from_u32(100), Asn::from_u32(200)];

        let hp: HopPath = (&asns[..]).into();
        assert_eq!(
            hp.to_as_path::<Vec<u8>>().unwrap().to_string(),
            "AS_SEQUENCE(AS100, AS200)"
        );

        let hp: HopPath = asns.into();
        assert_eq!(
            hp.to_as_path::<Vec<u8>>().unwrap().to_string(),
            "AS_SEQUENCE(AS100, AS200)"
        );

        let hp: HopPath = [Asn::from_u32(100), Asn::from_u32(200)].into();
        assert_eq!(
            hp.to_as_path::<Vec<u8>>().unwrap().to_string(),
            "AS_SEQUENCE(AS100, AS200)"
        );

        assert_eq!(
                Hop::<Vec<u8>>::Asn(Asn::from_u32(1234)).try_into(),
                Ok(Asn::from_u32(1234))
        );

        assert_eq!(
                Hop::<Vec<u8>>::Asn(Asn::from_u32(1234)).try_into(),
                Hop::<Vec<u8>>::Asn(Asn::from_u32(1234)).try_into_asn()
        );

        let hop: Hop<Vec<u8>> = Segment::new_set([Asn::from_u32(10)]).into();
        assert!(TryInto::<Asn>::try_into(hop.clone()).is_err());
        assert!(hop.try_into_asn().is_err());
    }

    #[test]
    fn hop_path_iter() {
        let mut hp = HopPath::new();
        hp.prepend_arr([Asn::from_u32(10), Asn::from_u32(20)]);
        assert!(hp.iter().eq(
                &[Hop::Asn(Asn::from_u32(10)), Hop::Asn(Asn::from_u32(20))]
        ));
    }


    #[test]
    fn empty_segments() {
        let raw = vec![
            0x01, 0x01, 0x00, 0x00, 0x00, 0x64, // SET(AS100)
            0x01, 0x00,                         // SET()
            0x02, 0x00,                         // SEQUENCE()
            0x01, 0x01, 0x00, 0x00, 0x00, 0x65  // SET(AS101)

        ];
        let asp = AsPath::new(&raw, true).unwrap();
        assert_eq!(
            asp.to_string(),
            "AS_SET(AS100), AS_SET(), AS_SEQUENCE(), AS_SET(AS101)"
            );
        assert_eq!(asp.hops().count(), 4);
    }

    #[test]
    fn two_octet_paths() {
        let raw = vec![
            0x01, 0x01, 0x00, 0x64, // SET(AS100)
            0x02, 0x02, 0x00, 0x66, 0x00, 0x65  // SET(AS102, AS101)

        ];
        let asp = AsPath::new(&raw, false).unwrap();
        assert_eq!(
            asp.to_string(),
            "AS_SET(AS100), AS_SEQUENCE(AS102, AS101)"
        );
        
    }

}