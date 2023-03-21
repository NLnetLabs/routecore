//! AS Path generic over Octets
//!
//! Using Hop etc etc

use crate::asn::Asn;
use octseq::{
    EmptyBuilder, FromBuilder, Octets, OctetsBuilder, OctetsFrom, OctetsInto,
    Parser,
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

//--- Segment ----------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment<Octs> {
    stype: SegmentType,
    octets: Octs,
}

impl Segment<Vec<u8>> {
    pub fn new_set(asns: impl IntoIterator<Item = Asn>) -> Self {
        let mut set = vec![SegmentType::Set.into(), 0u8];
        let mut len = 0u8;
        for a in asns.into_iter().map(|a| a.to_raw()) {
            set.extend_from_slice(&a);
            len += 1;
        }
        set[1] = len;

        Segment {
            stype: SegmentType::Set,
            octets: set
        }
    }
}

impl<Octs: Octets> Segment<Octs> {
    pub fn asns(&self) -> Asns<Octs> {
        Asns::new(&self.octets)
    }

    pub fn compose<Target: OctetsBuilder>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        target.append_slice(
            &[self.stype.into(), 
            u8::try_from((self.octets.as_ref().len() - 2) / 4)
                .expect("long sequence")
            ]
        )?;
        for c in self.octets.as_ref()[2..].chunks(4) {
            target.append_slice(c)?
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
        Ok(Segment {
            stype: source.stype, 
            octets: Octs::try_octets_from(source.octets)?
        })
    }
}

impl<Octs: Octets> std::fmt::Display for Segment<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let _ = match self.stype {
            SegmentType::Sequence => write!(f, "AS_SEQUENCE("),
            SegmentType::Set => write!(f, "AS_SET("),
            SegmentType::ConfedSet => write!(f, "AS_CONFED_SET("),
            SegmentType::ConfedSequence => write!(f, "AS_CONFED_SEQUENCE("),
        };
        let mut first = true;
        for a in self.asns() {
            if first {
                let _ = write!(f, "{}", a);
                first = false;
            } else {
                let _ = write!(f, ", {}", a);
            }
        }
        write!(f, ")")
    }
}



//--- Hop --------------------------------------------------------------------
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Hop<Octs> {
    Asn(Asn),
    Segment(Segment<Octs>),
}

impl Hop<Vec<u8>> {
    pub fn try_into_asn(self) -> Result<Asn, InvalidSegmentTypeError> {
        todo!()
    }
}

impl<Octs> From<Asn> for Hop<Octs> {
    fn from(a: Asn) -> Self {
        Hop::Asn(a)
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

impl fmt::Display for Hop<Vec<u8>> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}


//--- AsPath -----------------------------------------------------------------
#[derive(Debug)]
pub struct AsPath<Octs> {
    octets: Octs,
}

impl<Octs> AsPath<Octs> {
    pub unsafe fn from_octets_unchecked(octets: Octs) -> Self {
        AsPath { octets }
    }
}

impl<Octs: Octets> AsPath<Octs> {
    pub fn hops(&self) -> PathHops<Octs> {
        PathHops::new(&self.octets)
    }
    
    pub fn segments(&self) -> PathSegments<Octs> {
        PathSegments::new(&self.octets)
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

impl<Octs: Octets> std::fmt::Display for AsPath<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut first = true;
        let _ = write!(f, "[");
        for s in self.segments() {
            if first {
                let _ = write!(f, "{}", s);
                first = false;
            } else {
                let _ = write!(f, ", {}", s);
            }
        }
        write!(f, "]")
    }
}

//----------- PathHops -------------------------------------------------------

/// Iterators over `Hop`s in a Path.
pub struct PathHops<'a, Octs> {
    segments: PathSegments<'a, Octs>,
    current: Option<Asns<'a, Octs>>,
}

impl<'a, Octs: AsRef<[u8]>> PathHops<'a, Octs> {
    fn new(octets: &'a Octs) -> Self {
        PathHops {
            segments: PathSegments::new(octets),
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
        if let Some((stype, mut parser)) = self.segments.next_pair() {
            if stype == SegmentType::Sequence {
                let mut asn_iter = Asns { parser };
                if let Some(asn) = asn_iter.next() {
                    self.current = Some(asn_iter);
                    return Some(Hop::Asn(asn))
                } else {
                    return None
                }
            } else {
                return Some(Hop::Segment(Segment {
                    stype,
                    octets: parser.parse_octets(parser.remaining()).expect("parsed before") } ) )
            }
        }


        None
    }
}

//--- PathSegments --------------------------------------------------------
/// Iterates over Segments in a Path.
pub struct PathSegments<'a, Octs> {
    parser: Parser<'a, Octs>
}

impl<'a, Octs: AsRef<[u8]>> PathSegments<'a, Octs> {
    fn new(octets: &'a Octs) -> Self {
        PathSegments { parser: Parser::from_ref(octets) }
    }
}

impl<'a, Octs: Octets> PathSegments<'a, Octs> {
    fn next_pair(&mut self) -> Option<(SegmentType, Parser<'a, Octs>)> {
        if self.parser.remaining() == 0 {
            return None;
        }
        let stype = self.parser.parse_u8().expect("parsed before")
            .try_into().expect("illegally encoded AS path");

        let len = self.parser.parse_u8().expect("parsed before");
        // XXX 4 for 32bit ASNs, how can we support 16bit ASNs nicely?
        let parser = self.parser.parse_parser(len as usize * 4).expect("parsed before");
        Some((stype, parser))
    }
}

impl<'a, Octs: Octets> Iterator for PathSegments<'a, Octs> {
    type Item = Segment<Octs::Range<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None;
        }
        let stype = self.parser.parse_u8().expect("parsed before")
            .try_into().expect("illegally encoded AS path");

        let len = self.parser.parse_u8().expect("parsed before");
        // XXX 4 for 32bit ASNs, how can we support 16bit ASNs nicely?
        let octets = self.parser.parse_octets(len as usize * 4).expect("parsed before");
        Some(Segment { stype, octets } )
    }
}

/// Iterates over ASNs in a Segment.
pub struct Asns<'a, Octs> {
    parser: Parser<'a, Octs>
}
impl<'a, Octs: Octets> Asns<'a, Octs> {
    fn new(octets: &'a Octs) -> Self {
        Asns { parser: Parser::from_ref(octets) }
    }
}

impl<'a, Octs: Octets> Iterator for Asns<'a, Octs> {
    type Item = Asn;
    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None
        }
        let n = self.parser.parse_u32().expect("parsed before");
        Some(Asn::from(n))
    }
}

impl<'a, Octs: 'a + Octets> IntoIterator for &'a Segment<Octs> {
    type Item = Asn;
    type IntoIter = Asns<'a, Octs>;
    fn into_iter(self) -> Self::IntoIter {
        Asns { parser: Parser::from_ref(&self.octets) }
    }
}


//------------ HopPath ------------------------------------------------------


#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HopPath {
    hops: Vec<Hop<Vec<u8>>>,
}

//--- Reading ---------------------------------------------------------------


impl HopPath {
    pub fn contains(&self, _hop: &Hop<Vec<u8>>) -> bool {
        todo!()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Hop<Vec<u8>>> {
        todo!()
    }

    pub fn origin(&self) -> Option<Hop<Vec<u8>>> {
        todo!()
    }

    pub fn path_len(&self) -> Option<usize> {
        todo!()
    }
}

impl fmt::Display for HopPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl std::iter::IntoIterator for HopPath {
    type IntoIter = std::vec::IntoIter<Hop<Vec<u8>>>;
    type Item = Hop<Vec<u8>>;

    fn into_iter(self) -> Self::IntoIter {
        self.hops.into_iter()
    }
}


//--- Building / composing ---------------------------------------------------


impl HopPath {
    pub fn new() -> Self {
        Self { hops: vec![] }
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
        &mut self, _set: impl IntoIterator<Item = Asn>)
    {
        todo!()
    }

    pub fn prepend_confed_set(
        &mut self, _set: impl IntoIterator<Item = Asn>)
    {
        todo!()
    }

    pub fn append(&mut self, hop: Hop<Vec<u8>>) {
        self.hops.push(hop);
    }

    pub fn append_asn(&mut self, asn: Asn) {
        self.hops.push(Hop::Asn(asn))
    }

    pub fn insert_asns(&mut self, pos: usize, asns: Vec<Asn>) {
        todo!()
    }

    pub fn append_set(&mut self, set: impl IntoIterator<Item = Asn>) {
        self.append(Hop::Segment(Segment::new_set(set)))
    }

    pub fn append_confed_sequence(
        &mut self, _set: impl IntoIterator<Item = Asn>)
    {
        todo!()
    }

    pub fn append_confed_set(
        &mut self, _set: impl IntoIterator<Item = Asn>)
    {
        todo!()
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
        Ok(unsafe { AsPath::from_octets_unchecked(Octs::from_builder(target)) })
    }

    fn compose_hops<Octs: Octets, Target: OctetsBuilder>(
        mut hops: &[Hop<Octs>], target: &mut Target
    ) -> Result<(), Target::AppendError> {
        while !hops.is_empty() {
            let i = hops.iter().position(|h| !matches!(h, Hop::Asn(_))).unwrap_or_else(|| hops.len());
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

impl From<Vec<Hop<Vec<u8>>>> for HopPath {
    fn from(value: Vec<Hop<Vec<u8>>>) -> Self {
        todo!()
    }
}

impl From<Vec<Asn>> for HopPath {
    fn from(value: Vec<Asn>) -> Self {
        todo!()
    }
}

impl From<&[Asn]> for HopPath {
    fn from(value: &[Asn]) -> Self {
        todo!()
    }
}


//============ Error Types ===================================================

//------------ InvalidSegmentTypeError ---------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct InvalidSegmentTypeError;

impl fmt::Display for InvalidSegmentTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid segment type")
    }
}

impl error::Error for InvalidSegmentTypeError { }



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

        let path = AsPath{ octets: &raw };
        for hop in path.hops() {
            println!("{hop:?}");
        }
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

        let path = AsPath{ octets: &raw };
        for hop in path.hops() {
            println!("{hop:?}");
        }
    }

    #[test]
    fn prepend() {
        let mut hp = HopPath::new();
        hp.prepend(Asn::from_u32(100));
        hp.prepend_n(Asn::from_u32(200), 3);
        hp.prepend_arr([Asn::from_u32(300)]);
        hp.prepend_arr([Asn::from_u32(400), Asn::from_u32(500)]);
        println!("{hp:?}");

        hp.prepend(Segment::new_set([Asn::from_u32(1000), Asn::from_u32(2000)]));

        let asp = hp.to_as_path::<Vec<u8>>().unwrap();
        println!("{asp}");
    }

    #[test]
    fn new_set() {
        let set = Segment::new_set([Asn::from_u32(100), Asn::from_u32(200)]);
        let mut hp = HopPath::new();
        hp.prepend(set);
        let asp = hp.to_as_path::<Vec<u8>>().unwrap();
        println!("{asp}");

    }
}
