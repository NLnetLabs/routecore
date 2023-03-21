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
    octets: Octs,
}

impl Segment<Vec<u8>> {
    pub fn new_set(asns: impl IntoIterator<Item = Asn>) -> Self {
        let mut set = vec![];
        for a in asns.into_iter().map(|a| a.to_raw()) {
            set.extend_from_slice(&a);
        }

        Segment { stype: SegmentType::Set, octets: set }
    }

    pub fn new_confed_set(asns: impl IntoIterator<Item = Asn>) -> Self {
        let mut set = vec![];
        for a in asns.into_iter().map(|a| a.to_raw()) {
            set.extend_from_slice(&a);
        }

        Segment { stype: SegmentType::ConfedSet, octets: set }
    }

    pub fn new_confed_sequence(asns: impl IntoIterator<Item = Asn>) -> Self {
        let mut set = vec![];
        for a in asns.into_iter().map(|a| a.to_raw()) {
            set.extend_from_slice(&a);
        }

        Segment { stype: SegmentType::ConfedSequence, octets: set }
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
            u8::try_from(self.octets.as_ref().len() / 4)
                .expect("long sequence")
            ]
        )?;
        target.append_slice(self.octets.as_ref())?;
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



//--- Hop --------------------------------------------------------------------
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Hop<Octs> {
    Asn(Asn),
    Segment(Segment<Octs>),
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


//--- Building / composing ---------------------------------------------------


#[derive(Debug)]
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

/*
impl<T> From<T> for HopPath where T: IntoIterator<Item = Asn> {
    fn from(asns: T) -> HopPath {
        HopPath { hops: asns.into_iter().map(Hop::Asn).collect() }  
    }
}
*/

impl From<Vec<Asn>> for HopPath {
    fn from(asns: Vec<Asn>) -> HopPath {
        HopPath { hops: asns.into_iter().map(Hop::Asn).collect() }  
    }
}

impl From<&[Asn]> for HopPath {
    fn from(asns: &[Asn]) -> HopPath {
        HopPath { hops: asns.into_iter().map(|&a| Hop::Asn(a)).collect() }  
    }
}

impl<const N: usize> From<[Asn; N]> for HopPath {
    fn from(asns: [Asn; N]) -> HopPath {
        HopPath { hops: asns.into_iter().map(Hop::Asn).collect() }  
    }
}


//============ Error Types ===================================================

//------------ InvalidSegmentTypeError ---------------------------------------

#[derive(Clone, Copy, Debug, PartialEq)]
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

        let path = AsPath{ octets: &raw };
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
        assert!(hp.contains(&Hop::Asn(Asn::from_u32(10).into())));
        assert!(!hp.contains(&Hop::Asn(Asn::from_u32(30).into())));
    }

    #[test]
    fn froms()  {
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

        let hop: Hop<Vec<u8>> = Segment::new_set([Asn::from_u32(10)]).into();
        assert!(
            TryInto::<Asn>::try_into(hop).is_err()
        );
    }

}
