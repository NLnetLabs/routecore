use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(IntoBytes, FromBytes, KnownLayout, Immutable)]
#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct NlriHints(u8);

impl NlriHints {
    // For now, we use the same bits as defined in path_attributes.
    // We need to double check whether these hints make actual sense for path attributes at all.
    // Perhaps ADDPATH and MULTILABEL don't make sense there.
    pub const ADDPATH:              Self = Self(0b0000_0100);
    pub const MULTILABEL:           Self = Self(0b0000_1000);
    pub const MALFORMED:            Self = Self(0b0001_0000);
    pub const HINT_UNRECOGNIZED:    Self = Self(0b0010_0000);

    pub fn set(&mut self, hint: NlriHints) {
        self.0 |= hint.0
    }

    pub fn get(&self, hint: NlriHints) -> bool {
        self.0 & hint.0 == hint.0
    }

    pub fn empty() -> Self {
        Self(0)
    }
}

pub struct PathId([u8; 4]);


pub fn bits_to_bytes(bits: u8) -> usize {
    usize::from((bits + 7) >> 3)
}

pub struct NlriIter<'a> {
    afisafi: [u8; 3],
    raw: &'a [u8],
}

impl<'a> NlriIter<'a> {
    pub fn new(afisafi: [u8; 3], raw: &'a [u8]) -> Self {
        Self {
            afisafi,
            raw,
        }
    }
}

impl<'a> Iterator for NlriIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.raw.len() == 0 {
            return None
        }


        let len_bytes = bits_to_bytes(self.raw[0]);
        if self.raw.len() < 1 + len_bytes {
            // TODO error
        }

        let res = Some(&self.raw[..1+len_bytes]);
        self.raw = &self.raw[1+len_bytes..];

        res
    }
}
