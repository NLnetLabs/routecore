use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::bgp::message_ng::common::AfiSafiType;

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

    pub const fn empty() -> Self {
        Self(0)
    }
}

#[derive(Debug)]
pub struct PathId(pub [u8; 4]);


pub fn bits_to_bytes(bits: u8) -> usize {
    (usize::from(bits) + 7) >> 3
}

pub struct NlriIter<'a> {
    afisafi: AfiSafiType,
    raw: &'a [u8],
}

impl<'a> NlriIter<'a> {
    pub fn unchecked(afisafi: AfiSafiType, raw: &'a [u8]) -> Self {
        Self {
            afisafi,
            raw,
        }
    }
    pub fn new_checked(afisafi: AfiSafiType, raw: &'a [u8])
        -> Result<NlriIter<'a>, (NlriIter<'a>, &'a [u8])>
    {
        Self {
            afisafi,
            raw,
        }.check()
    }

    pub const fn empty() -> Self {
        Self {
            afisafi: AfiSafiType::RESERVED,
            raw: &[]
        }
    }

    fn check(self) -> Result<NlriIter<'a>, (NlriIter<'a>, &'a [u8])> {
        let mut cursor = 0;
        while cursor < self.raw.len() {
            let len_bytes = bits_to_bytes(self.raw[cursor]);
            if cursor + 1 + len_bytes > self.raw.len() {
                return Err((
                    NlriIter {
                        afisafi: self.afisafi,
                        raw: &self.raw[0..cursor]
                    },
                    &self.raw[cursor..]
                ))
            }
            cursor += 1+len_bytes;
        }

        Ok(self)
    }
}

impl<'a> Iterator for NlriIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.raw.len() == 0 {
            return None
        }

        let len_bytes = bits_to_bytes(self.raw[0]);
        
        debug_assert!(self.raw.len() >= 1 + len_bytes, "illegal NLRI length");

        let res = Some(&self.raw[..1+len_bytes]);
        self.raw = &self.raw[1+len_bytes..];

        res
    }
}


pub struct NlriAddPathIter<'a> {
    afisafi: AfiSafiType,
    raw: &'a [u8],
}

impl<'a> NlriAddPathIter<'a> {
    pub fn unchecked(afisafi: AfiSafiType, raw: &'a [u8]) -> Self {
        Self {
            afisafi,
            raw,
        }
    }

    pub fn new_checked(afisafi: AfiSafiType, raw: &'a [u8])
        -> Result<NlriAddPathIter<'a>, (NlriAddPathIter<'a>, &'a [u8])>
    {
        Self {
            afisafi,
            raw,
        }.check()
    }

    pub const fn empty() -> Self {
        Self {
            afisafi: AfiSafiType::RESERVED,
            raw: &[]
        }
    }

    fn check(self) -> Result<NlriAddPathIter<'a>, (NlriAddPathIter<'a>, &'a [u8])> {
        let mut cursor = 0;
        while cursor < self.raw.len() {
            if self.raw.len() < 5 {
                // not enough bytes for PathId (4)
                // and length byte (1) of an NLRI
                return Err((
                        NlriAddPathIter {
                            afisafi: self.afisafi,
                            raw: &self.raw[0..cursor]
                        },
                        &self.raw[cursor..]
                ));  
            }
            let len_bytes = bits_to_bytes(self.raw[cursor + 4]);
            if cursor + 4 + 1 + len_bytes > self.raw.len() {
                return Err((
                    NlriAddPathIter {
                        afisafi: self.afisafi,
                        raw: &self.raw[0..cursor]
                    },
                    &self.raw[cursor..]
                ))
            }
            cursor += 4+1+len_bytes;
        }

        Ok(self)
    }
}

impl<'a> Iterator for NlriAddPathIter<'a> {
    type Item = (PathId, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.raw.len() == 0 {
            return None
        }

        let pathid = PathId(self.raw[..4].try_into().unwrap());

        let len_bytes = bits_to_bytes(self.raw[4]);
        debug_assert!(self.raw.len() >= 4 + 1 + len_bytes, "illegal NLRI length");

        let res = Some((pathid, &self.raw[4..4+1+len_bytes]));
        self.raw = &self.raw[4+1+len_bytes..];

        res
    }
}
