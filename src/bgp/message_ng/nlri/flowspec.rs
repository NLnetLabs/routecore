use crate::bgp::message_ng::{common::AfiSafiType, nlri::PathId};


#[derive(Debug)]
pub struct NlriByteLengthIter<'a> {
    afisafi: AfiSafiType,
    raw: &'a [u8],
}

impl<'a> NlriByteLengthIter<'a> {
    pub fn unchecked(afisafi: AfiSafiType, raw: &'a [u8]) -> Self {
        Self {
            afisafi,
            raw,
        }
    }
    pub fn new_checked(afisafi: AfiSafiType, raw: &'a [u8])
        -> Result<NlriByteLengthIter<'a>, (NlriByteLengthIter<'a>, &'a [u8])>
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

    fn check(self) -> Result<NlriByteLengthIter<'a>, (NlriByteLengthIter<'a>, &'a [u8])> {
        let mut cursor = 0;
        while cursor < self.raw.len() {
            let len_bytes = usize::from(self.raw[cursor]);
            if cursor + 1 + len_bytes > self.raw.len() {
                return Err((
                    NlriByteLengthIter {
                        afisafi: self.afisafi,
                        raw: &self.raw[0..cursor]
                    },
                    &self.raw[cursor..]
                ))
            }
            cursor += 1+len_bytes;
        }
        Ok(NlriByteLengthIter {
            afisafi: self.afisafi,
            raw: self.raw
        })
    }
}

impl<'a> Iterator for NlriByteLengthIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.raw.len() == 0 {
            return None
        }

        let len_bytes = usize::from(self.raw[0]);
        
        debug_assert!(self.raw.len() >= 1 + len_bytes, "illegal NLRI length");

        let res = Some(&self.raw[..1+len_bytes]);
        self.raw = &self.raw[1+len_bytes..];

        res
    }
}

#[derive(Debug)]
pub struct NlriAddPathByteLengthIter<'a> {
    afisafi: AfiSafiType,
    raw: &'a [u8],
}

impl<'a> NlriAddPathByteLengthIter<'a> {
    pub fn unchecked(afisafi: AfiSafiType, raw: &'a [u8]) -> Self {
        Self {
            afisafi,
            raw,
        }
    }
    pub fn new_checked(afisafi: AfiSafiType, raw: &'a [u8])
        -> Result<NlriAddPathByteLengthIter<'a>, (NlriAddPathByteLengthIter<'a>, &'a [u8])>
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

    fn check(self) -> Result<NlriAddPathByteLengthIter<'a>, (NlriAddPathByteLengthIter<'a>, &'a [u8])> {
        let mut cursor = 0;
        while cursor < self.raw.len() {
            if self.raw.len() < 5 {
                // not enough bytes for PathId (4)
                // and length byte (1) of an NLRI
                return Err((
                        NlriAddPathByteLengthIter {
                            afisafi: self.afisafi,
                            raw: &self.raw[0..cursor]
                        },
                        &self.raw[cursor..]
                ));  
            }
            let len_bytes = usize::from(self.raw[cursor]);
            if cursor + 4 + 1 + len_bytes > self.raw.len() {
                return Err((
                    NlriAddPathByteLengthIter {
                        afisafi: self.afisafi,
                        raw: &self.raw[0..cursor]
                    },
                    &self.raw[cursor..]
                ))
            }
            cursor += 4+1+len_bytes;
        }
        Ok(NlriAddPathByteLengthIter {
            afisafi: self.afisafi,
            raw: self.raw
        })
    }
}

impl<'a> Iterator for NlriAddPathByteLengthIter<'a> {
    type Item = (PathId, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.raw.len() == 0 {
            return None
        }

        let pathid = PathId(self.raw[..4].try_into().unwrap());
        let len_bytes = usize::from(self.raw[0]);
        
        debug_assert!(self.raw.len() >= 4 + 1 + len_bytes, "illegal NLRI length");

        let res = Some((pathid, &self.raw[4..4+1+len_bytes]));
        self.raw = &self.raw[4+1+len_bytes..];

        res
    }
}
