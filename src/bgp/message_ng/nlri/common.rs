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

    pub fn empty() -> Self {
        Self(0)
    }
}

//impl From<u8> for NlriHints {
//    fn from(value: u8) -> Self {
//        Self(value)
//    }
//}
//impl PartialEq<u8> for NlriHints {
//    fn eq(&self, other: &u8) -> bool {
//        self.0 == *other
//    }
//}
//impl std::ops::BitOr<u8> for NlriHints {
//    type Output = Self;
//
//    fn bitor(self, rhs: u8) -> Self::Output {
//        Self(self.0 | rhs)
//    }
//}
//impl std::ops::BitOrAssign<u8> for NlriHints {
//    fn bitor_assign(&mut self, rhs: u8) {
//        self.0 |= rhs
//    }
//}
//impl std::ops::BitAnd<u8> for NlriHints {
//    type Output = Self;
//
//    fn bitand(self, rhs: u8) -> Self::Output {
//        Self(self.0 & rhs)
//    }
//}
