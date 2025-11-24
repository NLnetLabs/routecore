use std::fmt;

use zerocopy::{byteorder, FromBytes, Immutable, IntoBytes, KnownLayout, NetworkEndian, TryFromBytes};

pub const MIN_MSG_SIZE: usize = 19;
pub const SEGMENT_TYPE_SEQUENCE: u8 = 2;

#[derive(IntoBytes, TryFromBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct Header {
    pub marker: [u8; 16],
    pub length: byteorder::U16<NetworkEndian>,
    pub msg_type: MessageType,
}


#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Header {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Header {
            marker: <[u8; 16]>::arbitrary(u)?,
            length: <[u8;2]>::arbitrary(u)?.into(),
            msg_type: MessageType::arbitrary(u)?,
        })
    }
}

#[derive(IntoBytes, TryFromBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct UncheckedMessage {
    header: Header,
    contents: [u8],
}

#[derive(IntoBytes, FromBytes, KnownLayout, Immutable)]
#[derive(Eq, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(C, packed)]
pub struct MessageType(pub u8);

#[allow(dead_code)]
impl MessageType {
    pub const OPEN: Self = Self(1);
    pub const UPDATE: Self = Self(2);
}

impl fmt::Debug for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MessageType").field(&self.0).finish()
    }
}


pub struct SessionConfig {
    four_octet_asns: bool,
    //addpath_families: TODO
    //max_pdu_size: TODO
}
impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            four_octet_asns: true,
        }
    }
}
impl SessionConfig {
    pub fn four_octet_asns(&self) -> bool {
        self.four_octet_asns
    }
}



#[allow(dead_code)] // just a helper for now
pub fn hexprint(buf: impl AsRef<[u8]>) {
    for c in buf.as_ref().chunks(16) {
        for b in c {
            print!("{:02X} ", b);
        }
        println!();
    }
}

pub struct HexFormatted<'a>(pub &'a[u8]);
impl fmt::Debug for HexFormatted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in self.0.chunks(16) {
            for b in c {
                write!(f, "{:02X} ", b)?;
            }
            writeln!(f)?;
        }
        Ok(())
    }
}


// XXX this might have to go somewhere else eventually
// Also, this is really just a placeholder for the time being
#[derive(IntoBytes, FromBytes, KnownLayout, Immutable)]
#[derive(Debug, Default, Eq, Hash, PartialEq)]
pub(crate) struct RpkiInfo(pub u8);
impl From<u8> for RpkiInfo {
    fn from(value: u8) -> Self {
        Self(value)
    }
}


