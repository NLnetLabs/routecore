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



#[derive(IntoBytes, TryFromBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct UncheckedMessage {
    header: Header,
    contents: [u8],
}

#[derive(IntoBytes, FromBytes, KnownLayout, Immutable)]
#[derive(Eq, PartialEq)]
#[repr(C, packed)]
pub struct MessageType(pub u8);

#[allow(dead_code)]
impl MessageType {
    pub const OPEN: Self = Self(1);
    pub const UPDATE: Self = Self(2);
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
