use zerocopy::{byteorder, FromBytes, Immutable, IntoBytes, KnownLayout, NetworkEndian, TryFromBytes};

pub const MIN_MSG_SIZE: usize = 19;

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

