use std::{borrow::Cow, fmt};

use paste::paste;
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
    addpath_rx: Vec<AfiSafiType>,
    //max_pdu_size: TODO
}
impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            four_octet_asns: true,
            addpath_rx: Vec::new(),
        }
    }
}
impl SessionConfig {
    pub fn four_octet_asns(&self) -> bool {
        self.four_octet_asns
    }

    pub fn addpath_rx(&self, afisafi: AfiSafiType) -> bool {
        self.addpath_rx.contains(&afisafi)

    }
    pub fn set_addpath_rx(&mut self, afisafi: AfiSafiType) {
        if !self.addpath_rx(afisafi) {
            self.addpath_rx.push(afisafi);
        }
    }
}

// TODO:
//
// instead of uppercase, pass in camel case
// make const names using paste crate ($var:upper)
// add Display impl (and use camel case in there)
// add TryFrom? or similar, to check whether we support the afisafi
// performance test, somehow, the complex afisafis

macro_rules! afisafi{
    ({
        $($name:ident => $bytes:expr),* $(,)*
    }
    {
        $($name2:ident => $bytes2:expr, $static_len:expr, $length_fn:expr),* $(,)*
    }
    ) => {
        paste! {
            impl AfiSafiType {
                $(pub const [<$name:upper>] : Self = Self($bytes);)*
                $(pub const [<$name2:upper>] : Self = Self($bytes2);)*
                pub fn nlri_fixed_size(&self) -> usize {
                    match *self {
                        $(Self::$name2 => $static_len,)*
                            _ => usize::MAX
                    }
                }
                pub fn nlri_length(&self, raw: &[u8]) -> usize {
                    match *self {
                        $(Self::[<$name2:upper>] => { $length_fn(raw)})*
                            _ => usize::MAX
                    }
                }

                pub fn is_custom(&self) -> bool {
                    match *self {
                        $(Self::[<$name:upper>] => false,)*
                        $(Self::[<$name2:upper>] => true,)*
                        _ => unreachable!()
                    }

                }
            }
        }

        paste! {
            impl fmt::Display for AfiSafiType {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {

                    match *self {
                        $(AfiSafiType::[<$name:upper>] => write!(f, "$name"),)*
                        $(AfiSafiType::[<$name2:upper>] => write!(f, "$name2"),)*
                        _ => {
                            write!(f,
                                "Unrecognized AFI/SAFI {}/{}",
                                u16::from_be_bytes([self.0[0], self.0[1]]), self.0[2]
                            )
                        }
                    }
                }
            }
        }
    }
}

afisafi! [
{
    RESERVED => [0,0,0],
    IPV4UNICAST => [0, 1, 1],
    IPV6UNICAST => [0, 2, 1],
}
{
    FLOWSPEC => [0, 1, 133], 1, |raw: &[u8]| usize::from(raw[0]),
    BGPLS => [0x40, 0x04, 71], 4, |raw: &[u8]| usize::from(u16::from_be_bytes([raw[2], raw[3]])),
}
];

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct AfiSafiType([u8; 3]);
//impl AfiSafiType {
//    pub const RESERVED: Self = Self([0x00, 0x00, 0x00]);
//    pub const IPV4UNICAST: Self = Self([0x00, 0x01, 0x01]);
//    pub const IPV6UNICAST: Self = Self([0x00, 0x02, 0x01]);
//
//    pub const FLOWSPEC: Self = Self([0x00, 0x01, 133]);
//    pub const BGPLS: Self = Self([0x40, 0x04, 71]);
//
//    pub const BYTE_LEN_NLRI: [Self; 1] = [Self::FLOWSPEC];
//
//    pub fn nlri_len_in_bytes(&self) -> bool {
//        match *self {
//            Self::FLOWSPEC => true,
//            _ => false,
//        }
//    }
//    const T: () = const {
//        assert!(
//            AfiSafiType::BGPLS.nlri_fixed_size() != usize::MAX
//            && AfiSafiType::FLOWSPEC.nlri_fixed_size() != usize::MAX
//        );
//    };
//}

impl AfiSafiType {
    // 
    //pub const fn nlri_fixed_size(&self) -> usize {
    //    match *self {
    //        Self::BGPLS => 4,
    //        Self::FLOWSPEC => 1,
    //        _ => usize::MAX,
    //    }
    //}

    //pub fn nlri_length2(&self) -> impl FnOnce(&[u8]) -> usize {
    //    match *self {
    //        Self::FLOWSPEC => { |raw: &[u8]| usize::from(raw[0]) },
    //        Self::BGPLS => { |raw: &[u8]| usize::from(u16::from_be_bytes([raw[2], raw[3]])) },
    //        _ => |_: &[u8]| usize::MAX
    //    }
    //}

    //pub fn nlri_length(&self, raw: &[u8]) -> usize {
    //    match *self {
    //        Self::FLOWSPEC => { usize::from(raw[0]) },
    //        Self::BGPLS => { usize::from(u16::from_be_bytes([raw[2], raw[3]])) },
    //        _ =>  usize::MAX
    //    }
    //}
}

// XXX so this try from does not do any conversion, technically.
// it is useful/necessary to have a 'do we recognize this' though.
impl TryFrom<&[u8]> for AfiSafiType {
    type Error = Cow<'static, str>;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 3 {
            return Err("expecting 3 bytes for AFISAFI".into());
        }
        match value {
            [0x00, 0x01, 0x01] => Ok(Self::IPV4UNICAST),
            [0x00, 0x02, 0x01] => Ok(Self::IPV6UNICAST),
            [0x00, 0x01, 133] => Ok(Self::FLOWSPEC),

            _ => Err(format!("unknown AFISAFI {:?}", value).into())
        }
    }
}

//impl fmt::Display for AfiSafiType {
//    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//
//        match *self {
//            AfiSafiType::RESERVED => write!(f, "Reserved (0/0)"),
//            AfiSafiType::IPV4UNICAST => write!(f, "Ipv4Unicast"),
//            AfiSafiType::IPV6UNICAST => write!(f, "Ipv6Unicast"),
//            AfiSafiType::FLOWSPEC => write!(f, "Ipv4Flowspec"),
//            _ => {
//                write!(f,
//                    "Unrecognized AFI/SAFI {}/{}",
//                    u16::from_be_bytes([self.0[0], self.0[1]]), self.0[2]
//                )
//            }
//        }
//    }
//}

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


