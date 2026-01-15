use std::{borrow::Cow, fmt};

use crate::bgp::message_ng::{common::AfiSafiType, nlri::{common::Nlri, NlriIter, NlriIterator}};


#[derive(Copy, Clone, Debug)]
pub struct Ipv4UnicastNlri<'a> {
    raw: &'a [u8],
}

impl<'a> Ipv4UnicastNlri<'a> {
    pub(crate) fn for_slice(raw: &'a [u8])  -> Self {
        Self { raw }
    }

    pub fn prefix_len(&self) -> u8 {
        self.raw[0]
    }

    pub fn to_fixed(&self) -> [u8; 5] {
        let mut res = [0; 5];
        res[..self.raw.len()].copy_from_slice(&self.raw);

        // Zero out anything in the last byte if the prefix length is not a multiple of 8
        let (full, rem) = (usize::from(self.raw[0] / 8), self.raw[0] % 8);
        if rem > 0 {
            res[full+1] = res[full+1] >> (8 - rem) << (8 - rem);
        }

        res
    }
}

impl<'a> Nlri<'a> for Ipv4UnicastNlri<'a> {
    const AFI_SAFI_TYPE: AfiSafiType = AfiSafiType::IPV6UNICAST;
    type Iterator = Ipv4UnicastNlriIter<'a>;
}


impl fmt::Display for Ipv4UnicastNlri<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self.raw[0];
        if len == 0 {
            return write!(f, "0.0.0.0/0")
        }

        let mut buf = [0u8; 4];
        buf[.. self.raw.len() - 1].copy_from_slice(&self.raw[1..]);
        let addr = std::net::Ipv4Addr::from_octets(buf);
        write!(f, "{addr}/{len}")
    }
}

impl serde::Serialize for Ipv4UnicastNlri<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        serializer.collect_str(self)
    }
}

impl AsRef<[u8]> for Ipv4UnicastNlri<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}


impl<'a> TryFrom<&'a [u8]> for Ipv4UnicastNlri<'a> {
    type Error = Cow<'static, str>;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Ok(Ipv4UnicastNlri { raw: value} )
    }
}

pub struct Ipv4UnicastNlriIter<'a> {
    iter: NlriIter<'a>,
}


impl<'a> NlriIterator<'a> for Ipv4UnicastNlriIter<'a> {
    fn empty() -> Self {
        Self { 
            iter: NlriIter::empty_for_afisafi(AfiSafiType::IPV6UNICAST),
        }
    }

    fn for_slice(raw: &'a [u8]) -> Self {
        Self {
            iter: NlriIter::unchecked(AfiSafiType::IPV6UNICAST, raw)
        }
    }
}

impl<'a> Iterator for Ipv4UnicastNlriIter<'a> {
    type Item = Ipv4UnicastNlri<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|raw_nlri|
           raw_nlri.try_into().unwrap() 
        )
    }
}
