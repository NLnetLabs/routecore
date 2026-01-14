use std::{borrow::Cow, fmt};

use crate::bgp::message_ng::{common::AfiSafiType, nlri::{common::Nlri, NlriIter, NlriIterator}};


pub struct Ipv6UnicastNlri<'a> {
    raw: &'a [u8],
}

impl<'a> Ipv6UnicastNlri<'a> {
    pub fn to_fixed(&self) -> [u8; 17] {
        todo!()
    }
}

impl<'a> Nlri<'a> for Ipv6UnicastNlri<'a> {
    const AFI_SAFI_TYPE: AfiSafiType = AfiSafiType::IPV6UNICAST;
    type Iterator = Ipv6UnicastNlriIter<'a>;
}

impl fmt::Display for Ipv6UnicastNlri<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {

        let len = self.raw[0];
        if len == 0 {
            return write!(f, "::/0")
        }

        let mut buf = [0u8; 16];
        buf[.. self.raw.len() - 1].copy_from_slice(&self.raw[1..]);
        let addr = std::net::Ipv6Addr::from_octets(buf);
        write!(f, "{addr}/{len}")

    }

    // half-working attempt not using std::net
    //fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    //let len = self.raw[0];
    //if len == 0 {
    //    return write!(f, "::/0")
    //}
    //let (full, rem) = (usize::from(len / 8), len % 8);
    //let mut zeroes = 16 - full;

    //let mut iter = self.raw[1..1+full].chunks_exact(2);
    //while let Some(hextet) = iter.next() {
    //    if hextet[0] == 0 {
    //        //write!(f, "00")?;
    //    } else {
    //        write!(f, "{:x}", hextet[0])?;
    //    }
    //    write!(f, "{:02x}:", hextet[1])?;
    //}

    //let mut last_is_colon = true;
    //let mut wrote_remainder = false;

    //if let Some(byte) = iter.remainder().get(0) {
    //    if *byte != 0 {
    //        write!(f, "{:x}", byte)?;
    //        wrote_remainder = true;
    //        last_is_colon = false;
    //    }
    //}

    ////depending on wrote_remainder include leading 0 in hex or not
    //if rem > 0 {
    //    if wrote_remainder {
    //        write!(f, "{:x}", self.raw[full+1] >> (8 - rem) << (8 - rem))?;
    //    } else {
    //        write!(f, "{:02x}:", self.raw[full+1] >> (8 - rem) << (8 - rem))?;
    //        last_is_colon = true;
    //    }
    //    zeroes -= 1;
    //}

    //if zeroes > 0 {
    //    if last_is_colon {
    //        write!(f, ":")?;
    //    } else {
    //        write!(f, "::")?;
    //    }
    //}
    //
    //write!(f, "/{len}")
    //}
}

impl AsRef<[u8]> for Ipv6UnicastNlri<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

impl serde::Serialize for Ipv6UnicastNlri<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        serializer.collect_str(self)
    }
}

impl<'a> NlriIterator<'a> for Ipv6UnicastNlriIter<'a> {
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

impl<'a> TryFrom<&'a [u8]> for Ipv6UnicastNlri<'a> {
    type Error = Cow<'static, str>;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Ok(Ipv6UnicastNlri { raw: value} )
    }
}

pub struct Ipv6UnicastNlriIter<'a> {
    iter: NlriIter<'a>,
}

impl<'a> Iterator for Ipv6UnicastNlriIter<'a> {
    type Item = Ipv6UnicastNlri<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|raw_nlri|
           raw_nlri.try_into().unwrap() 
        )
    }
}
