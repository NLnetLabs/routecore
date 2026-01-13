use std::{borrow::Cow, fmt};

use crate::bgp::message_ng::{common::AfiSafiType, nlri::{common::Nlri, NlriIter, NlriIterator}};


pub struct Ipv4UnicastNlri<'a> {
    raw: &'a [u8],
}

impl<'a> Ipv4UnicastNlri<'a> {
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

impl fmt::Display for Ipv4UnicastNlri<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self.raw[0];
        if len == 0 {
            return write!(f, "0.0.0.0/0")
        }
        let (full, rem) = (len / 8, len % 8);
        let mut zeroes = 4 - full;
        match full {
            0 => write!(f, "{}.0.0.0/{len}", self.raw[1] >> (8 - rem) << (8 - rem))?,
            1 => write!(f, "{}", self.raw[1])?,
            2 => write!(f, "{}.{}", self.raw[1], self.raw[2])?,
            3 => write!(f, "{}.{}.{}", self.raw[1], self.raw[2], self.raw[3])?,
            4 => { return write!(f, "{}.{}.{}.{}/32", self.raw[1], self.raw[2], self.raw[3], self.raw[4]); }
            _ => return write!(f, "illegal IPv4 prefix length {len}"),
        }

        if rem > 0 {
            write!(f, ".{}", self.raw[usize::from(full)+1] >> (8 - rem) << (8 - rem))?;
            zeroes -= 1;
        }
        for _ in 0..zeroes {
            write!(f, ".0")?;
        }
        write!(f, "/{len}")
    }
}

impl<'a> Nlri<'a> for Ipv4UnicastNlri<'a> {
    const AFI_SAFI_TYPE: AfiSafiType = AfiSafiType::IPV6UNICAST;
    type Iterator = Ipv4UnicastNlriIter<'a>;
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

impl<'a> TryFrom<&'a [u8]> for Ipv4UnicastNlri<'a> {
    type Error = Cow<'static, str>;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Ok(Ipv4UnicastNlri { raw: value} )
    }
}

pub struct Ipv4UnicastNlriIter<'a> {
    iter: NlriIter<'a>,
}

impl<'a> Iterator for Ipv4UnicastNlriIter<'a> {
    type Item = Ipv4UnicastNlri<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|raw_nlri|
           raw_nlri.try_into().unwrap() 
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_fixed() {
        assert_eq!(v4(&[0]).to_fixed(), [0,0,0,0,0]);
        assert_eq!(v4(&[32,1,2,3,4]).to_fixed(), [32,1,2,3,4]);
        assert_eq!(v4(&[8,1]).to_fixed(), [8,1,0,0,0]);
        assert_eq!(v4(&[16,1,2]).to_fixed(), [16,1,2,0,0]);
        assert_eq!(v4(&[17,1,2,128]).to_fixed(), [17,1,2,128,0]);
        assert_eq!(v4(&[15,1,2]).to_fixed(), [15,1,2,0,0]);
    }

    fn v4(raw: &[u8]) -> Ipv4UnicastNlri<'_> {
        Ipv4UnicastNlri {
            raw
        }
    }
    #[test]
    fn display() {
        assert_eq!("0.0.0.0/0", v4(&[0]).to_string());
        assert_eq!("1.2.3.4/32", v4(&[32,1,2,3,4]).to_string());
        assert_eq!("1.2.0.0/16", v4(&[16,1,2,0,0]).to_string());
        assert_eq!("1.2.0.0/16", v4(&[16,1,2]).to_string());
        assert_eq!("1.2.0.0/15", v4(&[15,1,2]).to_string());
        assert_eq!("1.2.0.0/17", v4(&[17,1,2,1]).to_string());
        assert_eq!("1.2.128.0/17", v4(&[17,1,2,128]).to_string());
        assert_eq!("1.2.192.0/18", v4(&[18,1,2,192]).to_string());
        assert_eq!("1.2.80.0/20", v4(&[18,1,2,80]).to_string());
    }

    #[test]
    fn serialize() {
        todo!();
    }
}
