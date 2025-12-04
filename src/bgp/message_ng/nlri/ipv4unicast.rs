use std::borrow::Cow;

use crate::bgp::message_ng::{common::AfiSafiType, nlri::{common::Nlri, NlriIter, NlriIterator}};


pub struct Ipv4UnicastNlri<'a> {
    raw: &'a [u8],
}

impl<'a> Ipv4UnicastNlri<'a> {
    pub fn to_fixed(&self) -> [u8; 5] {
        todo!()
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
