use std::borrow::Cow;

use crate::bgp::message_ng::{common::AfiSafiType, nlri::{common::Nlri, CustomNlriIter, NlriIterator}};



// In a BGP UPDATE PDU, there can be
// - one MP_REACH_NLRI, for the FlowSpec afisafi
//  - containing (possibly) multiple FlowSpecNlri,
//   - which each consist of one or more FlowSpec 'components'

// One NLRI, contains one or more components.
pub struct FlowSpecNlri<'a> {
    raw: &'a [u8],
}

impl<'a> FlowSpecNlri<'a> {
    pub fn components(&self) -> FlowSpecComponentIter<'a> {
        FlowSpecComponentIter {
            raw: &self.raw
        }
    }
}

impl<'a> Nlri<'a> for FlowSpecNlri<'a> {
    const AFI_SAFI_TYPE: AfiSafiType = AfiSafiType::FLOWSPEC;
    type Iterator = FlowSpecNlriIter<'a>;

}

impl<'a> NlriIterator<'a> for FlowSpecNlriIter<'a> {
    fn empty() -> Self {
        Self { 
            custom_iter: CustomNlriIter::empty_for_afisafi(AfiSafiType::FLOWSPEC),
        }
    }

    fn for_slice(raw: &'a [u8]) -> Self {
        Self {
            custom_iter: CustomNlriIter::unchecked(AfiSafiType::FLOWSPEC, raw)
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for FlowSpecNlri<'a> {
    type Error = Cow<'static, str>;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Ok(FlowSpecNlri { raw: value} )
    }
}

pub struct FlowSpecNlriIter<'a> {
    custom_iter: CustomNlriIter<'a>,
}

impl<'a> Iterator for FlowSpecNlriIter<'a> {
    type Item = FlowSpecNlri<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.custom_iter.next().map(|raw_nlri|
           raw_nlri.try_into().unwrap() 
        )
    }
}


// A single filter rule, of which there can be multiple in a single FlowSpecNlri
pub struct FlowSpecComponent<'a> {
    raw: &'a [u8],
}

impl<'a> FlowSpecComponent<'a> {
    pub fn filter_type(&self) -> u8 {
        self.raw[0]
    }
}


// To iterate over N filter rules per single FlowSpecNlri
pub struct FlowSpecComponentIter<'a> {
    raw: &'a[u8],
}

impl<'a> Iterator for FlowSpecComponentIter<'a> {
    type Item = FlowSpecComponent<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.raw.is_empty() {
            return None;
        }

        let len = usize::from(self.raw[0]);
        let res = &self.raw[1..1+len];
        self.raw = &self.raw[1+len..];
        Some(res.try_into().unwrap())
    }
}

impl<'a> TryFrom<&'a[u8]> for FlowSpecComponent<'a> {
    type Error = Cow<'static, str>;

    fn try_from(value: &'a[u8]) -> Result<Self, Self::Error> {
        Ok(Self { raw: value } )
    }
}
