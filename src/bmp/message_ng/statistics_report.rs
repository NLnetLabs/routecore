
use std::borrow::Cow;

use zerocopy::{byteorder, Immutable, KnownLayout, NetworkEndian, TryFromBytes};

use crate::bmp::message_ng::common::{CommonHeader, PerPeerHeaderV3};


#[derive(TryFromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct StatisticsReport {
    pub common: CommonHeader,
    pub pph: PerPeerHeaderV3,
    pub stats_count: byteorder::U32<NetworkEndian>,
    pub stats: [u8],
}


impl StatisticsReport {
    pub fn try_from_full_pdu(raw: &[u8]) -> Result<&Self, Cow<'static, str>> {
        //TODO all kinds of length checks
        Self::try_ref_from_bytes(&raw).map_err(|e| e.to_string().into())
    }

    pub fn stats_count(&self) -> usize {
        usize::try_from(u32::from(self.stats_count)).unwrap()
    }
}
