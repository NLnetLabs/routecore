use std::borrow::Cow;

use zerocopy::{Immutable, KnownLayout, TryFromBytes};

use crate::{bgp::message_ng::Update, bmp::message_ng::{common::{CommonHeader, PerPeerHeaderV3, PerPeerHeaderV4}, io::Parseable}};

// TODO make v3 and v4 versions
// based on generic const u8?
#[derive(TryFromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct RouteMonitoringV3 {
    pub common: CommonHeader,
    pub per_peer_header: PerPeerHeaderV3,
    bgp_update: [u8],
}

#[derive(TryFromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct RouteMonitoringV4 {
    pub common: CommonHeader,
    pub per_peer_header: PerPeerHeaderV4,
    tlvs: [u8],
}


impl Parseable for RouteMonitoringV3 {
    fn try_from_full_pdu(raw: &[u8]) -> Result<&Self, Cow<'static, str>> {
        //TODO all kinds of length checks

        let (ch, _) = CommonHeader::try_ref_from_prefix(&raw).map_err(|_| "can't parse Common Header")?;
        if ch.version != 3 {
            // TODO introduce a proper "mismatched version" error so the caller can try with
            // another version if wanted.
            return Err(format!("expected version 3, got {}", ch.version).into());
        }
        Self::try_ref_from_bytes(&raw).map_err(|e| e.to_string().into())
    }
}
impl RouteMonitoringV3 {

    //pub fn try_from_full_pdu(raw: &[u8]) -> Result<&Self, Cow<'static, str>> {
    //    //TODO all kinds of length checks

    //    let (ch, _) = CommonHeader::try_ref_from_prefix(&raw).map_err(|_| "can't parse Common Header")?;
    //    if ch.version != 3 {
    //        // TODO introduce a proper "mismatched version" error so the caller can try with
    //        // another version if wanted.
    //        return Err(format!("expected version 3, got {}", ch.version).into());
    //    }
    //    Self::try_ref_from_bytes(&raw).map_err(|e| e.to_string().into())
    //}

    pub fn bgp_update(&self) -> Result<&Update, Cow<'static, str>> {
        Update::try_from_full_pdu(&self.bgp_update)
    }

    pub fn per_peer_header(&self) -> &PerPeerHeaderV3 {
        &self.per_peer_header
    }
}

impl Parseable for RouteMonitoringV4 {
    fn try_from_full_pdu(raw: &[u8]) -> Result<&Self, Cow<'static, str>> {
        //TODO all kinds of length checks

        let (ch, _) = CommonHeader::try_ref_from_prefix(&raw).map_err(|_| "can't parse Common Header")?;
        if ch.version != 4 {
            return Err(format!("expected version 4, got {}", ch.version).into());
        }
        Self::try_ref_from_bytes(&raw).map_err(|e| e.to_string().into())
    }
}

impl RouteMonitoringV4 {
    //pub fn try_from_full_pdu(raw: &[u8]) -> Result<&Self, Cow<'static, str>> {
    //    //TODO all kinds of length checks

    //    let (ch, _) = CommonHeader::try_ref_from_prefix(&raw).map_err(|_| "can't parse Common Header")?;
    //    if ch.version != 4 {
    //        return Err(format!("expected version 4, got {}", ch.version).into());
    //    }
    //    Self::try_ref_from_bytes(&raw).map_err(|e| e.to_string().into())
    //}

    pub fn bgp_update(&self) -> Result<&Update, Cow<'static, str>> {
        todo!(); // TODO get PDU from TLV
        //Update::try_from_full_pdu(&self.bgp_update)
    }
}


#[cfg(test)]
mod tests {

    use crate::bgp::message_ng::common::SessionConfig;

    use super::*;

    #[test]
    fn parse_msg() {
        // a single BMP Route Monitoring message, containing one BGP UPDATE
        // message with 4 path attributes and 1 IPv4 NLRI
        let raw = vec![
            0x03, 0x00, 0x00, 0x00, 0x67, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x0a, 0xff, 0x00, 0x65,
            0x00, 0x01, 0x00, 0x00, 0x0a, 0x0a, 0x0a, 0x01,
            0x54, 0xa2, 0x0e, 0x0c, 0x00, 0x0e, 0x81, 0x09,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x37, 0x02, 0x00, 0x00, 0x00, 0x1b, 0x40,
            0x01, 0x01, 0x00, 0x40, 0x02, 0x06, 0x02, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x40, 0x03, 0x04, 0x0a,
            0xff, 0x00, 0x65, 0x80, 0x04, 0x04, 0x00, 0x00,
            0x00, 0x01, 0x20, 0x0a, 0x0a, 0x0a, 0x02
        ]; 

        let rm = RouteMonitoringV3::try_from_full_pdu(&raw).unwrap();
        let update = rm.bgp_update().unwrap();
        let update = update.into_checked_parts(&SessionConfig::default()).unwrap();
        assert_eq!(update.conv_reach_iter().count(), 1);

    }
}
