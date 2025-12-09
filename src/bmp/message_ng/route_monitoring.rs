use std::borrow::Cow;

use zerocopy::{Immutable, KnownLayout, TryFromBytes};

use crate::{bgp::message_ng::Update, bmp::message_ng::common::{CommonHeader, PerPeerHeader, V3, V4}};

// TODO make v3 and v4 versions
// based on generic const u8?
#[derive(TryFromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
//pub struct RouteMonitoring<const V: u8 = 3> {
pub struct RouteMonitoring<V> {
    _version: std::marker::PhantomData<V>,
    pub common: CommonHeader,
    pub pph: PerPeerHeader,
    bgp_update: [u8], // if we keep one struct (generic over V) for both v3 and v4, change this
                      // into 'bgp_update_or_tlvs' or something
}

impl<V> RouteMonitoring<V> {
    pub fn per_peer_header(&self) -> &PerPeerHeader {
        &self.pph
    }
}
impl RouteMonitoring<V3> {

    // The default for now is still v3. Whenever that changes, we move this method to
    // RouteMonitoring<V4>.
    pub fn try_from_full_pdu(raw: &[u8]) -> Result<&RouteMonitoring<V3>, Cow<'static, str>> {
        RouteMonitoring::<V3>::try_v3_from_full_pdu(&raw)
    }

    pub fn try_v3_from_full_pdu(raw: &[u8]) -> Result<&RouteMonitoring<V3>, Cow<'static, str>> {
        //TODO all kinds of length checks

        let (ch, _) = CommonHeader::try_ref_from_prefix(&raw).map_err(|_| "can't parse Common Header")?;
        if ch.version != 3 {
            return Err(format!("expected version 3, got {}", ch.version).into());
        }
        RouteMonitoring::try_ref_from_bytes(&raw).map_err(|e| e.to_string().into())
    }

    pub fn bgp_update(&self) -> Result<&Update, Cow<'static, str>> {
        Update::try_from_full_pdu(&self.bgp_update)
    }
}

impl RouteMonitoring<V4> {
    pub fn try_v4_from_full_pdu(raw: &[u8]) -> Result<&RouteMonitoring<V4>, Cow<'static, str>> {
        //TODO all kinds of length checks

        let (ch, _) = CommonHeader::try_ref_from_prefix(&raw).map_err(|_| "can't parse Common Header")?;
        if ch.version != 4 {
            return Err(format!("expected version 4, got {}", ch.version).into());
        }
        RouteMonitoring::try_ref_from_bytes(&raw).map_err(|e| e.to_string().into())
    }

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

        let rm = RouteMonitoring::try_v3_from_full_pdu(&raw).unwrap();
        let update = rm.bgp_update().unwrap();
        let update = update.into_checked_parts(&SessionConfig::default()).unwrap();
        assert_eq!(update.conv_reach_iter().count(), 1);

    }
}
