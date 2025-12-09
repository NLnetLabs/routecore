use std::borrow::Cow;

use zerocopy::{byteorder, Immutable, KnownLayout, NetworkEndian, TryFromBytes};

use crate::{bgp::message_ng::Open, bmp::message_ng::common::{CommonHeader, PerPeerHeaderV3, Tlvs}};


#[derive(TryFromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct PeerUpNotification {
    pub common: CommonHeader,
    pub pph: PerPeerHeaderV3,
    pub local_addr: [u8; 16],
    pub local_port: byteorder::U16<NetworkEndian>,
    pub remote_port: byteorder::U16<NetworkEndian>,
    opens_and_tlvs: [u8],
    //pub sent_open: BgpOpen, // XXX should we put these in TLVs as well in BMPv4?
    //pub rcvd_open: BgpOpen,
    //pub tlvs: Tlvs,
}

impl PeerUpNotification {
    pub fn try_from_full_pdu(raw: &[u8]) -> Result<&Self, Cow<'static, str>> {
        //TODO all kinds of length checks
        Self::try_ref_from_bytes(&raw).map_err(|e| e.to_string().into())
    }

    pub fn bgp_opens(&self) -> Result<(&Open, &Open), Cow<'static, str>> {
        let (sent, tail) = Open::try_from_prefix(&self.opens_and_tlvs)?;
        let (rcvd, _tlvs) = Open::try_from_prefix(tail)?;

        Ok((sent, rcvd))
    }
}

#[cfg(test)]
mod tests {
    use std::{net::{IpAddr, Ipv4Addr}, str::FromStr};

    use crate::bmp::message_ng::common::{Asn, MessageType, PeerType};

    use super::*;

    #[test]
    fn peer_up_notification() {
        // BMP PeerUpNotification, containing two BGP OPEN messages (the Sent
        // OPEN and the Received OPEN), both containing 5 Capabilities in the
        // Optional Parameters.
        // No optional Information field.
        // quoting RFC7854:
        // Inclusion of the Information field is OPTIONAL.  Its presence or
        // absence can be inferred by inspection of the Message Length in the
        // common header. TODO implement this presence check.
        //
		let raw = vec![
			0x03, 0x00, 0x00, 0x00, 0xba, 0x03, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x0a, 0xff, 0x00, 0x65,
			0x00, 0x00, 0xfb, 0xf0, 0x0a, 0x0a, 0x0a, 0x01,
			0x54, 0xa2, 0x0e, 0x0b, 0x00, 0x0e, 0x0c, 0x20,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x0a, 0xff, 0x00, 0x53,
			0x90, 0x6e, 0x00, 0xb3, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0x00, 0x3b, 0x01, 0x04,
			0xfb, 0xff, 0x00, 0xb4, 0x0a, 0x0a, 0x0a, 0x67,
			0x1e, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00,
			0x01, 0x02, 0x02, 0x80, 0x00, 0x02, 0x02, 0x02,
			0x00, 0x02, 0x06, 0x41, 0x04, 0x00, 0x00, 0xfb,
			0xff, 0x02, 0x04, 0x40, 0x02, 0x00, 0x78, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
			0x3b, 0x01, 0x04, 0xfb, 0xf0, 0x00, 0x5a, 0x0a,
			0x0a, 0x0a, 0x01, 0x1e, 0x02, 0x06, 0x01, 0x04,
			0x00, 0x01, 0x00, 0x01, 0x02, 0x02, 0x80, 0x00,
			0x02, 0x02, 0x02, 0x00, 0x02, 0x04, 0x40, 0x02,
			0x00, 0x78, 0x02, 0x06, 0x41, 0x04, 0x00, 0x00,
			0xfb, 0xf0];

        let bmp = PeerUpNotification::try_from_full_pdu(&raw).unwrap();

        assert_eq!(bmp.common.version, 3);
        assert_eq!(bmp.common.length, 186);
        assert_eq!(
            bmp.common.msg_type,
            MessageType::PEER_UP_NOTIFICATION
        );
        assert_eq!(
            bmp.pph.peer_type,
            PeerType::GLOBAL_INSTANCE
        );
        assert!(bmp.pph.is_ipv4());
        assert_eq!(bmp.pph.distinguisher(), [0; 8]);
        assert_eq!(
            bmp.pph.address(),
            IpAddr::from_str("10.255.0.101").unwrap()
        );

        assert_eq!(bmp.pph.asn(), Asn::from_u32(64496));
        assert_eq!(bmp.pph.bgp_id(), [0x0a, 0x0a, 0x0a, 0x1]);
        assert_eq!(bmp.pph.ts_seconds(), 1419906571);
        assert_eq!(bmp.pph.ts_micros(), 920608);

        assert_eq!(
            bmp.pph.timestamp().to_string(),
            "2014-12-30 02:29:31.920608 UTC"
        );

        // Now the actual PeerUpNotification TODO FIX ALL THIS
        //assert_eq!(bmp.local_address(), Ipv4Addr::new(10, 255, 0, 83));
        //assert_eq!(bmp.local_port(), 36974);
        //assert_eq!(bmp.remote_port(), 179);
        
        // Now, the two variable length BGP OPEN messages
        let (bgp_open_sent, bgp_open_rcvd) = bmp.bgp_opens().unwrap();
        // first, the sent one
        //let bgp_open_sent = bmp.bgp_open_sent();
        //assert_eq!(bgp_open_sent.version(), 4);
        //assert_eq!(bgp_open_sent.my_asn(), Asn::from_u32(64511));
        //assert_eq!(bgp_open_sent.identifier(), [10, 10, 10, 103]);
        //assert_eq!(bgp_open_sent.opt_parm_len(), 30);
        //assert_eq!(bgp_open_sent.parameters().count(), 5);
        assert_eq!(bgp_open_sent.capabilities().count(), 5);
        
        // second, the received one
        //let bgp_open_rcvd = bmp.bgp_open_rcvd();
        //assert_eq!(bgp_open_rcvd.version(), 4);
        //assert_eq!(bgp_open_rcvd.my_asn(), Asn::from_u32(64496));
        //assert_eq!(bgp_open_rcvd.identifier(), [10, 10, 10, 1]);
        //assert_eq!(bgp_open_rcvd.opt_parm_len(), 30);
        //assert_eq!(bgp_open_rcvd.parameters().count(), 5);
        assert_eq!(bgp_open_rcvd.capabilities().count(), 5);

        //let (sent, rcvd) = bmp.bgp_open_sent_rcvd();
        //assert_eq!(sent.as_ref(), bgp_open_sent.as_ref());
        //assert_eq!(rcvd.as_ref(), bgp_open_rcvd.as_ref());

        //let sc = bmp.pph_session_config();
        //assert_eq!(sc.1, None);
        //assert!(sc.0.four_octet_enabled());
        //assert_eq!(sc.0.enabled_addpaths().count(), 0);

        //assert_eq!(
        //    bmp.supported_protocols(),
        //    vec![(AfiSafiType::Ipv4Unicast)]
        //);
    }

}
