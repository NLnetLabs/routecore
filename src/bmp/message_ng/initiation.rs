use std::borrow::Cow;

use zerocopy::{Immutable, KnownLayout, TryFromBytes};

use crate::bmp::message_ng::common::{CommonHeader, Tlvs};


#[derive(TryFromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct InitiationMessage {
    common: CommonHeader,
    tlvs: Tlvs,
}

impl InitiationMessage {
    pub fn try_from_full_pdu(raw: &[u8]) -> Result<&Self, Cow<'static, str>> {
        //TODO all kinds of length checks
        Self::try_ref_from_bytes(&raw).map_err(|e| e.to_string().into())
    }

    //pub fn try_from<R>(raw: &R) -> Result<&Self, Cow<'static, str>>
    //    where R: AsRef<[u8]>
    //{
    //    match InitiationMessage::try_ref_from_prefix(raw.as_ref()) {
    //        Ok((init_msg, _)) => Ok(init_msg),
    //        Err(e) => Err(e.to_string().into()),
    //    }
    //}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_initiation_msg() {
        // BMP Initiation Messsage with two Information TLVs:
        // sysDesc and sysName
        let buf = vec![
            0x03, 0x00, 0x00, 0x00, 0x6c, 0x04, 0x00, 0x01, 0x00, 0x5b, 0x43,
            0x69, 0x73, 0x63, 0x6f, 0x20, 0x49, 0x4f, 0x53, 0x20, 0x58, 0x52,
            0x20, 0x53, 0x6f, 0x66, 0x74, 0x77, 0x61, 0x72, 0x65, 0x2c, 0x20,
            0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x35, 0x2e, 0x32,
            0x2e, 0x32, 0x2e, 0x32, 0x31, 0x49, 0x5b, 0x44, 0x65, 0x66, 0x61,
            0x75, 0x6c, 0x74, 0x5d, 0x0a, 0x43, 0x6f, 0x70, 0x79, 0x72, 0x69,
            0x67, 0x68, 0x74, 0x20, 0x28, 0x63, 0x29, 0x20, 0x32, 0x30, 0x31,
            0x34, 0x20, 0x62, 0x79, 0x20, 0x43, 0x69, 0x73, 0x63, 0x6f, 0x20,
            0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x73, 0x2c, 0x20, 0x49, 0x6e,
            0x63, 0x2e, 0x00, 0x02, 0x00, 0x03, 0x78, 0x72, 0x33,
        ];

        let msg = InitiationMessage::try_from_full_pdu(&buf).unwrap();
        assert_eq!(msg.tlvs.iter().count(), 2);

        //for tlv in msg.tlvs.iter() {
        //    eprintln!(
        //        "tlv.length {}, tlv.value.len(): {}\n{}",
        //        tlv.length(),
        //        &tlv.value().len(),
        //        String::from_utf8_lossy(&tlv.value()),
        //    );
        //}
    }

}
