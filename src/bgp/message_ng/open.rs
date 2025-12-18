use std::borrow::Cow;

use zerocopy::{byteorder, FromBytes, Immutable, IntoBytes, KnownLayout, NetworkEndian, TryFromBytes};

use crate::bgp::message_ng::common::{Header, MessageType};


#[derive(IntoBytes, TryFromBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct Open {
    version: u8,
    my_as: byteorder::U16<NetworkEndian>,
    hold_time: byteorder::U16<NetworkEndian>,
    bgp_identifier: [u8; 4], 
    opt_param_len: u8,
    optional_parameters: UncheckedOptionalParameters,
}
impl Open {
    pub fn try_from_full_pdu(raw: &[u8]) -> Result<&Open, Cow<'static, str>> {
        if raw.len() < 29 {
            return Err("minimal size of OPEN PDU is 29 bytes".into());
        }
        let Ok((header, _)) = Header::try_ref_from_prefix(&raw.as_ref()) else {
            return Err("invalid header".into());
        };

        if header.marker != [0xff; 16] {
            return Err("invalid marker".into());
        }

        if usize::from(header.length) != raw.len() {
            return Err("length mismatches number of bytes in PDU".into());
        }

        if header.msg_type == MessageType::OPEN {
            Open::try_from_raw(&raw[19..usize::from(header.length)])
        } else {
            Err("not an OPEN".into())
        }
    }
    pub(crate) fn try_from_raw(raw: &[u8]) -> Result<&Open, Cow<'static, str>> {
        // The smallest OPEN has
        // - 10 bytes
        // - + N bytes of optional_parameters
        if raw.len() < 10 {
            return Err("minimal size of OPEN is 19+10".into());
        }

        let res = Open::try_ref_from_bytes(raw).map_err(|e| e.to_string())?;
        if usize::from(res.opt_param_len) > raw.len() - 10 {
            return Err("Optional parameter length exceeds PDU".into());
        }

        Ok(res)
    }

    pub fn try_from_prefix(raw: &[u8]) -> Result<(&Open, &[u8]), Cow<'static, str>> {
        if raw.len() < 29 {
            return Err("minimal size of OPEN PDU is 29 bytes".into());
        }
        let Ok((header, _)) = Header::try_ref_from_prefix(&raw.as_ref()) else {
            return Err("invalid header".into());
        };

        if header.marker != [0xff; 16] {
            return Err("invalid marker".into());
        }

        let msg_len = usize::from(header.length);
        if msg_len > raw.len() {
            return Err("invalid length, exceeds PDU".into());
        }

        if msg_len < 29 {
            return Err("invalid length, too small for valid OPEN".into());
        }

        if header.msg_type == MessageType::OPEN {
            Ok(
                (
                    Open::try_from_raw(&raw[19..msg_len])?,
                    &raw[msg_len-1..]
                )
            )
        } else {
            Err("not an OPEN".into())
        }

    }

    pub fn capabilities(&self) -> impl Iterator<Item = Result<&RawCapability, &[u8]>> {
        UncheckedOptionalParameterIter {
            raw: self.optional_parameters.as_bytes(),
        }.filter_map(|opt|
            opt.ok().filter(|opt|
                opt.parameter_type == OptionalParameterType::CAPABILITIES
            )
        ).map(|caps| UncheckedCapabilityIter { raw: &caps.value } ).flatten()
    }
}


#[derive(IntoBytes, TryFromBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct UncheckedOptionalParameters {
    optional_parameters: [u8],
}

#[derive(IntoBytes, FromBytes, KnownLayout, Immutable)]
#[derive(Copy, Clone, Eq, PartialEq)]
#[repr(C, packed)]
pub struct OptionalParameterType(u8);
impl OptionalParameterType {
    pub const CAPABILITIES: Self = Self(2);
}

#[derive(TryFromBytes, Immutable, KnownLayout, IntoBytes)]
#[repr(C, packed)]
pub struct RawOptionalParameter {
    parameter_type: OptionalParameterType,
    length: u8,
    value: [u8],
}


#[repr(C, packed)]
pub struct UncheckedOptionalParameterIter<'a> {
    raw: &'a [u8],
}

impl<'a> Iterator for UncheckedOptionalParameterIter<'a> {
    type Item = Result<&'a RawOptionalParameter, &'a [u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.raw.is_empty() {
            return None;
        }

        // Not enough bytes for an actual Optional Parameter
        if self.raw.len() < 2 {
            let res = Some(Err(self.raw));
            self.raw = &[];
            return res;
        }

        let len = usize::from(self.raw[1]);
        
        // Length of this Optional Parameter exceeds the PDU
        if 2 + len > self.raw.len() {
            let res = Some(Err(self.raw));
            self.raw = &[];
            return res;
        }

        let res = RawOptionalParameter::try_ref_from_bytes(&self.raw[..2+len])
            .map_err(|_| self.raw);

        self.raw = &self.raw[2+len..];

        Some(res)
    }
}



#[derive(IntoBytes, FromBytes, KnownLayout, Immutable)]
#[derive(Copy, Clone, Eq, PartialEq)]
#[repr(C, packed)]
pub struct CapabilityType(u8);
impl CapabilityType {
    pub const MULTI_PROTOCOL: Self = Self(1);
    pub const ROUTE_REFRESH: Self = Self(2);
    pub const OUTBOUND_ROUTE_FILTERING: Self = Self(3);
    pub const MULTIPLE_LABELS: Self = Self(8);
    pub const BGP_ROLE: Self = Self(9);
    pub const GRACEFUL_RESTART: Self = Self(64);
    pub const FOUR_OCTET_ASN: Self = Self(65);
    pub const ADD_PATH: Self = Self(69);
    pub const ENHANCED_ROUTE_REFRESH: Self = Self(70);
}

#[derive(TryFromBytes, Immutable, KnownLayout, IntoBytes)]
#[repr(C, packed)]
pub struct RawCapability {
    capability_type: CapabilityType,
    length: u8,
    value: [u8],
}

//#[repr(C, packed)]
pub struct UncheckedCapabilityIter<'a> {
    raw: &'a [u8],
}

impl<'a> Iterator for UncheckedCapabilityIter<'a> {
    type Item = Result<&'a RawCapability, &'a [u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.raw.is_empty() {
            return None;
        }

        // Not enough bytes for an actual Capability
        if self.raw.len() < 2 {
            let res = Some(Err(self.raw));
            self.raw = &[];
            return res;
        }

        let len = usize::from(self.raw[1]);
        
        // Length of this Capability exceeds the Optional Parameter
        if 2 + len > self.raw.len() {
            let res = Some(Err(self.raw));
            self.raw = &[];
            return res;
        }

        let res = RawCapability::try_ref_from_bytes(&self.raw[..2+len])
            .map_err(|_| self.raw);

        self.raw = &self.raw[2+len..];

        Some(res)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn single_capabilities() {
        // BGP OPEN with 5 optional parameters, all Capability
        let buf = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x39, 0x01, 0x04, 0x5b, 0xa0, 0x00, 0xb4,
            0x0a, 0x00, 0x00, 0x03, 0x1c, 0x02, 0x06, 0x01,
            0x04, 0x00, 0x01, 0x00, 0x01, 0x02, 0x02, 0x80,
            0x00, 0x02, 0x02, 0x02, 0x00, 0x02, 0x02, 0x46,
            0x00, 0x02, 0x06, 0x41, 0x04, 0x00, 0x64, 0x00,
            0x64
        ];

        let open = Open::try_from_full_pdu(&buf).unwrap();

        assert_eq!(open.capabilities().count(), 5);
        assert!(
            open.capabilities().map(|c| c.unwrap().capability_type).eq([
                CapabilityType::MULTI_PROTOCOL,
                CapabilityType(128),
                CapabilityType::ROUTE_REFRESH,
                CapabilityType::ENHANCED_ROUTE_REFRESH,
                CapabilityType::FOUR_OCTET_ASN,
            ])
        );
    }

    #[test]
    fn multiple_capabilities() {
        // BGP OPEN with one Optional Parameter of type Capability,
        // containing 8 Capabilities.
        let buf = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x51, 0x01, 0x04, 0xfb, 0xf0, 0x00, 0xb4,
            0xc0, 0x00, 0x02, 0x01, 0x34, 0x02, 0x32, 0x02,
            0x00, 0x46, 0x00, 0x41, 0x04, 0x00, 0x00, 0xfb,
            0xf0, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x01,
            0x04, 0x00, 0x02, 0x00, 0x04, 0x08, 0x04, 0x00,
            0x02, 0x04, 0x0d, 0x40, 0x0a, 0xc0, 0x78, 0x00,
            0x01, 0x01, 0x00, 0x00, 0x02, 0x04, 0x00, 0x45,
            0x08, 0x00, 0x01, 0x01, 0x01, 0x00, 0x02, 0x04,
            0x01
        ];

        let open = Open::try_from_full_pdu(&buf).unwrap();

        assert_eq!(open.capabilities().count(), 8);

        assert!(
            open.capabilities().map(|c| c.unwrap().capability_type).eq([
                CapabilityType::ROUTE_REFRESH,
                CapabilityType::ENHANCED_ROUTE_REFRESH,
                CapabilityType::FOUR_OCTET_ASN,
                CapabilityType::MULTI_PROTOCOL,
                CapabilityType::MULTI_PROTOCOL,
                CapabilityType::MULTIPLE_LABELS,
                CapabilityType::GRACEFUL_RESTART,
                CapabilityType::ADD_PATH,
            ])
        );
    }
}
