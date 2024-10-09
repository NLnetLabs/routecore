use crate::bgp::message::{Header, MsgType};
use inetnum::asn::Asn;
use crate::bgp::types::{AfiSafiType, AddpathFamDir, AddpathDirection};
use crate::typeenum; // from util::macros
use crate::util::parser::ParseError;
use log::warn;
use octseq::{FreezeBuilder, Octets, OctetsBuilder, Parser, ShortBuf, Truncate};

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

const COFF: usize = 19; // XXX replace this with .skip()'s?

const AS_TRANS: u16 = 23456;

/// BGP OPEN message, variant of the [`Message`] enum.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenMessage<Octets> {
    octets: Octets,
}

// ---BGP Open----------------------------------------------------------------

/// BGP OPEN Message.
///
/// Offers methods to access and/or iterate over all the fields, and some
/// additional convenience methods.
///
/// ## Convenience methods
///
/// * [`my_asn()`][`OpenMessage::my_asn`]: returns the 32bit ASN if present,
///   otherwise falls back to the conventional 16bit ASN (though represented
///   as the 32bit [`inetnum::asn::Asn`][`Asn`]);
/// * [`multiprotocol_ids()`][`OpenMessage::multiprotocol_ids`]: returns an
///   iterator over all the AFI/SAFI combinations listed as Capability in the
///   Optional Parameters. If this yields an empty iterator, one can assume
///   the default (IPv4/Unicast) can be used, but it is up to the user to
///   handle as such.
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+
//  |    Version    |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     My Autonomous System      |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |           Hold Time           |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                         BGP Identifier                        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  | Opt Parm Len  |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                                                               |
//  |             Optional Parameters (variable)                    |
//  |                                                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
impl<Octs: Octets> OpenMessage<Octs> {
    pub fn for_slice(s: Octs) -> Self {
        OpenMessage { octets: s }
    }

    pub fn octets(&self) -> &Octs {
        &self.octets
    }
}

impl<Octs: Octets> OpenMessage<Octs> {
    /// Returns the [`Header`] for this message.
    pub fn header(&self) -> Header<Octs::Range<'_>> {
        Header::for_slice(self.octets().range(..19))
    }
    
    /// Returns the length in bytes of the entire BGP message.
	pub fn length(&self) -> u16 {
        self.header().length()
	}
}

impl<Octs: Octets> AsRef<[u8]> for OpenMessage<Octs> {
    fn as_ref(&self) -> &[u8] {
        self.octets().as_ref()
    }
}

impl<Octs: Octets> OpenMessage<Octs> {
    /// Returns the protocol version number, which should be 4.
    pub fn version(&self) -> u8 {
        self.octets.as_ref()[COFF]
    }

    /// Convenience method: returns the `Asn` from the Capabilities if any,
    /// otherwise the two-octet Asn from the 'My Autonomous System' field.
    pub fn my_asn(&self) -> Asn {
        if let Some(c) = self.capabilities().find(|c|
            c.typ() == CapabilityType::FourOctetAsn
        ) {
            Asn::from(
                u32::from_be_bytes(
                    c.value()
                .try_into().expect("parsed before"))
            )
        } else {
            self._my_asn()
        }
    }

    /// Returns the proposed value for the Hold Timer.
    pub fn holdtime(&self) -> u16 {
        u16::from_be_bytes([
            self.octets.as_ref()[COFF+3],
            self.octets.as_ref()[COFF+4]
        ])
    }

    /// Returns the BGP Identifier in raw format.
    pub fn identifier(&self) -> &[u8] {
        &self.octets.as_ref()[COFF+5..COFF+9]
    }

    /// Returns the length of the Optional Parameters. If 0, there are no
    /// Optional Parameters in this BGP OPEN message.
    pub fn opt_parm_len(&self) -> u8 {
        self.octets.as_ref()[COFF+9]
    }

    /// Returns an iterator over the Optional Parameters.
    pub fn parameters(&self) -> ParametersParser<Octs> {
        self.parameters_iter()
    }

    fn parameters_iter(&self) -> ParametersParser<Octs> {
        let mut p = Parser::from_ref(&self.octets); 
        p.advance(COFF+10).unwrap();

        ParametersParser {
            parser: p.parse_parser(self.opt_parm_len() as usize).unwrap()
        }
    }

    /// Returns an iterator over the Capabilities
    // Multiple Capabilities can be carried in a single Optional Parameter, or
    // multiple individual Optional Parameters can carry a single Capability
    // each. Hence the flatten.
	pub fn capabilities(&self)
        -> impl Iterator<Item = Capability<Octs::Range<'_>>>
    {
        self.parameters_iter().filter(|p|
            p.typ() == OptionalParameterType::Capabilities
        ).flat_map(|p|
            p.into_capability_iter()
        )
	}

    // This is the conventional, two-octet Asn. Possibly, the Capabilities at
    // the end of the OPEN message list the actual (4-byte) ASN.
    // If so, and the 4-byte ASN is non-mappable (i.e it can not be
    // represented in 2 bytes), the ASN field here should contain AS_TRANS.
    // We do however not check or enforce that.
    fn _my_asn(&self) -> Asn {
        Asn::from(
            u16::from_be_bytes([
                self.octets.as_ref()[COFF+1],
                self.octets.as_ref()[COFF+2]
            ]) as u32
        )
    }

    /// Returns true if this message contains the Four-Octet-Capable
    /// capability in the Optional Parameters.
    pub fn four_octet_capable(&self) -> bool {
        self.capabilities().any(|c|
            c.typ() == CapabilityType::FourOctetAsn
        )
    }

    pub fn addpath_families_vec(&self)
        -> Result<Vec<(AfiSafiType, AddpathDirection)>, ParseError>
    {
        let mut res = vec![];
        for c in self.capabilities().filter(|c|
            c.typ() == CapabilityType::AddPath
        ) {
            for c in c.value().chunks(4) {
                let mut parser = Parser::from_ref(c);

                let afi = parser.parse_u16_be()?;
                let safi = parser.parse_u8()?;
                let dir = AddpathDirection::try_from(parser.parse_u8()?)
                    .map_err(|_| ParseError::Unsupported)?;
                res.push((AfiSafiType::from((afi, safi)), dir));
            }
        }
        Ok(res)
    }

    /// Merge exchanged ADDPATH capabilities from our perspective.
    ///
    /// Note that depending on the directions (Send, Receive, or SendReceive)
    /// for the address families, we might up with a unidirectional ADDPATH
    /// enabled session. For example, if we announce only Receive, and the
    /// other side announces SendReceive, we must not send out prefixes with
    /// Path IDs.
    ///
    /// Calling `msg1.addpath_intersection(msg2)` might give a different
    /// result than `msg2.addpath_intersection(msg1)`.
    pub fn addpath_intersection<O: Octets>(&self, other: &OpenMessage<O>)
        -> Vec<AddpathFamDir>
    {
        let (Ok(mine), Ok(other)) =
            (self.addpath_families_vec(), other.addpath_families_vec()) else {
            return vec![];
        };

        mine.iter().filter_map(|(my_fam, my_dir)| {
            other.iter().find(|(f, _d)| {
                my_fam == f
            }).and_then(|(_f, other_dir)| {
                my_dir.merge(*other_dir)
            }).map(|m| AddpathFamDir::new(*my_fam, m))
        }).collect::<Vec<_>>()
    }

    /// Returns an iterator over `AfiSafiType`s listed as MultiProtocol
    /// Capabilities in the Optional Parameters of this message.
    pub fn multiprotocol_ids(&self) -> impl Iterator<Item = AfiSafiType> + '_ {
        self.capabilities().filter(|c|
            c.typ() == CapabilityType::MultiProtocol
        ).map(|mp_cap| {
            let afi = u16::from_be_bytes([
                mp_cap.value()[0],
                mp_cap.value()[1]
            ]);
            let safi = mp_cap.value()[3];
            (afi, safi).into()
        })
    }

}


impl<Octs: Octets> OpenMessage<Octs> {
    /// Create an OpenMessage from an octets sequence.
    pub fn from_octets(octets: Octs) -> Result<Self, ParseError> {
        OpenMessage::check(octets.as_ref())?;
        Ok( OpenMessage { octets } )
    }
}

impl<Octs: Octets> OpenMessage<Octs> {
    fn check(octets: Octs) -> Result<(), ParseError> {
        let mut parser = Parser::from_ref(&octets);
        Header::check(&mut parser)?;
        // jump over version, 2-octet ASN, Hold timer and BGP ID
        parser.advance(1 + 2 + 2 + 4)?;
        let opt_param_len = parser.parse_u8()? as usize;
        let mut param_parser = parser.parse_parser(opt_param_len)?;

        while param_parser.remaining() > 0 {
            Parameter::check(&mut param_parser)?;
        }

        if parser.remaining() > 0 {
            return Err(ParseError::form_error("trailing bytes"));
        }

        Ok(())

    }
}

impl<Octs: Octets> OpenMessage<Octs> {
    // used in bmp/message.rs still
    pub fn parse<'a>(parser: &mut Parser<'a, Octs>)
        -> Result<OpenMessage<Octs::Range<'a>>, ParseError>
    {
        // parse header
        let pos = parser.pos();
        let hdr = Header::parse(parser)?;

        let _version = parser.parse_u8()?;
        let _my_as = parser.parse_u16_be()?;
        let _hold_timer = parser.parse_u16_be()?;
        let _bgp_id = parser.parse_u32_be()?;

        let mut opt_param_len = parser.parse_u8()? as usize;
        if opt_param_len > parser.remaining() {
            return Err(
                ParseError::ShortInput
            );
        }

        while opt_param_len > 0 {
            let param = Parameter::parse(parser)?;
            opt_param_len -= 2 + param.length() as usize;
        }

        let end = parser.pos();
        if end - pos != hdr.length() as usize {
            return Err(ParseError::form_error(
                "message length and parsed bytes do not match"
            ));
        }
        parser.seek(pos)?;
        Ok(
            OpenMessage { octets: parser.parse_octets(hdr.length().into())? }
        )
    }
}

impl<Octs: Octets> Parameter<Octs> {
    // XXX still used in bmp/message.rs
    pub fn parse<'a, R>(parser: &mut Parser<'a, R>)
        -> Result<Self, ParseError>
    where
        R: Octets<Range<'a> = Octs>
    {
        let pos = parser.pos();
        let typ = parser.parse_u8()?;
        let len = parser.parse_u8()? as usize;
        if typ == 2 {
            // There might be more than Capability within a single Optional
            // Parameter, so we need to loop.
            while parser.pos() < pos + len {
                Capability::parse(parser)?;
            }
        } else {
            warn!("Optional Parameter in BGP OPEN other than Capability: {}",
                typ
            );
        }
        parser.seek(pos)?;
        Ok(
            Self::for_slice(
                parser.parse_octets(2+len)?
            )
        )
    }
}

impl<Octs: Octets> Parameter<Octs> {
    fn check(parser: &mut Parser<Octs>) -> Result<(), ParseError> {
        let typ = parser.parse_u8()?;
        let len = parser.parse_u8()? as usize;
        if typ == 2 {
            // There might be more than Capability within a single Optional
            // Parameter, so we need to loop.
            let mut caps_parser = parser.parse_parser(len)?;
            while caps_parser.remaining() > 0 {
                Capability::check(&mut caps_parser)?;
            }
        } else {
            warn!("Optional Parameter in BGP OPEN other than Capability: {}",
                typ
            );
        }
        Ok(())
    }
}

impl<Octs: Octets> Capability<Octs> {
    fn check(parser: &mut Parser<Octs>) -> Result<(), ParseError> {
        let _typ = parser.parse_u8()?;
        let len = parser.parse_u8()? as usize;
        parser.advance(len)?;
        Ok(())
    }
}

impl<Octs: Octets> Capability<Octs> {
    fn parse<'a, Ref>(parser: &mut Parser<'a, Ref>)
        -> Result<Self, ParseError>
    where
        Ref: Octets<Range<'a> = Octs>
    {
        let pos = parser.pos();
        let typ = parser.parse_u8()?;
        let len = parser.parse_u8()? as usize;
        match typ.into() {
            CapabilityType::Reserved => {
                warn!("Capability type Reserved");
            },
            CapabilityType::MultiProtocol => {
                let _afi = parser.parse_u16_be()?;
                let _rsvd = parser.parse_u8()?;
                let _safi = parser.parse_u8()?;
            },
            CapabilityType::RouteRefresh => {
                if len != 0 {
                    return Err(ParseError::form_error(
                            "RouteRefresh Capability with length > 0"
                    ));
                }
            },
            CapabilityType::OutboundRouteFiltering => {
                let _afi = parser.parse_u16_be()?;
                let _rsvd = parser.parse_u8()?;
                let _safi = parser.parse_u8()?;

                let num_orfs = parser.parse_u8()?;
                for _ in 0..num_orfs {
                    let _orf_type = parser.parse_u8()?;
                    let _send_receive = parser.parse_u8()?;
                }
            },
            CapabilityType::ExtendedNextHop => {
                while parser.pos() < pos + len {
                    let _afi = parser.parse_u16_be()?;
                    // Note that SAFI is 2 bytes for this Capability.
                    let _safi = parser.parse_u16_be()?;
                    let _nexthop_afi = parser.parse_u16_be()?;
                }
            },
            CapabilityType::ExtendedMessage => {
                if len != 0 {
                    return Err(ParseError::form_error(
                            "ExtendedMessage Capability with length > 0"
                    ));
                }
            },
            CapabilityType::MultipleLabels => {
                while parser.pos() < pos + len {
                    let _afi = parser.parse_u16_be()?;
                    let _safi = parser.parse_u8()?;
                    let _count = parser.parse_u8()?;
                }
            },
            CapabilityType::BgpRole => {
                if len != 1 {
                    return Err(ParseError::form_error(
                            "ExtendedMessage Capability with length != 1"
                    ));
                }
                let _role = parser.parse_u8()?;
            },
            CapabilityType::GracefulRestart => {
                let _restart_flags_and_time = parser.parse_u16_be()?;
                while parser.pos() < pos + len {
                    let _afi = parser.parse_u16_be()?;
                    let _safi = parser.parse_u8()?;
                    let _flags = parser.parse_u8()?;
                }
            },
            CapabilityType::FourOctetAsn => {
                let _asn = parser.parse_u32_be()?;
            },
            CapabilityType::DeprecatedDynamicCapability 
            | CapabilityType::DynamicCapability => {
                for _ in 0..len {
                    let _cap = parser.parse_u8()?;
                }
            },
            CapabilityType::Multisession => {
                let _flags = parser.parse_u8()?;
                for _ in 0..len-1 {
                    let _session_id = parser.parse_u8()?;
                }
            },
            CapabilityType::AddPath => {
                let _afi = parser.parse_u16_be()?;
                let _safi = parser.parse_u8()?;
                let send_receive = parser.parse_u8()?;
                if send_receive > 3 {
                    return Err(ParseError::form_error(
                            "Capability AddPath send/receive not 1,2 or 3"
                    ))
                }
            },
            CapabilityType::EnhancedRouteRefresh => {
                if len != 0 {
                    return Err(ParseError::form_error(
                            "EnhancedRouteRefresh Capability with length > 0"
                    ));
                }
            },
            CapabilityType::LongLivedGracefulRestart => {
                while parser.pos() < pos + len {
                    let _afi = parser.parse_u16_be()?;
                    let _safi = parser.parse_u8()?;
                    let _flags = parser.parse_u8()?;
                    // 24 bits of staletime
                    let _ll_staletime_1 = parser.parse_u16_be()?;
                    let _ll_staletime_2 = parser.parse_u8()?;
                }
            },
            CapabilityType::FQDN => {
                let hostname_len = parser.parse_u8()? as usize;
                parser.advance(hostname_len)?;
                let domain_len = parser.parse_u8()? as usize;
                parser.advance(domain_len)?;
            },
            CapabilityType::PrestandardRouteRefresh => {
                if len > 0 {
                    warn!("PrestandardRouteRefresh with len > 0, capture me for testing purposes!");
                    return Err(ParseError::form_error(
                            "PrestandardRouteRefresh len > 0"
                    ));
                }
                while parser.pos() < pos + len {
                    let _afi = parser.parse_u16_be()?;
                    let _safi = parser.parse_u8()?;
                    let _flags = parser.parse_u8()?;
                }
            },
            CapabilityType::PrestandardOutboundRouteFiltering => {
                let _afi = parser.parse_u16_be()?;
                let _rsvd = parser.parse_u8()?;
                let _safi = parser.parse_u8()?;

                let num_orfs = parser.parse_u8()?;
                for _ in 0..num_orfs {
                    let _orf_type = parser.parse_u8()?;
                    let _send_receive = parser.parse_u8()?;
                }
            },
            CapabilityType::PrestandardMultisession => {
                let _flags = parser.parse_u8()?;
                for _ in 0..len-1 {
                    let _session_id = parser.parse_u8()?;
                }
            }
            CapabilityType::Unimplemented(u) => {
                warn!("Unimplemented Capability: {}", u);
            },
        }

        parser.seek(pos)?;
        Ok(
            Self::for_slice(
                parser.parse_octets(2+len)?
            )
        )
    }
}


//--- Helpers / types related to BGP OPEN ------------------------------------

/// BGP Capability Optional parameter.
// As per RFC3392:
//
//  +------------------------------+
//  | Capability Code (1 octet)    |
//  +------------------------------+
//  | Capability Length (1 octet)  |
//  +------------------------------+
//  | Capability Value (variable)  |
//  +------------------------------+
//
// Also see
// <https://www.iana.org/assignments/capability-codes/capability-codes.xhtml>

#[derive(Clone, Debug)]
pub struct Capability<Octs> {
    octets: Octs,
}

impl<Octs: Octets> Capability<Octs> {
    fn for_slice(octets: Octs) -> Capability<Octs> {
        Capability { octets }
    }

    pub fn new(octets: Octs) -> Self {
        Capability { octets }
    }

    /// Returns the [`CapabilityType`] of this capability.
    pub fn typ(&self) -> CapabilityType {
        self.octets.as_ref()[0].into()
    }

    pub fn length(&self) -> u8 {
        self.octets.as_ref()[1]
    }

    pub fn value(&'_ self) -> &'_ [u8] {
        &self.octets.as_ref()[2..]
    }
}

impl<Octs: Octets> AsRef<[u8]> for Capability<Octs> {
    fn as_ref(&self) -> &[u8] {
        self.octets.as_ref()
    }
}

/// Iterator for BGP OPEN Capabilities.
pub struct CapabilitiesIter<'a, Ref> {
    parser: Parser<'a, Ref>,
}

impl<'a, Ref: Octets> Iterator for CapabilitiesIter<'a, Ref> {
    type Item = Capability<Ref::Range<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None;
        }
        Some(Capability::parse(&mut self.parser).unwrap())
    }
}

// Optional Parameter
// 0                   1
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...
// |  Parm. Type   | Parm. Length  |  Parameter Value (variable)
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...
//
// also see
// https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-11
/// BGP OPEN Optional Parameter.
pub struct Parameter<Octets> {
    octets: Octets,
}

/// Iterator over BGP OPEN Optional [`Parameter`]s.
pub struct ParametersParser<'a, Ref> {
    parser: Parser<'a, Ref>
}

pub struct ParameterParser<'a, Ref> {
    typ: OptionalParameterType,
    parser: Parser<'a, Ref>
}

impl<'a, Ref> ParameterParser<'a, Ref> {
    fn into_capability_iter(self) -> CapabilitiesIter<'a, Ref> {
        CapabilitiesIter { parser: self.parser }
    }

    /// Returns the parameter type.
    pub fn typ(&self) -> OptionalParameterType {
        self.typ
    }
}

impl<Octs: Octets> Parameter<Octs> {
    /// Returns the parameter type.
    pub fn typ(&self) -> OptionalParameterType {
        self.octets.as_ref()[0].into()
    }
    
    /// Returns the parameter length.
    pub fn length(&self) -> u8 {
        self.octets.as_ref()[1]
    }
}

impl<Octs: Octets> Parameter<Octs> {
    pub fn for_slice(slice: Octs) -> Self {
        Parameter { octets: slice }
    }
}

impl<Octs: Octets> Parameter<Octs> {
    /// Returns the raw value of the parameter.
    pub fn value(&self) -> Octs::Range<'_> {
        self.octets.range(2..)
    }
}

impl<'a, Ref: Octets> Iterator for ParametersParser<'a, Ref> {
    type Item = ParameterParser<'a, Ref>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None;
        }
        let typ: OptionalParameterType = self.parser.parse_u8().unwrap().into();
        let len = self.parser.parse_u8().unwrap();
        Some(ParameterParser {
                typ,
                parser: self.parser.parse_parser(len as usize).unwrap()
            })
    }
}

//--- Types ------------------------------------------------------------------

typeenum!(
/// BGP Capability type, as per
/// <https://www.iana.org/assignments/capability-codes/capability-codes.xhtml>.
    CapabilityType, u8,
    {
        0 => Reserved,
        1 => MultiProtocol,
        2 => RouteRefresh,
        3 => OutboundRouteFiltering,
        5 => ExtendedNextHop,
        6 => ExtendedMessage,
        8 => MultipleLabels,
        9 => BgpRole,
        //10..=63 => Unassigned,
        64 => GracefulRestart,
        65 => FourOctetAsn,
        66 => DeprecatedDynamicCapability,
        67 => DynamicCapability,
        68 => Multisession,
        69 => AddPath,
        70 => EnhancedRouteRefresh,
        71 => LongLivedGracefulRestart,
        73 => FQDN,
        128 => PrestandardRouteRefresh,
        130 => PrestandardOutboundRouteFiltering,
        131 => PrestandardMultisession,
    }
);

typeenum!(
/// BGP OPEN Optional Parameter type, as per
/// <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-11>.
    OptionalParameterType, u8,
    {
        0 => Reserved,
        1 => Authentication,
        2 => Capabilities,
        255 => ExtendedLength
    },
    {
        3..=254 => Unassigned,
    }
);


//--- Builder ----------------------------------------------------------------


#[derive(Debug)]
pub struct OpenBuilder<Target> {
    target: Target,
    capabilities: Vec<Capability<Vec<u8>>>,
    addpath_families: Vec<(AfiSafiType, AddpathDirection)>,
}

use core::convert::Infallible;
impl<Target: OctetsBuilder + Truncate> OpenBuilder<Target>
where
    Infallible: From<<Target as OctetsBuilder>::AppendError>
{
    pub fn from_target(mut target: Target) -> Result<Self, ShortBuf> {
        //target.truncate(0);
        let mut h = Header::<&[u8]>::new();
        h.set_length(29);
        h.set_type(MsgType::Open);
        let _ =target.append_slice(h.as_ref());

        // BGP version
        let _ =target.append_slice(&[4]);

         // Prepare space for the mandatory ASN, holdtime, bgp_id.
        let _ =target.append_slice(&[0; 8]);

        // opt param len is set in finish()

        Ok(
            OpenBuilder {
                target,
                capabilities: Vec::<Capability<_>>::new(),
                addpath_families: Vec::new(),
            }
        )
    }
}


impl<Target: OctetsBuilder + AsMut<[u8]>> OpenBuilder<Target> {
    pub fn set_asn(&mut self, asn: Asn) {
        // XXX should we call set_four_octet_asn from here as well?
        let asn = u16::try_from(asn.into_u32()).unwrap_or(AS_TRANS);
        self.target.as_mut()[COFF+1..=COFF+2]
            .copy_from_slice(&asn.to_be_bytes());
    }

    pub fn set_holdtime(&mut self, holdtime: u16) {
        self.target.as_mut()[COFF+3..=COFF+4]
            .copy_from_slice(&holdtime.to_be_bytes());
    }

    pub fn set_bgp_id(&mut self, id: [u8; 4]) {
        self.target.as_mut()[COFF+5..=COFF+8]
            .copy_from_slice(&id);
    }

    //pub fn append_optional_parameter(&mut self, opt: OptionalParameterType);
    
    pub fn add_capability(&mut self, cap: Capability<Vec<u8>>) {
        // keep a vec of capabilities
        // append cap in that vec
        // update opt param len
        // wrap it in a single opt param on build()
        self.capabilities.push(cap);
    }

    pub fn four_octet_capable(&mut self, asn: Asn) {
        let mut s = vec![0x41, 0x04];
        s.extend_from_slice(&asn.to_raw());
        self.add_capability(Capability::for_slice(s.to_vec()));
    }

    pub fn add_mp(&mut self, afisafi: AfiSafiType) {
        // code 1
        // length n
        // 2 bytes AFI, rsrvd byte, 1 byte SAFI

        let (afi, safi) = afisafi.into();
        let mut s = vec![0x01, 0x04];
        s.extend_from_slice(&afi.to_be_bytes()[..]);
        s.extend_from_slice(&[0x00, safi]);

        self.add_capability(Capability::<Vec<u8>>::for_slice(s));
    }

    pub fn add_addpath(&mut self, afisafi: AfiSafiType, dir: AddpathDirection) {
        self.addpath_families.push((afisafi, dir));
    }
}

impl<Target: OctetsBuilder + AsMut<[u8]>> OpenBuilder<Target>
where Infallible: From<<Target as OctetsBuilder>::AppendError>
{
    pub fn finish(mut self) -> Target {

        if !self.addpath_families.is_empty() {
            let addpath_cap_len = 4 * self.addpath_families.len();
            let mut addpath_cap = Vec::<u8>::with_capacity(addpath_cap_len);

            addpath_cap.extend_from_slice(
            // XXX throw a ComposeError or equivalent after refactoring the
            // builder.
                &[69,
                  addpath_cap_len.try_into().unwrap_or(u8::MAX)
                ]
            );

            for (afisafi, dir) in self.addpath_families.iter() {
                addpath_cap.extend_from_slice(&afisafi.as_bytes());
                addpath_cap.extend_from_slice(&[u8::from(*dir)]);
            }
            self.add_capability(Capability::new(addpath_cap));
        }

        let mut cap_len = 0u8;
        for c in &self.capabilities {
            cap_len += c.as_ref().len() as u8;
        }
        let mut opt_param_len = 0u8;

        if cap_len > 0 {
            opt_param_len += cap_len + 2;
        }

        let _ = self.target.append_slice(&[opt_param_len]);
        if opt_param_len > 0 {
            let _ = self.target.append_slice(&[0x02, cap_len]);
            for c in self.capabilities {
                let _ = self.target.append_slice(c.as_ref());
            }
        }

        let msg_len = 29 + opt_param_len as u16;
        self.target.as_mut()[16..=17].copy_from_slice( &(msg_len.to_be_bytes()) );
        self.target
    }

    pub fn into_message(
        self
    ) -> OpenMessage<<Target as FreezeBuilder>::Octets>
    where Target: FreezeBuilder {
        OpenMessage{ octets: self.finish().freeze() }
    }
}

impl OpenBuilder<Vec<u8>> {
    pub fn new_vec() -> Self {
        Self::from_target(Vec::with_capacity(29)).unwrap()
    }
}


//--- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;

    use bytes::Bytes;

    use crate::bgp::message::Message;

    #[test]
    fn no_optional_parameters() {
        // BGP OPEN message, 2-octet ASN 64496, no opt params
        let buf = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x1d, 0x01, 0x04, 0xfb, 0xf0, 0x00, 0x5a,
            0xc0, 0x00, 0x02, 0x01, 0x00
        ];

        let bb = Bytes::from(buf);

        //let open: OpenMessage<_> = parse_open(&buf);
        //let open: OpenMessage<_> = Message::from_octets(&buf, None).unwrap().try_into().unwrap();
        let open: OpenMessage<_> = Message::from_octets(bb, None).unwrap().try_into().unwrap();

        assert_eq!(open.length(), 29);
        assert_eq!(open.version(), 4);
        assert_eq!(open.my_asn(), Asn::from(64496));
        assert_eq!(open.holdtime(), 90);
        assert_eq!(open.identifier(), &[192, 0, 2, 1]);
        assert_eq!(open.opt_parm_len(), 0);
        assert_eq!(open.parameters().count(), 0);
    }

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

        //let open: OpenMessage<_> = parse_msg(&buf);
        let open: OpenMessage<_> = Message::from_octets(buf, None).unwrap().try_into().unwrap();

        assert_eq!(open.capabilities().count(), 5);
        let mut iter = open.capabilities();
        let cap1 = iter.next().unwrap();
        assert_eq!(cap1.typ(), CapabilityType::MultiProtocol);

        let cap2 = iter.next().unwrap();
        assert_eq!(cap2.typ(), CapabilityType::PrestandardRouteRefresh);

        let cap3 = iter.next().unwrap();
        assert_eq!(cap3.typ(), CapabilityType::RouteRefresh);

        let cap4 = iter.next().unwrap();
        assert_eq!(cap4.typ(), CapabilityType::EnhancedRouteRefresh);

        let cap5 = iter.next().unwrap();
        assert_eq!(cap5.typ(), CapabilityType::FourOctetAsn);

        assert!(iter.next().is_none());
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

        //let open: OpenMessage<_> = parse_msg(&buf);
        let open: OpenMessage<_> = Message::from_octets(&buf, None).unwrap().try_into().unwrap();

        assert_eq!(open.capabilities().count(), 8);
        let types = [
            CapabilityType::RouteRefresh,
            CapabilityType::EnhancedRouteRefresh,
            CapabilityType::FourOctetAsn,
            CapabilityType::MultiProtocol,
            CapabilityType::MultiProtocol,
            CapabilityType::MultipleLabels,
            CapabilityType::GracefulRestart,
            CapabilityType::AddPath,
        ];
        for (cap, cap_type) in open.capabilities().zip(types.iter()) {
            assert_eq!(cap.typ(), *cap_type);
        }

        open.capabilities().zip(types.iter()).for_each(|(cap, cap_type)|{
            assert_eq!(cap.typ(), *cap_type);
        });

    }

    #[test]
    fn multiple_multiprotocol() {
        // BGP OPEN message with 15 Multiprotocol capabilities
        let buf = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x9d, 0x01, 0x04, 0x5b, 0xa0, 0x00, 0xb4,
            0xc0, 0x00, 0x02, 0x02, 0x80, 0x02, 0x06, 0x01,
            0x04, 0x00, 0x01, 0x00, 0x01, 0x02, 0x06, 0x01,
            0x04, 0x00, 0x01, 0x00, 0x02, 0x02, 0x06, 0x01,
            0x04, 0x00, 0x01, 0x00, 0x04, 0x02, 0x06, 0x01,
            0x04, 0x00, 0x01, 0x00, 0x80, 0x02, 0x06, 0x01,
            0x04, 0x00, 0x01, 0x00, 0x84, 0x02, 0x06, 0x01,
            0x04, 0x00, 0x01, 0x00, 0x85, 0x02, 0x06, 0x01,
            0x04, 0x00, 0x01, 0x00, 0x86, 0x02, 0x06, 0x01,
            0x04, 0x00, 0x02, 0x00, 0x01, 0x02, 0x06, 0x01,
            0x04, 0x00, 0x02, 0x00, 0x02, 0x02, 0x06, 0x01,
            0x04, 0x00, 0x02, 0x00, 0x04, 0x02, 0x06, 0x01,
            0x04, 0x00, 0x02, 0x00, 0x80, 0x02, 0x06, 0x01,
            0x04, 0x00, 0x02, 0x00, 0x85, 0x02, 0x06, 0x01,
            0x04, 0x00, 0x02, 0x00, 0x86, 0x02, 0x06, 0x01,
            0x04, 0x00, 0x19, 0x00, 0x41, 0x02, 0x06, 0x01,
            0x04, 0x00, 0x19, 0x00, 0x46, 0x02, 0x06, 0x41,
            0x04, 0x00, 0x01, 0x00, 0x00
                ];

        //let open: OpenMessage<_> = parse_msg(&buf);
        let open: OpenMessage<_> = Message::from_octets(&buf, None).unwrap().try_into().unwrap();

        assert_eq!(open.multiprotocol_ids().count(), 15);
        let protocols = [
            AfiSafiType::Ipv4Unicast,
            AfiSafiType::Ipv4Multicast,
            AfiSafiType::Ipv4MplsUnicast,
            AfiSafiType::Ipv4MplsVpnUnicast,
            AfiSafiType::Ipv4RouteTarget,
            AfiSafiType::Ipv4FlowSpec,
            //AfiSafiType::Ipv4FlowSpecVpn,
            AfiSafiType::Unsupported(1, 134),
            AfiSafiType::Ipv6Unicast,
            AfiSafiType::Ipv6Multicast,
            AfiSafiType::Ipv6MplsUnicast,
            AfiSafiType::Ipv6MplsVpnUnicast,
            AfiSafiType::Ipv6FlowSpec,
            //AfiSafiType::Ipv6FlowSpecVpn,
            AfiSafiType::Unsupported(2, 134),
            AfiSafiType::L2VpnVpls,
            AfiSafiType::L2VpnEvpn,
        ];

        for (id, protocol) in open.multiprotocol_ids().zip(
            protocols.iter()
            ){
            assert_eq!(id, *protocol);
        }

    }

    #[test]
    fn multiple_addpath_single_cap() {
        // BGP OPEN with 1 optional parameter, Capability ADDPATH
        let buf = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 41, 0x01, 0x04, 0x5b, 0xa0, 0x00, 0xb4,
            0x0a, 0x00, 0x00, 0x03,
            0x0c,
            0x02, 0x0a, 69, 0x08,
            0x00, 0x01, 0x01, 0x03,
            0x00, 0x02, 0x01, 0x03,
        ];

        let open = OpenMessage::from_octets(buf).unwrap();

        assert_eq!(open.capabilities().count(), 1);
        assert!(open.addpath_families_vec().unwrap().iter().eq(
            &[(AfiSafiType::Ipv4Unicast, AddpathDirection::SendReceive),
              (AfiSafiType::Ipv6Unicast, AddpathDirection::SendReceive)]
            )
        );
    }

    #[test]
    fn multiple_addpath_multi_cap() {
        // BGP OPEN with 2 optional parameters, all Capability ADDPATH
        // XXX note that this isn't actually allowed, not sure if it occurs in
        // the wild.
        let buf = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 45, 0x01, 0x04, 0x5b, 0xa0, 0x00, 0xb4,
            0x0a, 0x00, 0x00, 0x03,
            0x10,
            0x02, 0x06, 69, 0x04, 0x00, 0x01, 0x01, 0x03,
            0x02, 0x06, 69, 0x04, 0x00, 0x02, 0x01, 0x03,
        ];

        let open = OpenMessage::from_octets(buf).unwrap();

        assert_eq!(open.capabilities().count(), 2);
        assert!(open.addpath_families_vec().unwrap().iter().eq(
            &[(AfiSafiType::Ipv4Unicast, AddpathDirection::SendReceive),
              (AfiSafiType::Ipv6Unicast, AddpathDirection::SendReceive)]
            )
        );
    }

mod builder {
    use super::*;

    #[test]
    fn builder_16bit_asn() {
        let mut open = OpenBuilder::new_vec();
        open.set_asn(Asn::from_u32(1234));
        open.set_holdtime(180);
        open.set_bgp_id([1, 2, 3, 4]);

        open.add_mp(AfiSafiType::Ipv4Unicast);
        open.add_mp(AfiSafiType::Ipv6Unicast);

        let res = open.into_message();

        assert_eq!(res.my_asn(), Asn::from_u32(1234));
    }

    #[test]
    fn builder_32bit_asn() {
        let mut open = OpenBuilder::new_vec();
        open.set_asn(Asn::from_u32(123123));
        open.set_holdtime(180);
        open.set_bgp_id([1, 2, 3, 4]);

        open.add_mp(AfiSafiType::Ipv4Unicast);
        open.add_mp(AfiSafiType::Ipv6Unicast);

        let res = open.into_message();

        assert_eq!(res.my_asn(), Asn::from_u32(AS_TRANS.into()));
    }

    #[test]
    fn builder_addpath() {
        let mut open = OpenBuilder::new_vec();
        open.set_asn(Asn::from_u32(123123));
        open.set_holdtime(180);
        open.set_bgp_id([1, 2, 3, 4]);

        open.add_mp(AfiSafiType::Ipv4Unicast);
        open.add_mp(AfiSafiType::Ipv6Unicast);
        open.add_addpath(AfiSafiType::Ipv4Unicast, AddpathDirection::SendReceive);
        open.add_addpath(AfiSafiType::Ipv6Unicast, AddpathDirection::SendReceive);

        let res = open.into_message();

        assert_eq!(res.my_asn(), Asn::from_u32(AS_TRANS.into()));
        for ap in res.addpath_families_vec().unwrap().iter() {
            eprintln!("{:?}", ap);
        }
    }


}
}
