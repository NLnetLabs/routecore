use std::fmt;
use std::net::{IpAddr, Ipv6Addr};

use bytes::BytesMut;
use octseq::{EmptyBuilder, FreezeBuilder, Octets, OctetsBuilder, OctetsFrom, ShortBuf};
use log::warn;

use crate::bgp::aspath::HopPath;
use crate::bgp::communities::StandardCommunity;
use crate::bgp::message::{Header, MsgType, UpdateMessage, SessionConfig};
use crate::bgp::nlri::afisafi::{AfiSafiNlri, NlriParse, NlriCompose};
use crate::bgp::path_attributes::{Attribute, PaMap, PathAttributeType};
use crate::bgp::types::{AfiSafiType, NextHop};
use crate::util::parser::ParseError;

//------------ UpdateBuilder -------------------------------------------------
#[derive(Debug)]
pub struct UpdateBuilder<Target, A> {
    target: Target,
    //config: AgreedConfig, //FIXME this lives in rotonda_fsm, but that
    //depends on routecore. Sounds like a depedency hell.
    announcements: Option<MpReachNlriBuilder<A>>,
    withdrawals: Option<MpUnreachNlriBuilder<A>>,
    attributes: PaMap,
}

impl<T, A> UpdateBuilder<T, A> {
    const MAX_PDU: usize = 4096; // XXX should come from NegotiatedConfig
}

impl<Target, A> UpdateBuilder<Target, A>
where
    A: AfiSafiNlri + NlriCompose,
    Target: OctetsBuilder + octseq::Truncate,
{

    pub fn from_target(mut target: Target) -> Result<Self, ShortBuf> {
        target.truncate(0);
        let mut h = Header::<&[u8]>::new();
        h.set_length(19 + 2 + 2);
        h.set_type(MsgType::Update);
        let _ = target.append_slice(h.as_ref());

        Ok(UpdateBuilder {
            target,
            announcements: None,
            withdrawals: None,
            attributes: PaMap::empty(),
        })
    }
}

impl<Target, A> UpdateBuilder<Target, A>
where
    A: AfiSafiNlri + NlriCompose,
    Target: EmptyBuilder + OctetsBuilder + octseq::Truncate,
{

    pub fn from_attributes_builder(
        attributes: PaMap,
    ) -> UpdateBuilder<Target, A> {
        let mut res = UpdateBuilder::from_target(Target::empty()).unwrap();
        res.attributes = attributes;
        res
    }

    pub fn from_workshop(
        ws: crate::bgp::workshop::route::RouteWorkshop<A>
    ) -> UpdateBuilder<Target, A> {

        let mut res = Self::from_attributes_builder(ws.attributes().clone());
        let _ = res.add_announcement(ws.into_nlri());

        res
    }

    /// Creates an UpdateBuilder with Path Attributes from an UpdateMessage
    ///
    ///
    pub fn from_update_message<'a, Octs: 'a + Octets>(
        pdu: &'a UpdateMessage<Octs>, 
        _session_config: &SessionConfig,
        target: Target
    ) -> Result<UpdateBuilder<Target, A>, ComposeError>
    where
        Vec<u8>: OctetsFrom<Octs::Range<'a>>
    {
        
        let mut builder = UpdateBuilder::from_target(target)
            .map_err(|_| ComposeError::ShortBuf)?;

        let pa_map = PaMap::from_update_pdu(pdu)?;
        builder.attributes = pa_map;

        Ok(builder)
    }

    //--- Withdrawals

    pub fn add_withdrawal(&mut self, withdrawal: A)
        -> Result<(), ComposeError>
    {
        if let Some(ref mut w) = self.withdrawals.as_mut() {
            w.add_withdrawal(withdrawal);
        } else {
            self.withdrawals = Some(MpUnreachNlriBuilder::from(withdrawal));
        }

        Ok(())
    }

    
    pub fn withdrawals_from_iter<I>(&mut self, withdrawals: I)
        -> Result<(), ComposeError>
    where I: IntoIterator<Item = A>
    {
        withdrawals.into_iter().try_for_each(|w| self.add_withdrawal(w) )?;
        Ok(())
    }
    

    
    pub fn append_withdrawals(&mut self, withdrawals: Vec<A>)
        -> Result<(), ComposeError>
    {
        for w in withdrawals {
            self.add_withdrawal(w)?;
        }

        Ok(())
    }

    //--- Path Attributes

    pub fn set_aspath(&mut self , aspath: HopPath)
        -> Result<(), ComposeError>
    {
        // XXX there should be a HopPath::compose_len really, instead of
        // relying on .to_as_path() first.
        let wireformat = octseq::builder::infallible(
            aspath.to_as_path::<Vec<u8>>()
        );

        if wireformat.compose_len() > u16::MAX.into() {
            return Err(ComposeError::AttributeTooLarge(
                    PathAttributeType::AsPath,
                    wireformat.compose_len()
            ));
        }

        self.attributes.set(aspath);
        Ok(())
    }

    pub fn set_nexthop(&mut self, nexthop: NextHop)
        -> Result<(), ComposeError>
    {
        self.set_mp_nexthop(nexthop)
    }

    pub fn set_mp_nexthop(&mut self, nexthop: NextHop)
        -> Result<(), ComposeError>
    {
        if let Some(ref mut a) = self.announcements.as_mut() {
            a.set_nexthop(nexthop)?;
        } else {
            self.announcements =
                Some(MpReachNlriBuilder::for_nexthop(nexthop))
            ;
        }

        Ok(())
    }

    pub fn set_nexthop_ll_addr(&mut self, addr: Ipv6Addr)
        -> Result<(), ComposeError>
    {
        if let Some(ref mut a) = self.announcements.as_mut() {
            a.set_nexthop_ll_addr(addr);
        } else {
            let nexthop = NextHop::Ipv6LL(Ipv6Addr::from(0), addr);
            self.announcements =
                Some(MpReachNlriBuilder::for_nexthop(nexthop))
            ;
        }

        Ok(())
    }
    

    //--- Announcements

    pub fn add_announcement(&mut self, announcement: A)
        -> Result<(), ComposeError>
    {
        if let Some(ref mut a) = self.announcements.as_mut() {
            a.add_announcement(announcement);
        } else {
            self.announcements =
                Some(MpReachNlriBuilder::for_nlri(announcement))
            ;
        }
        Ok(())
    }

    pub fn announcements_from_iter<I>(&mut self, announcements: I)
        -> Result<(), ComposeError>
    where I: IntoIterator<Item = A>
    {
        announcements.into_iter().try_for_each(|w| self.add_announcement(w))?;
        Ok(())
    }

    pub fn add_announcements_from_pdu<'a, Octs, O>(
        &mut self,
        source: &'a UpdateMessage<Octs>,
        _session_config: &SessionConfig
    )
    where
        A: AfiSafiNlri + NlriCompose + NlriParse<'a, O, Octs, Output = A>,
        Octs: Octets<Range<'a> = O>,
        O: Octets,
    {
        if source.announcements().is_ok_and(|i| i.count() == 0) {
            return;
        }
        if let Some(ref mut a) = self.announcements.as_mut() {
            a.add_announcements_from_pdu::<Octs, O>(source, _session_config);
        } else {
            let mut a = MpReachNlriBuilder::new();
            a.add_announcements_from_pdu::<Octs, O>(source, _session_config);
            self.announcements = Some(a);
        }
    }

    pub fn add_withdrawals_from_pdu<'a, Octs, O>(
        &mut self,
        source: &'a UpdateMessage<Octs>,
        _session_config: &SessionConfig
    )
    where
        A: AfiSafiNlri + NlriCompose + NlriParse<'a, O, Octs, Output = A>,
        Octs: Octets<Range<'a> = O>,
        O: Octets,
    {
        if source.withdrawals().is_ok_and(|i| i.count() == 0) {
            return;
        }
        if let Some(ref mut w) = self.withdrawals.as_mut() {
            w.add_withdrawals_from_pdu::<Octs, O>(source, _session_config);
        } else {
            let mut w = MpUnreachNlriBuilder::new();
            w.add_withdrawals_from_pdu::<Octs, O>(source, _session_config);
            self.withdrawals = Some(w);
        }
    }

    //--- Standard communities

    pub fn add_community(
        &mut self,
        community: StandardCommunity,
    ) -> Result<(), ComposeError> {
        if !self.attributes.contains::<StandardCommunitiesList>() {
            self.attributes.set(StandardCommunitiesList::new());
        }
        let mut builder = self
            .attributes
            .take::<StandardCommunitiesList>()
            .unwrap(); // Just added it, so we know it is there.
        builder.add_community(community);
        self.attributes.set(builder);
        Ok(())
    }
}

impl<Target, A> UpdateBuilder<Target, A>
where
    A: Clone + AfiSafiNlri + NlriCompose
{
    pub fn into_message(self, session_config: &SessionConfig) ->
        Result<UpdateMessage<<Target as FreezeBuilder>::Octets>, ComposeError>
    where
        Target: OctetsBuilder + FreezeBuilder + AsMut<[u8]> + octseq::Truncate,
        <Target as FreezeBuilder>::Octets: Octets
    {
        self.is_valid()?;
        Ok(UpdateMessage::from_octets(
            self.finish(session_config).map_err(|_| ShortBuf)?, session_config,
        )?)
    }

    pub fn attributes(&self) -> &PaMap {
        &self.attributes
    }

    // What is this suppose to do?
    // It basically creates a copy of the PaMap, not an UpdateBuilder?
    pub fn from_map(&self, map: &mut PaMap) -> PaMap {
        let mut pab = PaMap::empty();
        pab.merge_upsert(map);
        pab
    }

    // Check whether the combination of NLRI and attributes would produce a
    // valid UPDATE pdu.
    fn is_valid(&self) -> Result<(), ComposeError> {
        // If we have a builder for MP_REACH_NLRI, it should carry prefixes.
        if self.announcements.as_ref()
            .is_some_and(|b| b.announcements.is_empty())
        {
            return Err(ComposeError::EmptyMpReachNlri);
        }

        if self.withdrawals.as_ref().is_some_and(|b| b.is_empty()) &&
            (
                self.announcements.as_ref().is_some_and(|b| !b.is_empty())
                || !self.attributes.is_empty()
            )
        {
            // Empty MP_UNREACH but other announcements/attributes
            // present, so this is not a valid EoR
            return Err(ComposeError::EmptyMpUnreachNlri);
        }

        Ok(())
    }

    fn calculate_pdu_length(&self, _session_config: &SessionConfig) -> usize {
        // Marker, length and type.
        let mut res: usize = 16 + 2 + 1;

        // TODO we must check where the ipv4 unicast withdrawals/announcements
        // for this session should go: MP attributes or conventional PDU
        // sections?
        // For now, we do everything in MP.
        
       
        // Withdrawals, 2 bytes for length + N bytes for NLRI:
        res += 2; // + self.withdrawals.iter() .fold(0, |sum, w| sum + w.compose_len());

        // Path attributes, 2 bytes for length + N bytes for attributes:
        res += 2 + self.attributes.bytes_len();

        // Manually add in the MP attributes:
        if let Some(mp_reach) = &self.announcements {
            res += mp_reach.compose_len();
        }

        if let Some(mp_unreach) = &self.withdrawals {
            res += mp_unreach.compose_len();
        }

        res
    }

    fn larger_than(&self, max: usize, session_config: &SessionConfig) -> bool {
        // TODO add more 'quick returns' here, e.g. for MpUnreachNlri or
        // conventional withdrawals/announcements.

        if let Some(b) = &self.announcements {
            if b.announcements.len() * 2 > max {
                return true;
            }
        }
        self.calculate_pdu_length(session_config) > max
    }

    /// Compose the PDU, returns the builder if it exceeds the max PDU size.
    ///
    /// Note that `UpdateBuilder` implements `IntoIterator`, which is perhaps
    /// more appropriate for many use cases.
    pub fn take_message(mut self, session_config: &SessionConfig) -> (
        Result<UpdateMessage<<Target as FreezeBuilder>::Octets>, ComposeError>,
        Option<Self>
    )
    where
        Target: Clone + OctetsBuilder + FreezeBuilder + AsMut<[u8]> + octseq::Truncate,
        <Target as FreezeBuilder>::Octets: Octets
    {
        if !self.larger_than(Self::MAX_PDU, session_config) {
            return (self.into_message(session_config), None)

        }

        // It does not fit in a single PDU. Figure out where to split things.
        //
        // Scenarios where we can expect large PDUs:
        // - many withdrawals of an entire RIB (e.g. when a session goes down)
        // - many announcements when a new session is established, or doing a
        // route refresh
        //
        // There might be specific scenarios where both many withdrawals and
        // announcements need to be built. But we should be able to split
        // those up in withdrawal-only and announcement-only PDUs, presumably?

        // Withdrawals come without path attributes. But, MP_UNREACH_NLRI
        // contains (non v4-unicast) withdrawals which are... represented as a
        // path attribute.


        // Scenario 1: many conventional withdrawals
        // If we have any withdrawals, they can go by themselves.
        // First naive approach: we split off at most 450 NLRI. In the extreme
        // case of AddPathed /32's this would still fit in a 4096 PDU.

        // TODO we need to see if, for this session, there is anything that
        // should go into the conventional withdrawals.
        // Note that because we are making the builders generic over (a
        // single) AfiSafiNlri, these parts are probably prone to change
        // anyway.
        
        /*
        if !self.withdrawals.is_empty() {
            //let withdrawal_len = self.withdrawals.iter()
            //    .fold(0, |sum, w| sum + w.compose_len());

            let split_at = std::cmp::min(self.withdrawals.len() / 2,  450);
            let this_batch = self.withdrawals.drain(..split_at);
            let mut builder = Self::from_target(self.target.clone()).unwrap();
            
            builder.withdrawals = this_batch.collect();

            return (builder.into_message(), Some(self));
        }
        */

        // Scenario 2: many withdrawals in MP_UNREACH_NLRI
        // At this point, we have no conventional withdrawals anymore.

        let maybe_pdu = if let Some(ref mut unreach_builder) =
            self.withdrawals
        {
            let mut split_at = 0;
            if !unreach_builder.withdrawals.is_empty() {
                let mut compose_len = 0;
                for (idx, w) in unreach_builder.withdrawals.iter().enumerate()
                {
                    compose_len += w.compose_len();
                    if compose_len > 4000 {
                        split_at = idx;
                        break;
                    }
                }

                let this_batch = unreach_builder.split(split_at);
                let mut builder =
                    UpdateBuilder::from_target(self.target.clone()).unwrap();
                builder.withdrawals = Some(this_batch);

                Some(builder.into_message(session_config))
            } else {
                None
            }
        } else {
            None
        };

        // Bit of a clumsy workaround as we can not return Some(self) from
        // within the if let ... self.attributes.get_mut above
        if let Some(pdu) = maybe_pdu {
            return (pdu, Some(self))
        }

        // TODO: like with conventional withdrawals, handle this case for
        // sessions where ipv4 unicast does not go into MP attributes.
        // Scenario 3: many conventional announcements
        // Similar but different to the scenario of many withdrawals, as
        // announcements are tied to the attributes. At this point, we know we
        // have no conventional withdrawals left, and no MP_UNREACH_NLRI.

        /*
        if !self.announcements.is_empty() {
            let split_at = std::cmp::min(self.announcements.len() / 2, 450);
            let this_batch = self.announcements.drain(..split_at);
            let mut builder = Self::from_target(self.target.clone()).unwrap();

            builder.announcements = this_batch.collect();
            builder.attributes = self.attributes.clone();

            return (builder.into_message(), Some(self));
        }
        */

        // Scenario 4: many MP_REACH_NLRI announcements
        // This is tricky: we need to split the MP_REACH_NLRI attribute, and
        // clone the other attributes.
        // At this point, we have no conventional withdrawals/announcements or
        // MP_UNREACH_NLRI path attribute.

        // FIXME this works, but is still somewhat slow for very large input
        // sets. The first PDUs take longer to construct than the later ones.
        // Flamegraph currently hints at the fn split on MpReachNlriBuilder.

        let maybe_pdu = if let Some(ref mut reach_builder) =
            self.announcements
        {
            let mut split_at = 0;

            let other_attrs_len = self.attributes.bytes_len();
            let limit = Self::MAX_PDU 
                    // marker/len/type, wdraw len, total pa len
                    - (16 + 2 + 1 + 2 + 2)
                    // MP_REACH_NLRI flags/type/len/afi/safi/rsrved, next_hop
                    - 8 - reach_builder.get_nexthop().compose_len()
                    - other_attrs_len;

                if !reach_builder.announcements.is_empty() {
                    let mut compose_len = 0;
                    for (idx, a) in reach_builder.announcements.iter().enumerate() {
                        compose_len += a.compose_len();
                        if compose_len > limit {
                            split_at = idx;
                            break;
                        }
                    }

                    let this_batch = reach_builder.split(split_at);
                    let mut builder = Self::from_target(
                        self.target.clone()
                    ).unwrap();
                    builder.attributes = self.attributes.clone();
                    builder.announcements = Some(this_batch);

                    Some(builder.into_message(session_config))
                } else {
                    None
                }
            } else {
                None
            }
        ;
        if let Some(pdu) = maybe_pdu {
            return (pdu, Some(self))
        }


        // If we end up here, there is something other than
        // announcements/withdrawals causing very large PDUs. The only thing
        // that comes to mind is any type of Communities, but we can not split
        // those without altering the information that the user intends to
        // convey. So, we error out.

        let pdu_len = self.calculate_pdu_length(session_config);
        (Err(ComposeError::PduTooLarge(pdu_len)), None)

    }


    /// Turn the builder into a vec of one or more UpdateMessages.
    ///
    /// Note that `UpdateBuilder` implements `IntoIterator`, which is perhaps
    /// more appropriate for many use cases.
    pub fn into_messages(self, session_config: &SessionConfig) -> Result<
        Vec<UpdateMessage<<Target as FreezeBuilder>::Octets>>,
        ComposeError
    >
    where
        Target: Clone + OctetsBuilder + FreezeBuilder + AsMut<[u8]> + octseq::Truncate,
        <Target as FreezeBuilder>::Octets: Octets
    {
        let mut res = Vec::new();
        let mut remainder = Some(self);
        loop {
            if remainder.is_none() {
                return Ok(res);
            }
            let (pdu, new_remainder) =
                remainder.take().unwrap().take_message(session_config)
            ;
            match pdu {
                Ok(pdu) => {
                    res.push(pdu);
                    remainder = new_remainder;
                }
                Err(e) => {
                    warn!("error in into_messages(): {}", e);
                    return Err(e)
                }
            }
        }
    }

    pub fn into_pdu_iter(self, session_config: &SessionConfig)
        -> PduIterator<'_, Target, A>
    {
        PduIterator { builder: Some(self), session_config }
    }

    fn finish(mut self, session_config: &SessionConfig)
        -> Result<<Target as FreezeBuilder>::Octets, Target::AppendError>
    where
        Target: OctetsBuilder + FreezeBuilder + AsMut<[u8]> + octseq::Truncate,
        <Target as FreezeBuilder>::Octets: Octets
    {
        let total_pdu_len = self.calculate_pdu_length(session_config);
        let mut header = Header::for_slice_mut(self.target.as_mut());
        header.set_length(u16::try_from(total_pdu_len).unwrap());

        // `withdrawals_len` is checked to be <= 4096 or <= 65535
        // so it will always fit in a u16.
        //
        // TODO handle the case where ipv4 unicast does not go into MP.
        // For now, we put everything in MP_UNREACH_NLRI, leaving the
        // conventional withdrawals section empty, i.e. length 0

        self.target.append_slice(&0_u16.to_be_bytes())?;

        //
        /*
        let withdrawals_len = self.withdrawals.iter()
            .fold(0, |sum, w| sum + w.compose_len());
        self.target.append_slice(
            &u16::try_from(withdrawals_len).unwrap().to_be_bytes()
        )?;

        for w in &self.withdrawals {
            match w {
                Nlri::Unicast(b) if b.is_v4() => {
                    b.compose(&mut self.target)?;
                },
                _ => todo!(),
            }
        }
        */

        // TODO we need checks for things like the total attributes length.
        // These happened in other places (in cumbersome ways), but are now
        // gone.
        let mut attributes_len = self.attributes.bytes_len();


        if let Some(ref mp_reach_builder) = self.announcements {
            attributes_len += mp_reach_builder.compose_len();
        }

        if let Some(ref mp_unreach_builder) = self.withdrawals {
            attributes_len += mp_unreach_builder.compose_len();
        }

        let _ = self.target.append_slice(
            &u16::try_from(attributes_len).unwrap().to_be_bytes()
        );

        if let Some(mp_reach_builder) = self.announcements {
            mp_reach_builder.compose(&mut self.target)?;
        }

        if let Some(mp_unreach_builder) = self.withdrawals {
            mp_unreach_builder.compose(&mut self.target)?;
        }

        self.attributes
            .attributes()
            .iter()
            .try_for_each(|(_tc, pa)| pa.compose(&mut self.target))?;


        // XXX Here, in the conventional NLRI field at the end of the PDU, we
        // write IPv4 Unicast announcements. But what if we have agreed to do
        // MP for v4/unicast, should these announcements go in the
        // MP_REACH_NLRI attribute then instead?
        //
        // TODO see note at conventional withdrawals. For now, everything goes
        // into MP.
        /*
        for a in &self.announcements {
            match a {
                Nlri::Unicast(b) if b.is_v4() => {
                        b.compose(&mut self.target)?;
                },
                _ => unreachable!(),
            }
        }
        */

        Ok(self.target.freeze())
    }
}

pub struct PduIterator<'a, Target, A> {
    builder: Option<UpdateBuilder<Target, A>>,
    session_config: &'a SessionConfig,
}

impl<Target, A> Iterator for PduIterator<'_, Target, A>
where
    A: AfiSafiNlri + NlriCompose + Clone,
    Target: Clone + OctetsBuilder + FreezeBuilder + AsMut<[u8]> + octseq::Truncate,
    <Target as FreezeBuilder>::Octets: Octets
{
    type Item = Result<
        UpdateMessage<<Target as FreezeBuilder>::Octets>,
        ComposeError
    >;

    fn next(&mut self) -> Option<Self::Item> {
        self.builder.as_ref()?;
        let (res, remainder) =
            self.builder.take().unwrap().take_message(self.session_config)
        ;
        self.builder = remainder;
        Some(res)
    }

}

// XXX impl IntoIterator seems untrivial because we need to squeeze in a
// lifetime for the &SessionConfig, which the trait does not facilitate.
// The fn into_pdu_iterator()->PduIterator on UpdateBuilder provides
// similar functionality for now.
/*
impl<Target, A: AfiSafiNlri + NlriCompose> IntoIterator for UpdateBuilder<Target, A>
    where
    Target: Clone + OctetsBuilder + FreezeBuilder + AsMut<[u8]> + octseq::Truncate,
    <Target as FreezeBuilder>::Octets: Octets,
    for<'a> Self: 'a
{
    type Item = Result<
        UpdateMessage<<Target as FreezeBuilder>::Octets>,
        ComposeError
    >;
    type IntoIter = PduIterator<'a, Target, A>;

    fn into_iter(self) -> Self::IntoIter {
        PduIterator { builder: Some(self) }
    }
}
*/

impl<A: AfiSafiNlri + NlriCompose> UpdateBuilder<Vec<u8>, A> {
    pub fn new_vec() -> Self {
        UpdateBuilder::from_target(Vec::with_capacity(23)).unwrap()
    }
}

impl<A: AfiSafiNlri + NlriCompose> UpdateBuilder<BytesMut, A> {
    pub fn new_bytes() -> Self {
        Self::from_target(BytesMut::new()).unwrap()
    }
}


//------------ MpReachNlriBuilder --------------------------------------------
// See notes at MpUnreachNlriBuilder, these also apply here.
//
// Additionally, the MpReachNlri attribute contains the nexthop information.
// The nexthop semantics can not always be derived from the AFI/SAFI tuple,
// i.e. for IPv6 unicast the nexthop might contain two addresses (one global
// and one link-local). The global address will always be there, the
// link-local is optional. 
//
// Now whether or not the additional link-local is necessary might not be
// known at the time we build the UPDATE PDU. Therefore we reserve 16 bytes
// for a LL address, to prevent ending up with a PDU larger than the max pdu
// size allowed on the BGP session.


#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct MpReachNlriBuilder<AfiSafi> {
    announcements: Vec<AfiSafi>,
    nexthop: NextHop,
}

impl<A> MpReachNlriBuilder<A> {
    pub fn add_announcements_from_pdu<'a, Octs, O>(
        &mut self,
        source: &'a UpdateMessage<Octs>,
        _session_config: &SessionConfig
    )
    where
        A: AfiSafiNlri + NlriCompose + NlriParse<'a, O, Octs, Output = A>,
        Octs: Octets<Range<'a> = O>,
        O: Octets,
    {
        if let Ok(Some(iter)) = source.typed_announcements::<_, A>() {
            for a in iter {
                self.add_announcement(a.unwrap());
            }
        }
    }
}

impl<A: AfiSafiNlri + NlriCompose> MpReachNlriBuilder<A> {
    pub fn new() -> Self {
        Self {
            announcements: Vec::new(),
            nexthop: NextHop::new(A::afi_safi())
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.announcements.is_empty()
    }

    pub fn for_nlri(nlri: A) -> Self {
        Self {
            announcements: vec![nlri],
            nexthop: NextHop::new(A::afi_safi())
        }
    }

    pub fn for_nexthop(nexthop: NextHop) -> Self {
        Self {
            announcements: Vec::new(),
            nexthop,
        }
    }

    pub fn for_nlri_and_nexthop(nlri: A, nexthop: NextHop) -> Self {
        Self {
            announcements: vec![nlri],
            nexthop,
        }
    }


    pub fn afi_safi(&self) -> AfiSafiType {
        A::afi_safi()
    }

    pub fn add_announcement(&mut self, nlri: A) {
        self.announcements.push(nlri);
    }

    pub fn set_nexthop(&mut self, nexthop: NextHop) -> Result<(), ComposeError> {

        // TODO check whether nexthop is valid for the AfiSafi this builder is
        // generic over
        //if !<AfiSafi>::nh_valid(&nexthop) {
        //{
        //        return Err(ComposeError::IllegalCombination);
        //}

        self.nexthop = nexthop;
        Ok(())
    }

    pub fn set_nexthop_ll_addr(&mut self, addr: Ipv6Addr) {
        match self.nexthop {
            NextHop::Unicast(IpAddr::V6(a)) => {
                self.nexthop = NextHop::Ipv6LL(a, addr);
            }
            NextHop::Ipv6LL(a, _ll) => {
                self.nexthop = NextHop::Ipv6LL(a, addr);
            }
            _ => unreachable!()
        }
    }


    pub(crate) fn get_nexthop(&self) -> &NextHop {
        &self.nexthop
    }

    //--- Composing related

    pub(crate) fn split(&mut self, n: usize) -> Self {
        let this_batch = self.announcements.drain(..n).collect();
        MpReachNlriBuilder {
            announcements: this_batch,
            ..*self
        }
    }

    pub fn value_len(&self) -> usize {
        2 + 1 + 1  // afi, safi + 1 reserved byte
          + self.nexthop.compose_len() 
          + self.announcements.iter().fold(0, |sum, w| sum + w.compose_len())
    }

    pub fn compose_value<Target: OctetsBuilder>(
        &self,
        target: &mut Target
    ) -> Result<(), Target::AppendError>
    {
        target.append_slice(&A::afi_safi().as_bytes())?;
        self.nexthop.compose(target)?;

        // Reserved byte:
        target.append_slice(&[0x00])?;

        for a in &self.announcements {
            a.compose(target)?
        }

        Ok(())
    }
}

impl<A: AfiSafiNlri + NlriCompose> Default for MpReachNlriBuilder<A> {
    fn default() -> Self {
        Self::new()
    }
}

/*
impl MpReachNlriBuilder {
    // MP_REACH_NLRI and MP_UNREACH_NLRI can only occur once (like any path
    // attribute), and can carry only a single tuple of (AFI, SAFI).
    // My interpretation of RFC4760 means one can mix conventional
    // NLRI/withdrawals (so, v4 unicast) with one other (AFI, SAFI) in an
    // MP_(UN)REACH_NLRI path attribute.
    // Question is: can one also put (v4, unicast) in an MP_* attribute, and,
    // then also in the conventional part (at the end of the PDU)? 

    // Minimal required size for a meaningful MP_REACH_NLRI. This comprises
    // the attribute flags/size/type (3 bytes), a IPv6 nexthop (17), reserved
    // byte (1) and then space for at least an IPv6 /48 announcement (7)

    pub(crate) fn new(
        afisafi: AfiSafi,
        nexthop: NextHop,
        addpath_enabled: bool,
    ) -> Self {
        MpReachNlriBuilder {
            announcements: vec![],
            // 3 bytes for AFI+SAFI, nexthop len, reserved byte
            len: 3 + nexthop.compose_len() + 1,
            extended: false,
            afisafi,
            nexthop,
            addpath_enabled
        }
    }

    pub(crate) fn split(&mut self, n: usize) -> Self {
        let this_batch = self.announcements.drain(..n).collect();
        MpReachNlriBuilder {
            announcements: this_batch,
            ..*self
        }
    }

    pub fn new_for_nlri<T>(nlri: &Nlri<T>) -> Self
    where T: Octets,
          Vec<u8>: OctetsFrom<T>
    {
        let addpath_enabled = nlri.is_addpath();
        let nexthop = NextHop::new(nlri.afi_safi());
        Self::new(nlri.afi_safi(), nexthop, addpath_enabled)
    }

    pub(crate) fn value_len(&self) -> usize {
        2 + 1 + 1  // afi, safi + 1 reserved byte
          + self.nexthop.compose_len() 
          + self.announcements.iter().fold(0, |sum, w| sum + w.compose_len())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.announcements.is_empty()
    }

    pub(crate) fn first_nlri(self) -> Option<Nlri<Vec<u8>>> {
        self.announcements.first().cloned()
    }

    pub(crate) fn get_nexthop(&self) -> &NextHop {
        &self.nexthop
    }

    pub(crate) fn set_nlri(&mut self, nlri: Nlri<Vec<u8>>) -> Result<(), ComposeError> {
        self.afisafi = nlri.afi_safi();
        self.addpath_enabled = nlri.is_addpath();
        self.announcements = vec![nlri];
        Ok(())
    }

    pub(crate) fn set_nexthop(&mut self, nexthop: NextHop) -> Result<(), ComposeError> {

        if !self.announcements.is_empty() &&
            !matches!(self.nexthop, _nexthop)
        {
                return Err(ComposeError::IllegalCombination);
        }

        self.len -= self.nexthop.compose_len();
        self.nexthop = nexthop;
        self.len += self.nexthop.compose_len();
        Ok(())
    }

    pub(crate) fn set_nexthop_ll_addr(&mut self, addr: Ipv6Addr) {
        match self.nexthop {
            NextHop::Unicast(IpAddr::V6(a)) => {
                self.nexthop = NextHop::Ipv6LL(a, addr);
                self.len += 16;
            }
            NextHop::Ipv6LL(a, _ll) => {
                self.nexthop = NextHop::Ipv6LL(a, addr);
            }
            _ => unreachable!()
        }
    }

     fn valid_combination<T>(
        &self, nlri: &Nlri<T>
    ) -> bool {
        self.afisafi == nlri.afi_safi()
        && (self.announcements.is_empty()
             || self.addpath_enabled == nlri.is_addpath())
    }

    pub(crate) fn add_announcement<T>(&mut self, announcement: &Nlri<T>)
    where
        T: Octets,
        Vec<u8>: OctetsFrom<T>,
    {
        let announcement_len = announcement.compose_len();
        if !self.extended && self.len + announcement_len > 255 {
            self.extended = true;
        }
        self.len += announcement_len;
        self.announcements.push(
            <&Nlri<T> as OctetsInto<Nlri<Vec<u8>>>>::try_octets_into(announcement).map_err(|_| ComposeError::todo() ).unwrap()
        );
    }

    pub(crate) fn compose_value<Target: OctetsBuilder>(
        &self,
        target: &mut Target
    ) -> Result<(), Target::AppendError>
    {
        //target.append_slice(&u16::from(self.afi).to_be_bytes())?;
        //target.append_slice(&[self.safi.into()])?;
        target.append_slice(&self.afisafi.as_bytes())?;
        self.nexthop.compose(target)?;

        // Reserved byte:
        target.append_slice(&[0x00])?;

        for a in &self.announcements {
            match a {
                Nlri::Unicast(b) => {
                    if !b.is_v4() {
                        b.compose(target)?;
                    } else {
                        // v4 unicast does not go in the MP_REACH_NLRI path
                        // attribute but at the end of the UDPATE PDU. The
                        // MpReachNlriBuilder should never contain v4 unicast
                        // announcements in its current implementation.
                        unreachable!();
                    }
                }
                Nlri::Multicast(b) => b.compose(target)?,
                Nlri::FlowSpec(f) => f.compose(target)?,
                _ => todo!("{:?}", a)
            }
        }

        Ok(())
    }

}
*/

// **NB:** this is bgp::message::update::NextHop
impl NextHop {
    fn compose_len(&self) -> usize {
        // 1 byte for the length, plus:
        1 + match *self {
            NextHop::Unicast(IpAddr::V4(_)) | NextHop::Multicast(IpAddr::V4(_)) => 4, 
            NextHop::Unicast(IpAddr::V6(_)) | NextHop::Multicast(IpAddr::V6(_)) => 16, 
            NextHop::Ipv6LL(_, _) => 32,
            NextHop::MplsVpnUnicast(_rd, IpAddr::V4(_)) => 8 + 4,
            NextHop::MplsVpnUnicast(_rd, IpAddr::V6(_)) => 8 + 16,
            NextHop::Empty => 0, // FlowSpec
            NextHop::Unimplemented(_afisafi) => {
                warn!(
                    "unexpected compose_len called on NextHop::Unimplemented \
                    returning usize::MAX, this will cause failure."
                );
                usize::MAX
            }
        }
    }

    pub(crate) fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(&[u8::try_from(self.compose_len()).unwrap() - 1])?;
        match *self {
            NextHop::Unicast(IpAddr::V4(a)) | NextHop::Multicast(IpAddr::V4(a)) => 
                target.append_slice(&a.octets())?,
            NextHop::Unicast(IpAddr::V6(a)) | NextHop::Multicast(IpAddr::V6(a)) => 
                target.append_slice(&a.octets())?,
            NextHop::Ipv6LL(a, ll) => {
                target.append_slice(&a.octets())?;
                target.append_slice(&ll.octets())?;
            }
            NextHop::MplsVpnUnicast(rd, IpAddr::V4(a)) => {
                target.append_slice(rd.as_ref())?;
                target.append_slice(&a.octets())?;
            }
            NextHop::MplsVpnUnicast(rd, IpAddr::V6(a)) => {
                target.append_slice(rd.as_ref())?;
                target.append_slice(&a.octets())?;
            }
            NextHop::Empty => { },
            NextHop::Unimplemented(_afisafi) => todo!(),
        }

        Ok(())
    }

}


//------------ MpUnreachNlriBuilder ------------------------------------------

// Note that all to-be-withdrawn NLRI should either have no PathID, or have a
// PathID. We can not mix non-addpath and addpath NLRI.
// Note that:
//  - add path works on a afi/safi level for a session, so a peer could do
//    addpath for v4 unicast but not for v6 unicast.
//  - in the Capability in the BGP OPEN, a peer can signal to be able to
//    receive, send, or receive+send add path NLRI. So, if we create methods
//    that take a NegotiatedConfig, the modification methods like
//    add_withdrawal should check whether the remote side is able to receive
//    path ids if the Nlri passed to add_withdrawal contains Some(PathId).
//

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct MpUnreachNlriBuilder<AfiSafi> {
    withdrawals: Vec<AfiSafi>,
}

impl<A> MpUnreachNlriBuilder<A>
where
{
    pub fn add_withdrawals_from_pdu<'a, Octs, O>(
        &mut self,
        source: &'a UpdateMessage<Octs>,
        _session_config: &SessionConfig
    )
    where
        A: AfiSafiNlri + NlriCompose + NlriParse<'a, O, Octs, Output = A>,
        Octs: Octets<Range<'a> = O>,
        O: Octets,
    {
        if let Ok(Some(iter)) = source.typed_withdrawals::<_, A>() {
            for w in iter {
                self.add_withdrawal(w.unwrap());
            }
        }
    }
}

impl<A: NlriCompose> MpUnreachNlriBuilder<A> {
    pub fn new() -> Self {
        Self {
            withdrawals: Vec::new(),
        }
    }

    pub fn from(withdrawal: A) -> Self {
        Self {
            withdrawals: vec![withdrawal],
        }
    }

    pub(crate) fn split(&mut self, n: usize) -> Self {
        let this_batch = self.withdrawals.drain(..n).collect();
        MpUnreachNlriBuilder {
            withdrawals: this_batch,
        }
    }

    pub(crate) fn value_len(&self) -> usize {
        3 + self.withdrawals.iter().fold(0, |sum, w| sum + w.compose_len())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.withdrawals.is_empty()
    }

    pub fn add_withdrawal(&mut self, nlri: A) {
        self.withdrawals.push(nlri);
    }

    pub(crate) fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(&A::afi_safi().as_bytes())?;

        for w in &self.withdrawals {
            w.compose(target)?;
        }

        Ok(())
    }

}

//------------ StandardCommunitiesBuilder ------------------------------------
//
//

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct StandardCommunitiesList {
    communities: Vec<StandardCommunity>,
    len: usize, // size of value, excluding path attribute flags+type_code+len
    extended: bool,
}

impl StandardCommunitiesList {
    pub(crate) fn new() -> StandardCommunitiesList {
        StandardCommunitiesList {
            communities: Vec::new(),
            len: 0,
            extended: false
        }
    }

    pub(crate) fn with_capacity(c: usize) -> StandardCommunitiesList {
        StandardCommunitiesList {
            communities: Vec::with_capacity(c),
            len: 0,
            extended: false
        }
    }

    pub fn communities(&self) -> &Vec<StandardCommunity> {
        &self.communities
    }

    //pub(crate) fn compose_len(&self, _community: StandardCommunity) -> usize {
    //    if !self.extended && self.len + 4 > 255 {
    //        4 +1
    //    } else {
    //        4
    //    }
    //}

    pub fn add_community(&mut self, community: StandardCommunity) {
        if !self.extended && self.len + 4 > 255 {
            self.extended = true;
        }
        self.len += 4;
        self.communities.push(community);
    }

    // TODO fn add_community_from_iter() 
}

//------------ Errors --------------------------------------------------------

#[derive(Debug)]
pub enum ComposeError{
    /// Exceeded maximum PDU size, data field carries the violating length.
    PduTooLarge(usize),

    // TODO proper docstrings, first see how/if we actually use these.
    AttributeTooLarge(PathAttributeType, usize),
    AttributesTooLarge(usize),
    IllegalCombination,
    EmptyMpReachNlri,
    EmptyMpUnreachNlri,
    WrongAddressType,

    InvalidAttribute, // XXX perhaps carry the type_code here?

    /// Variant for `octseq::builder::ShortBuf`
    ShortBuf,
    /// Wrapper for util::parser::ParseError, used in `fn into_message`
    ParseError(ParseError),

    Todo,
}

impl ComposeError {
    #[allow(dead_code)]
    fn todo() -> Self {
        ComposeError::Todo
    }
}

impl From<ShortBuf> for ComposeError {
    fn from(_: ShortBuf) -> ComposeError {
        ComposeError::ShortBuf
    }
}


impl From<ParseError> for ComposeError {
    fn from(pe: ParseError) -> ComposeError {
        ComposeError::ParseError(pe)
    }
}


impl std::error::Error for ComposeError { }
impl fmt::Display for ComposeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ComposeError::PduTooLarge(n) => {
                write!(f, "oversized PDU: {n} bytes")
            }
            ComposeError::AttributeTooLarge(attr, n) => {
                write!(f, "oversized attribute {attr}: {n} bytes")
            }
            ComposeError::AttributesTooLarge(n) => {
                write!(f, "total path attributes too large: {n} bytes")
            }
            ComposeError::IllegalCombination => {
                write!(f, "illegal combination of prefixes/attributes")
            }
            ComposeError::EmptyMpReachNlri => {
                write!(f, "missing NLRI in MP_REACH_NLRI")
            }
            ComposeError::EmptyMpUnreachNlri => {
                write!(f, "missing NLRI in MP_UNREACH_NLRI")
            }
            ComposeError::WrongAddressType => {
                write!(f, "wrong address type")
            }
            ComposeError::InvalidAttribute => {
                write!(f, "invalid attribute")
            }
            ComposeError::ShortBuf => {
                ShortBuf.fmt(f)
            }
            ComposeError::ParseError(pe) => {
                write!(f, "parse error in builder: {}", pe)
            }
            ComposeError::Todo => {
                write!(f, "not implemented yet")
            }

        }
    }
}


//------------ Tests ----------------------------------------------------------
#[cfg(test)]
mod tests {

    //use std::collections::BTreeSet;
    use std::fs::File;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    use memmap2::Mmap;
    use octseq::Parser;


    //use crate::bgp::path_attributes::AttributeHeader;
    use inetnum::addr::Prefix;
    use inetnum::asn::Asn;
    use crate::bgp::aspath::HopPath;
    use crate::bgp::communities::{StandardCommunity, Tag};
    use crate::bgp::nlri::afisafi::{
        Ipv4UnicastNlri,
        Ipv4MulticastNlri,
        Ipv6UnicastNlri,
        Ipv4FlowSpecNlri,
        NlriType,
    };
    use crate::bgp::types::{AfiSafiType, OriginType, PathId};

    use super::*;

    fn print_pcap<T: AsRef<[u8]>>(buf: T) {
        print!("000000 ");
        for b in buf.as_ref() {
            print!("{:02x} ", b);
        }
        println!();
    }


    #[test]
    fn empty_nlri_iterators() {
        let mut builder = UpdateBuilder::new_vec();
        builder.add_withdrawal(
            Ipv6UnicastNlri::from_str("2001:db8::/32").unwrap()
        ).unwrap();

        let msg = builder.into_message(&SessionConfig::modern()).unwrap();
        print_pcap(msg.as_ref());
        assert_eq!(msg.withdrawals().unwrap().count(), 1);

        let mut builder2 = UpdateBuilder::new_vec();
        builder2.add_withdrawal(
            Ipv4UnicastNlri::from_str("10.0.0.0/8").unwrap()
        ).unwrap();

        let msg2 = builder2.into_message(&SessionConfig::modern()).unwrap();
        print_pcap(msg2.as_ref());
        assert_eq!(msg2.withdrawals().unwrap().count(), 1);
    }

    #[test]
    fn build_empty() {
        let builder: UpdateBuilder<_, Ipv4UnicastNlri> = UpdateBuilder::new_vec();
        let msg = builder.finish(&SessionConfig::modern()).unwrap();
        //print_pcap(&msg);
        assert!(
            UpdateMessage::from_octets(msg, &SessionConfig::modern()).is_ok()
        );
    }

    #[test]
    fn build_withdrawals_basic_v4() {
        let mut builder = UpdateBuilder::new_vec();

        let withdrawals = [
            "0.0.0.0/0",
            "10.2.1.0/24",
            "10.2.2.0/24",
            "10.2.0.0/23",
            "10.2.4.0/25",
            "10.0.0.0/7",
            "10.0.0.0/8",
            "10.0.0.0/9",
        ].map(|s| Ipv4UnicastNlri::from_str(s).unwrap())
         .into_iter()
         .collect::<Vec<_>>();

        let _ = builder.append_withdrawals(withdrawals.clone());
        let msg = builder.finish(&SessionConfig::modern()).unwrap();
        
        if let Err(e) = UpdateMessage::from_octets(&msg, &SessionConfig::modern()) {
            dbg!(e);
        }
        assert!(
            UpdateMessage::from_octets(&msg, &SessionConfig::modern())
            .is_ok()
        );
        print_pcap(&msg);


        let mut builder2 = UpdateBuilder::new_vec();
        for w in withdrawals {
            builder2.add_withdrawal(w).unwrap();
        }

        let msg2 = builder2.finish(&SessionConfig::modern()).unwrap();
        assert!(
            UpdateMessage::from_octets(&msg2, &SessionConfig::modern())
            .is_ok()
        );
        print_pcap(&msg2);

        assert_eq!(msg, msg2);
    }

    /*
    #[test]
    fn build_withdrawals_from_iter() {
        let mut builder = UpdateBuilder::new_vec();

        let withdrawals = [
            "0.0.0.0/0",
            "10.2.1.0/24",
            "10.2.2.0/24",
            "10.2.0.0/23",
            "10.2.4.0/25",
            "10.0.0.0/7",
            "10.0.0.0/8",
            "10.0.0.0/9",
        ].map(|s| Nlri::unicast_from_str(s).unwrap().octets_into())
         .into_iter()
         .collect::<Vec<_>>();

        let _ = builder.withdrawals_from_iter(withdrawals);
        let msg = builder.into_message().unwrap();
        print_pcap(msg);
    }
    */

    #[test]
    fn take_message_many_withdrawals() {
        let mut builder = UpdateBuilder::new_vec();
        let mut prefixes: Vec<Ipv4UnicastNlri> = vec![];
        for i in 1..3000_u32 {
            prefixes.push(
                Ipv4UnicastNlri::try_from(
                    Prefix::new_v4(
                        Ipv4Addr::from((i << 10).to_be_bytes()),
                        22
                    ).unwrap()
                ).unwrap()
            );
        }

        let prefixes_len = prefixes.len();
        builder.withdrawals_from_iter(prefixes).unwrap();

        let mut w_cnt = 0;
        let remainder = if let (pdu1, Some(remainder)) = builder.take_message(&SessionConfig::modern()) {
            match pdu1 {
                Ok(pdu) => {
                    w_cnt += pdu.withdrawals().unwrap().count();
                    remainder
                }
                Err(e) => panic!("{}", e)
            }
        } else {
            panic!("wrong 1");
        };

        let remainder2 = if let (pdu2, Some(remainder2)) = remainder.take_message(&SessionConfig::modern()) {
            match pdu2 {
                Ok(pdu) => {
                    w_cnt += pdu.withdrawals().unwrap().count();
                    remainder2
                }
                Err(e) => panic!("{}", e)
            }
        } else {
            panic!("wrong 2");
        };

        if let (pdu3, None) = remainder2.take_message(&SessionConfig::modern()) {
            match pdu3 {
                Ok(pdu) => {
                    w_cnt += pdu.withdrawals().unwrap().count();
                }
                Err(e) => panic!("{}", e)
            }
        } else {
            panic!("wrong 3");
        };

        assert_eq!(w_cnt, prefixes_len);
    }

    #[test]
    fn take_message_many_withdrawals_2() {
        let mut builder = UpdateBuilder::new_vec();
        let mut prefixes: Vec<Ipv4UnicastNlri> = vec![];
        for i in 1..1500_u32 {
            prefixes.push(
                Ipv4UnicastNlri::try_from(
                    Prefix::new_v4(
                        Ipv4Addr::from((i << 10).to_be_bytes()),
                        22
                    ).unwrap()
                ).unwrap()
            );
        }
        let prefixes_len = prefixes.len();
        builder.append_withdrawals(prefixes).unwrap();

        let mut w_cnt = 0;
        let mut remainder = Some(builder);
        loop {
            if remainder.is_none() {
                break
            }
            let (pdu, new_remainder) = remainder.take().unwrap().take_message(&SessionConfig::modern());
            match pdu {
                Ok(pdu) => {
                    w_cnt += pdu.withdrawals().unwrap().count();
                    remainder = new_remainder;
                }
                Err(e) => panic!("{}", e)
            }
        }

        assert_eq!(w_cnt, prefixes_len);
    }

    #[test]
    fn into_messages_many_withdrawals() {
        let mut builder = UpdateBuilder::new_vec();
        let mut prefixes: Vec<Ipv4UnicastNlri> = vec![];
        for i in 1..1500_u32 {
            prefixes.push(
                Ipv4UnicastNlri::try_from(
                    Prefix::new_v4(
                        Ipv4Addr::from((i << 10).to_be_bytes()),
                        22
                    ).unwrap()
                ).unwrap()
            );
        }
        let prefixes_len = prefixes.len();
        builder.append_withdrawals(prefixes).unwrap();

        let mut w_cnt = 0;
        for pdu in builder.into_messages(&SessionConfig::modern()).unwrap() {
            w_cnt += pdu.withdrawals().unwrap().count();
        }

        assert_eq!(w_cnt, prefixes_len);
    }

    #[test]
    fn into_messages_many_announcements() {
        let mut builder = UpdateBuilder::new_vec();
        let mut prefixes: Vec<Ipv4UnicastNlri> = vec![];
        for i in 1..1500_u32 {
            prefixes.push(
                Ipv4UnicastNlri::try_from(
                    Prefix::new_v4(
                        Ipv4Addr::from((i << 10).to_be_bytes()),
                        22
                    ).unwrap()
                ).unwrap()
            );
        }
        let prefixes_len = prefixes.len();
        for p in prefixes {
            builder.add_announcement(p).unwrap();
        }

        let mut w_cnt = 0;
        for pdu in builder.into_messages(&SessionConfig::modern()).unwrap() {
            w_cnt += pdu.announcements().unwrap().count();
        }

        assert_eq!(w_cnt, prefixes_len);
    }

    #[test]
    fn into_messages_many_withdrawals_mp() {
        let mut builder = UpdateBuilder::new_vec();
        let prefixes_num = 1024;
        for i in 0..prefixes_num {
            builder.add_withdrawal(
                Ipv6UnicastNlri::from_str(&format!("2001:db:{:04}::/48", i))
                    .unwrap()
            ).unwrap();
        }

        let mut w_cnt = 0;
        for pdu in builder.into_messages(&SessionConfig::modern()).unwrap() {
            w_cnt += pdu.withdrawals().unwrap().count();
        }

        assert_eq!(w_cnt, prefixes_num);
    }

    #[test]
    fn into_messages_many_announcements_mp() {
        let mut builder = UpdateBuilder::new_vec();
        let prefixes_num = 1_000_000;
        for i in 0..prefixes_num {
            builder.add_announcement(
                Ipv6UnicastNlri::try_from(Prefix::new_v6((i << 96).into(), 32).unwrap()).unwrap()
            ).unwrap();
        }
        builder.attributes.set(crate::bgp::types::LocalPref(123));
        builder.attributes.set(crate::bgp::types::MultiExitDisc(123));
        (1..=300).for_each(|n| {
            builder.add_community(StandardCommunity::new(n.into(), Tag::new(123))).unwrap();
        });

        let mut a_cnt = 0;
        for pdu in builder.into_pdu_iter(&SessionConfig::modern()) {
            //eprint!(".");
            let pdu = pdu.unwrap();
            assert!(pdu.as_ref().len() <= UpdateBuilder::<(), Ipv4UnicastNlri>::MAX_PDU);
            a_cnt += pdu.announcements().unwrap().count();
            assert!(pdu.local_pref().unwrap().is_some());
            assert!(pdu.multi_exit_disc().unwrap().is_some());
            assert_eq!(pdu.communities().unwrap().unwrap().count(), 300);
        }

        assert_eq!(a_cnt, prefixes_num.try_into().unwrap());
    }



    #[test]
    fn build_withdrawals_basic_v4_addpath() {
        let mut builder = UpdateBuilder::new_vec();
        let withdrawals = [
            "0.0.0.0/0",
            "10.2.1.0/24",
            "10.2.2.0/24",
            "10.2.0.0/23",
            "10.2.4.0/25",
            "10.0.0.0/7",
            "10.0.0.0/8",
            "10.0.0.0/9",
        ].iter().enumerate().map(|(idx, s)|
            Ipv4UnicastNlri::from_str(s).unwrap()
                .into_addpath(PathId(idx.try_into().unwrap()))
        ).collect::<Vec<_>>();
        let _ = builder.append_withdrawals(withdrawals);
        let msg = builder.finish(&SessionConfig::modern()).unwrap();
        let mut sc = SessionConfig::modern();
        sc.add_addpath_rxtx(AfiSafiType::Ipv4Unicast);
        assert!(
            UpdateMessage::from_octets(&msg, &sc)
            .is_ok()
        );
        print_pcap(&msg);
    }

    #[test]
    fn build_withdrawals_basic_v6_single() {
        let mut builder = UpdateBuilder::new_vec();
        let withdrawals = vec![
            Ipv6UnicastNlri::from_str("2001:db8::/32").unwrap()
        ];

        let _ = builder.append_withdrawals(withdrawals);

        let msg = builder.finish(&SessionConfig::modern()).unwrap();
        println!("msg raw len: {}", &msg.len());
        print_pcap(&msg);
        
        UpdateMessage::from_octets(&msg, &SessionConfig::modern()).unwrap();
    }

    #[test]
    fn build_withdrawals_basic_v6_from_iter() {
        let mut builder = UpdateBuilder::new_vec();

        let mut withdrawals = vec![];
        for i in 1..512_u128 {
            withdrawals.push(
                Ipv6UnicastNlri::try_from(
                    Prefix::new_v6(
                        Ipv6Addr::from((i << 64).to_be_bytes()),
                        64
                    ).unwrap()
                ).unwrap()
            );
        }

        let _ = builder.withdrawals_from_iter(withdrawals);
        let raw = builder.finish(&SessionConfig::modern()).unwrap();
        print_pcap(&raw);
        UpdateMessage::from_octets(&raw, &SessionConfig::modern()).unwrap();
    }

    /* not possible anymore with the new typed builders
    #[test]
    fn build_mixed_withdrawals() {
        let mut builder = UpdateBuilder::new_vec();
        builder.add_withdrawal(
            //&Nlri::unicast_from_str("10.0.0.0/8").unwrap()
            Ipv4UnicastNlri::from_str("10.0.0.0/8").unwrap()
        ).unwrap();
        builder.add_withdrawal(
            //&Nlri::unicast_from_str("2001:db8::/32").unwrap()
            Ipv6UnicastNlri::from_str("2001:db8::/32").unwrap()
        ).unwrap();
        let msg = builder.into_message().unwrap();
        print_pcap(msg.as_ref());

        assert_eq!(msg.withdrawals().unwrap().count(), 2);
    }

    #[test]
    fn build_mixed_addpath_conventional() {
        let mut builder = UpdateBuilder::new_vec();
        builder.add_withdrawal(
            &Nlri::unicast_from_str("10.0.0.0/8").unwrap()
        ).unwrap();
        let res = builder.add_withdrawal(
            &Nlri::<&[u8]>::Unicast(
                (Prefix::from_str("10.0.0.0/8").unwrap(),
                Some(PathId::from_u32(123))
                ).into())
        );
        assert!(matches!(res, Err(ComposeError::IllegalCombination)));
    }

    #[test]
    fn build_mixed_addpath_mp() {
        let mut builder = UpdateBuilder::new_vec();
        builder.add_withdrawal(
            &Nlri::unicast_from_str("2001:db8::/32").unwrap()
        ).unwrap();
        let res = builder.add_withdrawal(
            &Nlri::<&[u8]>::Unicast(
                (Prefix::from_str("2001:db8::/32").unwrap(),
                Some(PathId::from_u32(123))
                ).into())
        );
        assert!(matches!(res, Err(ComposeError::IllegalCombination)));
    }

    #[test]
    fn build_mixed_addpath_ok() {
        let mut builder = UpdateBuilder::new_vec();
        builder.add_withdrawal(
            &Nlri::unicast_from_str("10.0.0.0/8").unwrap()
        ).unwrap();
        let res = builder.add_withdrawal(
            &Nlri::<&[u8]>::Unicast(
                (Prefix::from_str("2001:db8::/32").unwrap(),
                Some(PathId::from_u32(123))
                ).into())
        );
        assert!(res.is_ok());
        print_pcap(builder.finish().unwrap());
    }
    */

    #[test]
    fn build_conv_mp_mix() {
        let buf = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x88 + 8, // adding length for the conv NLRI
            0x02, 0x00, 0x00, 0x00, 0x71, 0x80,
            0x0e, 0x5a, 0x00, 0x02, 0x01, 0x20, 0xfc, 0x00,
            0x00, 0x10, 0x00, 0x01, 0x00, 0x10, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0xfe, 0x80,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80,
            0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
            0x40, 0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00,
            0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff,
            0x00, 0x01, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0xff,
            0xff, 0x00, 0x02, 0x40, 0x20, 0x01, 0x0d, 0xb8,
            0xff, 0xff, 0x00, 0x03, 0x40, 0x01, 0x01, 0x00,
            0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0x00,
            0xc8, 0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00,
            // manually adding two conv NLRI here
            24, 1, 1, 1,
            24, 1, 1, 2

        ];

        let upd = UpdateMessage::from_octets(&buf, &SessionConfig::modern()).unwrap();
        print_pcap(upd.as_ref());

        assert!(upd.has_conventional_nlri() && upd.has_mp_nlri().unwrap());
        assert_eq!(upd.announcements().unwrap().count(), 7);
    }

    #[test]
    fn build_announcements_conventional() {
        let mut builder = UpdateBuilder::new_vec();
        let prefixes = [
            "1.0.1.0/24",
            "1.0.2.0/24",
            "1.0.3.0/24",
            "1.0.4.0/24",
        ].map(|p| Ipv4UnicastNlri::from_str(p).unwrap());
        builder.announcements_from_iter(prefixes).unwrap();
        builder.attributes.set(crate::bgp::types::Origin(OriginType::Igp));
        builder.set_nexthop(NextHop::Unicast(Ipv4Addr::from_str("1.2.3.4").unwrap().into())).unwrap();
        let path = HopPath::from([
             Asn::from_u32(123); 70
        ]);

        //builder.set_aspath::<Vec<u8>>(path.to_as_path().unwrap()).unwrap();
        builder.set_aspath(path).unwrap();

        let raw = builder.finish(&SessionConfig::modern()).unwrap();
        print_pcap(raw);

        //let pdu = builder.into_message().unwrap();
        //print_pcap(pdu);
    }

    #[test]
    fn build_announcements_mp() {

        let mut builder = UpdateBuilder::new_vec();
        let prefixes = [
            "2001:db8:1::/48",
            "2001:db8:2::/48",
            "2001:db8:3::/48",
        ].map(|p| Ipv6UnicastNlri::from_str(p).unwrap());
        builder.announcements_from_iter(prefixes).unwrap();
        builder.attributes.set(crate::bgp::types::Origin(OriginType::Igp));
        builder.set_nexthop(NextHop::Unicast(Ipv6Addr::from_str("fe80:1:2:3::").unwrap().into())).unwrap();
        let path = HopPath::from([
             Asn::from_u32(100),
             Asn::from_u32(200),
             Asn::from_u32(300),
        ]);
        //builder.set_aspath::<Vec<u8>>(path.to_as_path().unwrap()).unwrap();
        builder.set_aspath(path).unwrap();

        let raw = builder.finish(&SessionConfig::modern()).unwrap();
        print_pcap(raw);
    }

    #[test]
    fn build_announcements_mp_missing_nlri() {
        let mut builder = UpdateBuilder::<_, Ipv6UnicastNlri>::new_vec();
        builder.attributes.set(crate::bgp::types::Origin(OriginType::Igp));
        builder.set_nexthop(NextHop::Unicast(Ipv6Addr::from_str("fe80:1:2:3::").unwrap().into())).unwrap();
        let path = HopPath::from([
             Asn::from_u32(100),
             Asn::from_u32(200),
             Asn::from_u32(300),
        ]);
        builder.set_aspath(path).unwrap();

        assert!(matches!(
            builder.into_message(&SessionConfig::modern()),
            Err(ComposeError::EmptyMpReachNlri)
        ));
    }

    #[test]
    fn build_announcements_mp_link_local() {
        let mut builder = UpdateBuilder::new_vec();

        let prefixes = [
            "2001:db8:1::/48",
            "2001:db8:2::/48",
            "2001:db8:3::/48",
        ].map(|p| Ipv6UnicastNlri::from_str(p).unwrap());

        builder.announcements_from_iter(prefixes).unwrap();
        builder.attributes.set(crate::bgp::types::Origin(OriginType::Igp));
        builder.set_nexthop_ll_addr("fe80:1:2:3::".parse().unwrap()).unwrap();


        let path = HopPath::from([
             Asn::from_u32(100),
             Asn::from_u32(200),
             Asn::from_u32(300),
        ]);
        //builder.set_aspath::<Vec<u8>>(path.to_as_path().unwrap()).unwrap();
        builder.set_aspath(path).unwrap();

        //let unchecked = builder.finish().unwrap();
        //print_pcap(unchecked);
        let msg = builder.into_message(&SessionConfig::modern()).unwrap();
        msg.print_pcap();
    }

    #[test]
    fn build_announcements_mp_ll_no_nlri() {
        let mut builder = UpdateBuilder::<_, Ipv6UnicastNlri>::new_vec();
        builder.attributes.set(crate::bgp::types::Origin(OriginType::Igp));
        //builder.set_nexthop("2001:db8::1".parse().unwrap()).unwrap();
        builder.set_nexthop_ll_addr("fe80:1:2:3::".parse().unwrap()).unwrap();
        let path = HopPath::from([
             Asn::from_u32(100),
             Asn::from_u32(200),
             Asn::from_u32(300),
        ]);
        builder.set_aspath(path).unwrap();

        assert!(matches!(
            builder.into_message(&SessionConfig::modern()),
            Err(ComposeError::EmptyMpReachNlri)
        ));
    }

    #[test]
    fn build_standard_communities() {
        let mut builder = UpdateBuilder::new_vec();
        let prefixes = [
            "1.0.1.0/24",
            "1.0.2.0/24",
            "1.0.3.0/24",
            "1.0.4.0/24",
        ].map(|p| Ipv4UnicastNlri::from_str(p).unwrap());
        builder.announcements_from_iter(prefixes).unwrap();
        builder.attributes.set(crate::bgp::types::Origin(OriginType::Igp));
        builder.set_nexthop(NextHop::Unicast(Ipv4Addr::from_str("1.2.3.4").unwrap().into())).unwrap();
        let path = HopPath::from([
             Asn::from_u32(100),
             Asn::from_u32(200),
             Asn::from_u32(300),
        ]);
        //builder.set_aspath::<Vec<u8>>(path.to_as_path().unwrap()).unwrap();
        builder.set_aspath(path).unwrap();


        builder.add_community("AS1234:666".parse().unwrap()).unwrap();
        builder.add_community("NO_EXPORT".parse().unwrap()).unwrap();
        for n in 1..100 {
            builder.add_community(format!("AS999:{n}").parse().unwrap()).unwrap();
        }

        builder.into_message(&SessionConfig::modern()).unwrap();
        //let raw = builder.finish().unwrap();
        //print_pcap(&raw);
    }

    #[test]
    fn build_other_attributes() {
        let mut builder = UpdateBuilder::new_vec();
        let prefixes = [
            "1.0.1.0/24",
            "1.0.2.0/24",
            "1.0.3.0/24",
            "1.0.4.0/24",
        ].map(|p| Ipv4UnicastNlri::from_str(p).unwrap());
        builder.announcements_from_iter(prefixes).unwrap();
        builder.attributes.set(crate::bgp::types::Origin(OriginType::Igp));
        builder.set_nexthop(NextHop::Unicast(Ipv4Addr::from_str("1.2.3.4").unwrap().into())).unwrap();
        let path = HopPath::from([
             Asn::from_u32(100),
             Asn::from_u32(200),
             Asn::from_u32(300),
        ]);
        //builder.set_aspath::<Vec<u8>>(path.to_as_path().unwrap()).unwrap();
        builder.set_aspath(path).unwrap();

        builder.attributes.set(crate::bgp::types::MultiExitDisc(1234));
        builder.attributes.set(crate::bgp::types::LocalPref(9876));

        let msg = builder.into_message(&SessionConfig::modern()).unwrap();
        msg.print_pcap();
    }

    #[test]
    fn from_update_message() {
        let raw = vec![
            // BGP UPDATE, single conventional announcement, MultiExitDisc
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x37, 0x02,
            0x00, 0x00, 0x00, 0x1b, 0x40, 0x01, 0x01, 0x00, 0x40, 0x02,
            0x06, 0x02, 0x01, 0x00, 0x01, 0x00, 0x00, 0x40, 0x03, 0x04,
            0x0a, 0xff, 0x00, 0x65, 0x80, 0x04, 0x04, 0x00, 0x00, 0x00,
            0x01, 0x20, 0x0a, 0x0a, 0x0a, 0x02
        ];
        let sc = SessionConfig::modern();
        let upd = UpdateMessage::from_octets(&raw, &sc).unwrap();
        let target = BytesMut::new();
        let mut builder = UpdateBuilder::from_update_message(&upd, &sc, target).unwrap();


        assert_eq!(builder.attributes.len(), 4);

        builder.add_announcement(
            Ipv4UnicastNlri::from_str("10.10.10.2/32").unwrap()
        ).unwrap();

        let upd2 = builder.into_message(&SessionConfig::modern()).unwrap();

        // doesn't work as we put everything in MP attributes
        //assert_eq!(&raw, upd2.as_ref());

        assert!(
            upd.typed_announcements::<_, Ipv4UnicastNlri>().unwrap().unwrap().eq(
                upd2.typed_announcements::<_, Ipv4UnicastNlri>().unwrap().unwrap()
            )
        );
    }

    #[test]
    fn build_overwriting_attributes() {
        // TODO test that when setting and overwriting the same attribute in
        // an UpdateBuilder, the resulting PDU contains the lastly set
        // attribute and that all the lengths are correct etc
        
        let raw = vec![
            // BGP UPDATE, single conventional announcement, MultiExitDisc
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x37, 0x02,
            0x00, 0x00, 0x00, 0x1b, 0x40, 0x01, 0x01, 0x00, 0x40, 0x02,
            0x06, 0x02, 0x01, 0x00, 0x01, 0x00, 0x00, 0x40, 0x03, 0x04,
            0x0a, 0xff, 0x00, 0x65, 0x80, 0x04, 0x04, 0x00, 0x00, 0x00,
            0x01, 0x20, 0x0a, 0x0a, 0x0a, 0x02
        ];
        let sc = SessionConfig::modern();
        let upd = UpdateMessage::from_octets(&raw, &sc).unwrap();
        for pa in upd.clone().path_attributes().unwrap() {
            eprintln!("{:?}", pa.unwrap().to_owned().unwrap());
        }
        let target = BytesMut::new();
        let mut builder = UpdateBuilder::from_update_message(&upd, &sc, target).unwrap();

        
        assert_eq!(builder.attributes.len(), 4);

        builder.attributes.set(crate::bgp::types::Origin(OriginType::Igp));
        builder.attributes.set(crate::bgp::types::Origin(OriginType::Egp));
        builder.attributes.set(crate::bgp::types::Origin(OriginType::Igp));

        assert_eq!(builder.attributes.len(), 4);

        builder.add_announcement(
            Ipv4UnicastNlri::from_str("10.10.10.2/32").unwrap()
        ).unwrap();

        let upd2 = builder.into_message(&SessionConfig::modern()).unwrap();
        assert_eq!(upd2.origin(), Ok(Some(OriginType::Igp)));
    }

    #[test]
    fn build_ordered_attributes() {
        let mut builder = UpdateBuilder::<_, Ipv4UnicastNlri>::new_vec();
        builder.add_community(
            StandardCommunity::from_str("AS1234:999").unwrap()
        ).unwrap();
        builder.attributes.set(crate::bgp::types::Origin(OriginType::Igp));
        builder.add_community(
            StandardCommunity::from_str("AS1234:1000").unwrap()
        ).unwrap();

        assert_eq!(builder.attributes.len(), 2);

        let pdu = builder.into_message(&SessionConfig::modern()).unwrap();
        let mut prev_type_code = 0_u8;
        for pa in pdu.path_attributes().unwrap() {
            let type_code = pa.unwrap().type_code();
            assert!(prev_type_code < type_code);
            prev_type_code = type_code; 
        }
        assert_eq!(pdu.communities().unwrap().unwrap().count(), 2);
    }

    // TODO also do fn check(raw: Bytes)
    // XXX this will not work anymore as we put conventional NLRI in MP
    // attributes.. but we can check a subset of things perhaps.
    fn parse_build_compare(raw: &[u8]) {
            
        let sc = SessionConfig::modern();
        let original =
            match UpdateMessage::from_octets(raw, &sc) {
                Ok(msg) => msg,
                Err(_e) => {
                    //TODO get the ShortInput ones (and retry with a different
                    //SessionConfig)
                    //eprintln!("failed to parse input: {e:?}");
                    //print_pcap(&raw);
                    //panic!();
                    return;
                }
            };

            let target = BytesMut::new();
            let reach_afisafi = original.announcement_fams().last()
                .or(
                    original.withdrawal_fams().last()
                )
                .unwrap_or(NlriType::Ipv4Unicast);


            let composed = match reach_afisafi {
                NlriType::Ipv4Unicast => {
                    let mut builder = UpdateBuilder::<_, Ipv4UnicastNlri>::from_update_message(&original, &sc, target).unwrap();
                    builder.add_announcements_from_pdu(&original, &sc);
                    builder.add_withdrawals_from_pdu(&original, &sc);
                    builder.into_message(&sc)
                }
                NlriType::Ipv4Multicast => {
                    let mut builder = UpdateBuilder::<_, Ipv4MulticastNlri>::from_update_message(&original, &sc, target).unwrap();
                    builder.add_announcements_from_pdu(&original, &sc);
                    builder.add_withdrawals_from_pdu(&original, &sc);
                    builder.into_message(&sc)
                }
                NlriType::Ipv4MplsUnicast => todo!(),
                NlriType::Ipv4MplsVpnUnicast => todo!(),
                NlriType::Ipv4RouteTarget => todo!(),
                NlriType::Ipv4FlowSpec => {
                    let mut builder = UpdateBuilder::<_, Ipv4FlowSpecNlri<_>>::from_update_message(&original, &sc, target).unwrap();
                    builder.add_announcements_from_pdu(&original, &sc);
                    builder.add_withdrawals_from_pdu(&original, &sc);
                    builder.into_message(&sc)
                }
                NlriType::Ipv6Unicast => {
                    let mut builder = UpdateBuilder::<_, Ipv6UnicastNlri>::from_update_message(&original, &sc, target).unwrap();
                    builder.add_announcements_from_pdu(&original, &sc);
                    builder.add_withdrawals_from_pdu(&original, &sc);
                    builder.into_message(&sc)
                }

                NlriType::Ipv6Multicast => todo!(),
                NlriType::Ipv6MplsUnicast => todo!(),
                NlriType::Ipv6MplsVpnUnicast => todo!(),
                NlriType::Ipv6FlowSpec => todo!(),
                NlriType::L2VpnVpls => todo!(),
                NlriType::L2VpnEvpn => todo!(),
                NlriType::Unsupported(_, _) => todo!(),
                _ => todo!(), // ADD-PATH catch-all
            };
            //let mut builder = UpdateBuilder::<_, reach_afisafi>::from_update_message(
            //    &original, &sc, target
            //).unwrap();

            /*
            //for w in original.withdrawals().unwrap() {
            for w in original.typed_withdrawals().unwrap().unwrap() {
                builder.add_withdrawal(w.unwrap()).unwrap();
            }

            for a in original.announcements().unwrap() {
                builder.add_announcement(&a.unwrap()).unwrap();
            }

            if let Some(nh) = original.conventional_next_hop().unwrap() {
                if let NextHop::Unicast(IpAddr::V4(a))= nh {
                    builder.attributes.set(crate::bgp::types::ConventionalNextHop(a));
                } else {
                    unreachable!()
                }
            }
            if let Some(nh) = original.mp_next_hop().unwrap() {
                builder.set_mp_nexthop(nh).unwrap();
            }

            //eprintln!("--");
            //print_pcap(&raw);
            //print_pcap(builder.finish().unwrap());
            //eprintln!("--");
            //panic!("hard stop");


            let calculated_len = builder.calculate_pdu_length();

            */
            /*
            let composed = match composed {
                (Ok(msg), None) => msg,
                (Err(e), _) => {
                    print_pcap(raw);
                    panic!("error: {e}");
                }
                (_, Some(_)) => {
                    unimplemented!("builder returning remainder")
                }
            };
            */
            let composed = match composed {
                Ok(msg) => msg,
                Err(e) => {
                    print_pcap(raw);
                    panic!("error: {e}");
                }
            };

        if std::panic::catch_unwind(|| {
            assert_eq!(
              original.announcements().unwrap().count(),
              composed.announcements().unwrap().count(),
            );
            assert_eq!(
              original.withdrawals().unwrap().count(),
              composed.withdrawals().unwrap().count(),
            );

            // In case of an original with conventional withdrawals and
            // announcements, we end up with 2 extra attributes (MP
            // REACH/UNREACH), so allow a margin of 2 here.
            assert!(
                composed.path_attributes().unwrap().count().abs_diff(
                    original.path_attributes().unwrap().count()
                ) <= 2
            );

            assert_eq!(original.origin(), composed.origin());
            assert_eq!(original.multi_exit_disc(), composed.multi_exit_disc());
            assert_eq!(original.local_pref(), composed.local_pref());
        }).is_err() {
            eprintln!("--");
            print_pcap(raw);
            print_pcap(composed.as_ref());

            eprintln!("--");
            panic!("tmp");
        }

            //assert_eq!(composed.as_ref().len(), calculated_len);

            // XXX there are several possible reasons why our composed pdu
            // differs from the original input, especially if the attributes
            // in the original were not correctly ordered, or when attributes
            // had the extended-length bit set while not being >255 in size.
            //assert_eq!(raw, composed.as_ref());


            /*
            // compare as much as possible:
            #[allow(clippy::blocks_in_conditions)]
            if std::panic::catch_unwind(|| {
            assert_eq!(original.origin(), composed.origin());
            //assert_eq!(original.aspath(), composed.aspath());
            assert_eq!(original.conventional_next_hop(), composed.conventional_next_hop());
            assert_eq!(original.mp_next_hop(), composed.mp_next_hop());
            assert_eq!(original.multi_exit_disc(), composed.multi_exit_disc());
            assert_eq!(original.local_pref(), composed.local_pref());

            /*
            assert_eq!(
              original.path_attributes().iter().count(),
              composed.path_attributes().unwrap().count()
            );
            */

            let orig_pas = original.path_attributes().unwrap()
                .map(|pa| pa.unwrap().type_code()).collect::<BTreeSet<_>>();

            let composed_pas = composed.path_attributes().unwrap()
                .map(|pa| pa.unwrap().type_code()).collect::<BTreeSet<_>>();

            let diff_pas: Vec<_> = orig_pas.symmetric_difference(
                &composed_pas
            ).collect();
            if !diff_pas.is_empty() {
                for d in &diff_pas {
                    match *d {
                        // FIXME: check if MPU is the _only_ attribute,
                        // perhaps we are dealing with an EoR here?
                        &crate::bgp::message::update_builder::MpUnreachNlriBuilder::TYPE_CODE => {
                            // XXX RIS data contains empty-but-non-EoR
                            // MP_UNREACH_NLRI for some reason. 
                            //assert!(original.is_eor().is_some());
                            //});

                        }
                        _ => {
                            dbg!(diff_pas);
                            panic!("unclear why PAs differ")
                        }
                    }
                }
            }

            assert_eq!(
              original.announcements().unwrap().count(),
              composed.announcements().unwrap().count(),
            );
            assert_eq!(
              original.withdrawals().iter().count(),
              composed.withdrawals().iter().count(),
            );

            }).is_err() {
                eprintln!("--");
                print_pcap(raw);
                print_pcap(composed.as_ref());

                eprintln!("--");
                panic!("tmp");
            }

            if raw == composed.as_ref() {
                eprint!("✓");
            } else {
                eprint!("×");
            }
            */
    }

    #[test]
    fn parse_build_compare_1() {
        eprintln!();
        parse_build_compare(&[
        // BGP UPDATE, single conventional announcement, MultiExitDisc
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x37, 0x02, 0x00, 0x00, 0x00, 0x1b, 0x40,
            0x01, 0x01, 0x00, 0x40, 0x02, 0x06, 0x02, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x40, 0x03, 0x04, 0x0a,
            0xff, 0x00, 0x65, 0x80, 0x04, 0x04, 0x00, 0x00,
            0x00, 0x01, 0x20, 0x0a, 0x0a, 0x0a, 0x02
        ]
        );

        parse_build_compare(&[
            // BGP UPDATE, Ipv4 FlowSpec, empty AS_PATH, ext communities
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x46, 0x02, 0x00, 0x00, 0x00, 0x2f, 0x90,
            0x0e, 0x00, 0x12, 0x00, 0x01, 0x85, 0x00, 0x00,
            0x0c, 0x07, 0x81, 0x08, 0x08, 0x81, 0x00, 0x0b,
            0x81, 0x08, 0x0c, 0x81, 0x01, 0x40, 0x01, 0x01,
            0x00, 0x40, 0x02, 0x00, 0x40, 0x05, 0x04, 0x00,
            0x00, 0x00, 0x64, 0xc0, 0x10, 0x08, 0x80, 0x09,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x10
        ]
        );

        // FIXME: the NextHop in MP_REACH_NLRI gets lost
        parse_build_compare(&[
            // BGP UPDATE, IPv4 Multicast, NEXT_HOP, et al.
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x52, 0x02, 0x00, 0x00, 0x00, 0x3b, 0x80,
            0x0e, 0x1d, 0x00, 0x01, 0x02, 0x04, 0x0a, 0x09,
            0x0a, 0x09, 0x00, 0x1a, 0xc6, 0x33, 0x64, 0x00,
            0x1a, 0xc6, 0x33, 0x64, 0x40, 0x1a, 0xc6, 0x33,
            0x64, 0x80, 0x1a, 0xc6, 0x33, 0x64, 0xc0, 0x40,
            0x01, 0x01, 0x00, 0x40, 0x02, 0x06, 0x02, 0x01,
            0x00, 0x00, 0x01, 0xf4, 0x40, 0x03, 0x04, 0x0a,
            0x09, 0x0a, 0x09, 0x80, 0x04, 0x04, 0x00, 0x00,
            0x00, 0x00
        ]
        );
        eprintln!();

    }


    #[ignore]
    #[test]
    fn parse_build_compare_bulk() {
        let filename = "examples/raw_bgp_updates";
        let file = File::open(filename).unwrap();
        let mmap = unsafe { Mmap::map(&file).unwrap()  };
        let fh = &mmap[..];
        let mut parser = Parser::from_ref(&fh);

        let mut n = 0;
        const MAX: usize = usize::MAX;

        while parser.remaining() > 0 && n < MAX {
            let pos = parser.pos();
            parser.advance(16).unwrap();
            let len = parser.parse_u16_be().unwrap();
            parser.seek(pos).unwrap();
            parse_build_compare(
                parser.parse_octets(len.into()).unwrap()
            );
            n += 1;
            eprint!("\r{n} ");
        }
        eprintln!("parse_build_compare'd {n}");
    }

    #[test]
    fn build_mp_unreach_extended_length() {
        let raw = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x02, 0xd1, 0x02, 0x00, 0x00, 0x02, 0xba, 0x40,
            0x01, 0x01, 0x00, 0x40, 0x02, 0x1a, 0x02, 0x06,
            0x00, 0x00, 0x1a, 0x0b, 0x00, 0x00, 0x51, 0x1c,
            0x00, 0x00, 0xbc, 0xa5, 0x00, 0x00, 0x1b, 0x1b,
            0x00, 0x00, 0xf3, 0x20, 0x00, 0x03, 0x2e, 0xa9,
            0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0x08, 0xd0,
            0x08, 0x02, 0x60, 0x00, 0x00, 0x0b, 0x26, 0x00,
            0x00, 0x0c, 0xa3, 0x00, 0x00, 0x1a, 0x10, 0x00,
            0x00, 0x1a, 0x29, 0x00, 0x00, 0x20, 0x01, 0x00,
            0x00, 0x21, 0x16, 0x00, 0x00, 0x21, 0x2c, 0x00,
            0x00, 0x21, 0x93, 0x00, 0x00, 0x21, 0xbc, 0x00,
            0x00, 0x21, 0xc1, 0x00, 0x00, 0x23, 0xa3, 0x00,
            0x00, 0x31, 0x0b, 0x00, 0x00, 0x31, 0x6e, 0x00,
            0x00, 0x32, 0xca, 0x00, 0x00, 0x33, 0xf6, 0x00,
            0x00, 0x3c, 0x12, 0x00, 0x00, 0x3c, 0x59, 0x00,
            0x00, 0x3d, 0x38, 0x00, 0x00, 0x3d, 0xe8, 0x00,
            0x00, 0x52, 0x26, 0x00, 0x00, 0x53, 0x12, 0x00,
            0x00, 0x53, 0x33, 0x00, 0x00, 0x53, 0xcd, 0x00,
            0x00, 0x60, 0x3e, 0x00, 0x00, 0x60, 0xa3, 0x00,
            0x00, 0x61, 0x05, 0x00, 0x00, 0x67, 0x2f, 0x00,
            0x00, 0x71, 0x79, 0x00, 0x00, 0x71, 0xc4, 0x00,
            0x00, 0x71, 0xfe, 0x00, 0x00, 0x73, 0x94, 0x00,
            0x00, 0x78, 0x87, 0x00, 0x00, 0x78, 0x9d, 0x00,
            0x00, 0x78, 0xd8, 0x00, 0x00, 0x78, 0xf8, 0x00,
            0x00, 0x7a, 0x3e, 0x00, 0x00, 0x7a, 0x8a, 0x00,
            0x00, 0x7a, 0x90, 0x00, 0x00, 0x7a, 0xc6, 0x00,
            0x00, 0x7b, 0xd7, 0x00, 0x00, 0x84, 0x70, 0x00,
            0x00, 0x84, 0xb4, 0x00, 0x00, 0x86, 0x98, 0x00,
            0x00, 0x87, 0x2a, 0x00, 0x00, 0x88, 0x8f, 0x00,
            0x00, 0x88, 0xb8, 0x00, 0x00, 0x88, 0xd8, 0x00,
            0x00, 0x89, 0x44, 0x00, 0x00, 0x8a, 0x7f, 0x00,
            0x00, 0x8a, 0xb4, 0x00, 0x00, 0x8b, 0x0e, 0x00,
            0x00, 0x8b, 0xdf, 0x00, 0x00, 0x8b, 0xe2, 0x00,
            0x00, 0x98, 0xaf, 0x00, 0x00, 0x9b, 0x37, 0x00,
            0x00, 0xa0, 0xa2, 0x00, 0x00, 0xa2, 0x81, 0x00,
            0x00, 0xa2, 0xfa, 0x00, 0x00, 0xa5, 0x0d, 0x00,
            0x00, 0xa5, 0x33, 0x00, 0x00, 0xa6, 0x16, 0x00,
            0x00, 0xa6, 0xac, 0x00, 0x00, 0xa8, 0xae, 0x00,
            0x00, 0xa9, 0x35, 0x00, 0x00, 0xaa, 0x0a, 0x00,
            0x00, 0xaa, 0xcf, 0x00, 0x00, 0xab, 0xfe, 0x00,
            0x00, 0xac, 0xee, 0x00, 0x00, 0xad, 0x62, 0x00,
            0x00, 0xaf, 0x2b, 0x00, 0x00, 0xaf, 0x71, 0x00,
            0x00, 0xaf, 0xe5, 0x00, 0x00, 0xb8, 0x9a, 0x00,
            0x00, 0xb9, 0xca, 0x00, 0x00, 0xb9, 0xe2, 0x00,
            0x00, 0xba, 0x1d, 0x00, 0x00, 0xba, 0x6b, 0x00,
            0x00, 0xba, 0x83, 0x00, 0x00, 0xba, 0x9f, 0x00,
            0x00, 0xbb, 0xe0, 0x00, 0x00, 0xbc, 0x26, 0x00,
            0x00, 0xbc, 0x81, 0x00, 0x00, 0xbc, 0xa5, 0x00,
            0x00, 0xbc, 0xdb, 0x00, 0x00, 0xbd, 0x0f, 0x00,
            0x00, 0xbd, 0x25, 0x00, 0x00, 0xbd, 0x61, 0x00,
            0x00, 0xbd, 0x83, 0x00, 0x00, 0xbe, 0x82, 0x00,
            0x00, 0xbe, 0xca, 0x00, 0x00, 0xbf, 0x5d, 0x00,
            0x00, 0xbf, 0xa7, 0x00, 0x00, 0xc1, 0x61, 0x00,
            0x00, 0xc1, 0x86, 0x00, 0x00, 0xc1, 0xa1, 0x00,
            0x00, 0xc1, 0xe9, 0x00, 0x00, 0xc2, 0x73, 0x00,
            0x00, 0xc2, 0x95, 0x00, 0x00, 0xc4, 0x52, 0x00,
            0x00, 0xc4, 0xa4, 0x00, 0x00, 0xc5, 0x29, 0x00,
            0x00, 0xc6, 0x53, 0x00, 0x00, 0xc6, 0xc9, 0x00,
            0x00, 0xc7, 0x03, 0x00, 0x00, 0xc7, 0x0e, 0x00,
            0x00, 0xc7, 0x47, 0x00, 0x00, 0xc7, 0x94, 0x00,
            0x00, 0xc7, 0x95, 0x00, 0x00, 0xc8, 0x61, 0x00,
            0x00, 0xc8, 0x8d, 0x00, 0x00, 0xc9, 0xcb, 0x00,
            0x00, 0xc9, 0xd5, 0x00, 0x00, 0xcb, 0xbc, 0x00,
            0x00, 0xcb, 0xe1, 0x00, 0x00, 0xdc, 0xd6, 0x00,
            0x00, 0xdd, 0x10, 0x00, 0x00, 0xdd, 0x67, 0x00,
            0x00, 0xdd, 0x71, 0x00, 0x00, 0xdd, 0x7d, 0x00,
            0x00, 0xdd, 0xee, 0x00, 0x00, 0xde, 0x8b, 0x00,
            0x00, 0xde, 0xb2, 0x00, 0x00, 0xdf, 0x5e, 0x00,
            0x00, 0xdf, 0xc1, 0x00, 0x00, 0xe0, 0x31, 0x00,
            0x00, 0xe0, 0x8f, 0x00, 0x00, 0xe0, 0xb9, 0x00,
            0x00, 0xe1, 0x70, 0x00, 0x00, 0xe3, 0x2e, 0x00,
            0x00, 0xe8, 0x7c, 0x00, 0x00, 0xe8, 0xeb, 0x00,
            0x00, 0xe9, 0x53, 0x00, 0x00, 0xe9, 0x94, 0x00,
            0x00, 0xeb, 0x02, 0x00, 0x00, 0xeb, 0x05, 0x00,
            0x00, 0xeb, 0x55, 0x00, 0x00, 0xeb, 0xc5, 0x00,
            0x00, 0xed, 0xf7, 0x00, 0x00, 0xf2, 0x97, 0x00,
            0x00, 0xf2, 0xfd, 0x00, 0x00, 0xf3, 0x21, 0x00,
            0x00, 0xf3, 0xaa, 0x1a, 0x0b, 0x0b, 0xb9, 0x1a,
            0x0b, 0x0f, 0xa5, 0x1a, 0x0b, 0x14, 0x57, 0x1a,
            0x0b, 0x17, 0x70, 0x1a, 0x0b, 0x22, 0xbb, 0x51,
            0x1c, 0x0b, 0xba, 0x51, 0x1c, 0x0b, 0xc3, 0x51,
            0x1c, 0x0b, 0xcd, 0x71, 0x94, 0x03, 0x85, 0x71,
            0x94, 0xfc, 0x67, 0x90, 0x0e, 0x00, 0x2a, 0x00,
            0x02, 0x01, 0x20, 0x20, 0x01, 0x07, 0xf8, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x0b, 0x00,
            0x00, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0xe6, 0xfc, 0x82, 0xff, 0xfe,
            0xa3, 0xbf, 0xc3, 0x00, 0x1d, 0x2a, 0x10, 0xcb,
            0xc0
        ];

        parse_build_compare(&raw);

    }

    #[test]
    fn build_invalid_attribute() {
        // If the builder contains an Invalid attribute, apparently the user
        // wants that, so it should be encoded on the wire.
        let raw = vec![
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0x00, 0x5e, 0x02, 0x00, 0x00, 0x00, 0x43, 0x40,
          0x01, 0x01, 0x00, 0x40, 0x02, 0x16, 0x02, 0x05,
          0x00, 0x00, 0xbf, 0xee, 0x00, 0x00, 0xd0, 0x6c,
          0x00, 0x00, 0x1b, 0x1b, 0x00, 0x00, 0x1d, 0x97,
          0x00, 0x00, 0x5c, 0xa7, 0x40, 0x03, 0x04, 0x17,
          0x81, 0x20, 0x3d, 0x40, 0x06, 0x00, 0xc0, 0x07,
          0x08, 0x00, 0x00, 0xfe, 0x57, 0x0a, 0x40, 0x01,
          0xf6, 0xe0, 0x14, 0x0e, 0x00, 0x01, 0x00, 0x01,
          0xac, 0x15, 0x09, 0xf6, 0x00, 0x09, 0x0a, 0x40,
          0x01, 0xf6, 0x18, 0xcb, 0x20, 0x6b
        ];
        parse_build_compare(&raw);
    }

    #[test]
    fn build_mp_reach_nlri_ll() {
        let raw = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x9d, 0x02, 0x00, 0x00, 0x00, 0x86, 0x40,
            0x01, 0x01, 0x00, 0x40, 0x02, 0x16, 0x02, 0x05,
            0x00, 0x00, 0x5f, 0xa2, 0x00, 0x00, 0x19, 0x35,
            0x00, 0x00, 0x0d, 0x1c, 0x00, 0x00, 0x4f, 0xf9,
            0x00, 0x03, 0x3f, 0xf9, 0x80, 0x04, 0x04, 0x00,
            0x01, 0x57, 0xd4, 0xc0, 0x08, 0x24, 0x19, 0x35,
            0x00, 0x56, 0x19, 0x35, 0x03, 0xe8, 0x19, 0x35,
            0x05, 0x78, 0x19, 0x35, 0x05, 0x7c, 0x5f, 0xa2,
            0x00, 0x01, 0x5f, 0xa2, 0x32, 0xdc, 0x5f, 0xa2,
            0x32, 0xdd, 0x5f, 0xa2, 0x4f, 0x4c, 0x5f, 0xa2,
            0xfc, 0x59, 0xc0, 0x10, 0x08, 0x00, 0x02, 0x5f,
            0xa2, 0x00, 0x00, 0x01, 0x36, 0x90, 0x0e, 0x00,
            0x2c, 0x00, 0x02, 0x01, 0x20, 0x20, 0x01, 0x07,
            0xf8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xa5,
            0x02, 0x44, 0x82, 0x00, 0x01, 0xfe, 0x80, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0xc3, 0xd6,
            0x00, 0x51, 0x03, 0xe7, 0xc0, 0x00, 0x30, 0x2a,
            0x0e, 0x9b, 0x43, 0x00, 0x00
        ];
        parse_build_compare(&raw);

    }

    #[test]
    fn build_from_pdu_with_empty_unreach() {
        // An empty MP_UNREACH_NLRI, i.e. no actual prefixes, should not
        // be written to the wire. When creating a builder from an existing
        // PDU with such an empty MP_UNREACH_NLRI, the resulting PDU will have
        // one fewer path attribute.
        let raw = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x63, 0x02, 0x00, 0x00, 0x00, 0x4c, 0x80,
            0x0f, 0x03, 0x00, 0x02, 0x01, 0x40, 0x01, 0x01,
            0x00, 0x40, 0x02, 0x12, 0x02, 0x04, 0x00, 0x00,
            0x1b, 0x1b, 0x00, 0x00, 0x95, 0x0e, 0x00, 0x00,
            0xe7, 0x8e, 0x00, 0x00, 0x46, 0x88, 0x80, 0x0e,
            0x2a, 0x00, 0x02, 0x01, 0x20, 0x20, 0x01, 0x07,
            0xf8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xa5,
            0x00, 0x69, 0x39, 0x00, 0x01, 0xfe, 0x80, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x88, 0x2f,
            0xff, 0xfe, 0xbc, 0x52, 0xdd, 0x00, 0x20, 0x24,
            0x02, 0x82, 0xc0
        ];

        let sc = SessionConfig::modern();
        let original = UpdateMessage::from_octets(&raw, &sc).unwrap();
        // XXX unsure about Ipv4UnicastNlri here
        let mut builder = UpdateBuilder::<_, Ipv4UnicastNlri>::from_update_message(
            &original,
            &sc,
            Vec::new()
        ).unwrap();

        if let Ok(Some(iter)) = 
            original.typed_withdrawals::<_, Ipv4UnicastNlri>()
        {
            for a in iter {
                builder.add_withdrawal(a.unwrap()).unwrap();
            }
        }

        if let Ok(Some(iter)) = 
            original.typed_announcements::<_, Ipv4UnicastNlri>()
        {
            for a in iter {
                builder.add_announcement(a.unwrap()).unwrap();
            }
        }

        let composed = builder.into_message(&SessionConfig::modern()).unwrap();

        assert_eq!(original.path_attributes().unwrap().count(), 4);
        assert_eq!(composed.path_attributes().unwrap().count(), 2);
    }
}
