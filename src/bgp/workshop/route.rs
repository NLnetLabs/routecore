use std::fmt::Debug;
use std::hash::Hash;
//use std::marker::PhantomData;

use octseq::{Octets, OctetsFrom};

use crate::bgp::communities::Community;
use crate::bgp::message::update_builder::{ComposeError, /*MpReachNlriBuilder*/};
use crate::bgp::message::UpdateMessage;
use crate::bgp::path_attributes::{FromAttribute, PaMap};
use crate::bgp::{
    message::{
        //nlri::Nlri,
        update_builder::StandardCommunitiesList
    },
    path_attributes::{
        ExtendedCommunitiesList, Ipv6ExtendedCommunitiesList,
        LargeCommunitiesList, PathAttribute, 
    },
};

use crate::bgp::nlri::afisafi::{AfiSafiType, Nlri};
use crate::bgp::nlri::nexthop::NextHop;
use crate::bgp::types::ConventionalNextHop;

//------------ TypedRoute ----------------------------------------------------

#[derive(Debug)]
pub enum TypedRoute<N: Clone + Debug + Hash> {
    Announce(Route<N>),
    Withdraw(Nlri<N>),
}


//------------ Route ---------------------------------------------------------

#[derive(Debug, Eq, PartialEq, Clone, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Route<N: Clone + Debug + Hash>(N, PaMap);

impl<N: Clone + Debug + Hash> Route<N> {
    pub fn new(nlri: N, attrs: PaMap) -> Self {
        Self(nlri, attrs)
    }

    pub fn nlri(&self) -> &N {
        &self.0
    }

    pub fn get_attr<A: FromAttribute + Clone>(&self) -> Option<A> {
        if A::attribute_type().is_some() {
            self.1.get::<A>()
        } else {
            None
        }
    }

    pub fn attributes(&self) -> &PaMap {
        &self.1
    }

    pub fn attributes_mut(&mut self) -> &mut PaMap {
        &mut self.1
    }
}


//------------ From impls for PathAttribute ----------------------------------

impl From<crate::bgp::aspath::AsPath<bytes::Bytes>> for PathAttribute {
    fn from(value: crate::bgp::aspath::AsPath<bytes::Bytes>) -> Self {
        PathAttribute::AsPath(value.to_hop_path())
    }
}

impl From<crate::bgp::aspath::AsPath<Vec<u8>>> for PathAttribute {
    fn from(value: crate::bgp::aspath::AsPath<Vec<u8>>) -> Self {
        PathAttribute::AsPath(value.to_hop_path())
    }
}


//------------ The Workshop --------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct RouteWorkshop<N>(N, Option<NextHop>, PaMap);

impl<N: AfiSafiNlri + Clone + Debug + Hash> RouteWorkshop<N> {

    /// Creates an empty RouteWorkshop.
    ///
    /// The resulting RouteWorkshop has its NextHop set to `None` and an empty
    /// [`PaMap`].
    pub fn new(nlri: N) -> Self {
        Self(nlri, None, PaMap::empty())
    }

    /// Creates a RouteWorkshop from one NLRI and a [`PaMap`].
    ///
    /// No logic is applied to the contents of the attributes in the PaMap.
    /// When creating a RouteWorkshop via this constructor, the caller needs
    /// to ensure the contents of the PaMap are sensible for the provided
    /// NLRI.
    ///
    /// Consider using [`RouteWorkshop::from_update_pdu`] when the original
    /// PDU is available.
    // XXX do we actually need and want this?
    pub fn from_pa_map(nlri: N, pa_map: PaMap) -> Self {
        Self(nlri, None, pa_map)
    }

        
    /// Creates a RouteWorkshop from one NLRI and its BGP [`UpdateMessage`].
    ///
    /// Based on the type of NLRI, i.e. conventional or Multi Protocol, the
    /// Next Hop from the NEXT_HOP path attribute or the field in the
    /// MP_REACH_NLRI attribute is set in the resulting RouteWorkshop.
    /// In both cases, the NEXT_HOP path attribute is omitted from the
    /// attached [`PaMap`].
    pub fn from_update_pdu<Octs: Octets>(
        nlri: N,
        pdu: &UpdateMessage<Octs>,
    ) -> Result<Self, ComposeError>
    where
        for<'a> Vec<u8>: OctetsFrom<Octs::Range<'a>>,
    {
        let mut res = Self::new(nlri);

        if N::afi_safi() == AfiSafiType::Ipv4Unicast &&
            pdu.has_conventional_nlri()
        {
            if let Ok(Some(nh)) = pdu.conventional_next_hop() {
                res.set_nexthop(nh);
                let mut pamap = PaMap::from_update_pdu(pdu)?;
                let _ = pamap.remove::<ConventionalNextHop>();
                res.set_attributes(pamap);
                return Ok(res);
            } else {
                return Err(ComposeError::InvalidAttribute);
            }
        }

        if let Ok(Some(nh)) = pdu.mp_next_hop() {
            res.set_nexthop(nh);
            let mut pamap = PaMap::from_update_pdu(pdu)?;
            let _ = pamap.remove::<ConventionalNextHop>();
            res.set_attributes(pamap);
            Ok(res)
        } else {
            Err(ComposeError::InvalidAttribute)
        }
    }


    /// Validates the contents of this RouteWorkshop.
    ///
    /// If the combination of the various pieces of content in this
    /// RouteWorkshop could produce a valid BGP UPDATE PDU, this method
    /// returns `Ok(())`. The following checks are performed:
    ///
    ///  * The NextHop is set, and is compatible with the NLRI type.
    pub fn validate(&self) -> Result<(), ComposeError> {
        match self.1 {
            None     => { return Err(ComposeError::InvalidAttribute); }
            Some(nh) => {
                // TODO
                /*
                if !self.0.allowed_next_hops().any(|a| a == nh.afi_safi()) {
                    return Err(ComposeError::IllegalCombination);
                }
                */
            }
        }
        Ok(())
    }

    pub fn nlri(&self) -> &N {
        &self.0
    }

    pub fn nexthop(&self) -> &Option<NextHop> {
        &self.1
    }

    pub fn set_nexthop(&mut self, nh: NextHop) -> Option<NextHop> {
        self.1.replace(nh)
    }

    pub fn set_attr<WA: WorkshopAttribute<N>>(
        &mut self,
        value: WA,
    ) -> Result<(), ComposeError> {
        WA::store(value, &mut self.2)
    }

    pub fn get_attr<A: WorkshopAttribute<N>>(
        &self,
    ) -> Option<A> {
        self.2.get::<A>().or_else(|| A::retrieve(&self.2))
    }

    pub fn clone_into_route(&self) -> Route<N> {
        Route::<N>(self.0.clone(), self.2.clone())
    }

    pub fn into_route(self) -> Route<N> {
        Route::<N>(self.0, self.2)
    }

    pub fn attributes(&self) -> &PaMap {
        &self.2
    }

    pub fn set_attributes(&mut self, pa_map: PaMap) {
        self.2 = pa_map;
    }

    pub fn attributes_mut(&mut self) -> &mut PaMap {
        &mut self.2
    }
}

macro_rules! impl_workshop {
    (
        $( $attr:ty )+
    ) => {
        $(
            impl<N: Clone + Hash + Debug> WorkshopAttribute<N> for $attr {
                fn store(local_attrs: Self, attrs: &mut PaMap) ->
                    Result<(), ComposeError> { attrs.set(local_attrs); Ok(()) }
                fn retrieve(_attrs: &PaMap) ->
                    Option<Self> { None }
            }
        )+
    }
}

impl_workshop!(
    crate::bgp::aspath::HopPath
    crate::bgp::types::LocalPref
    crate::bgp::types::MultiExitDisc
    crate::bgp::types::Origin
    crate::bgp::types::OriginatorId
    crate::bgp::path_attributes::AggregatorInfo
    crate::bgp::path_attributes::ExtendedCommunitiesList
    crate::bgp::path_attributes::AsPathLimitInfo
    crate::bgp::path_attributes::Ipv6ExtendedCommunitiesList
    crate::bgp::path_attributes::LargeCommunitiesList
    crate::bgp::path_attributes::ClusterIds
    crate::bgp::message::update_builder::StandardCommunitiesList
    crate::bgp::types::Otc
    //crate::bgp::message::update_builder::MpReachNlriBuilder
);


//------------ WorkshopAttribute ---------------------------------------------

pub trait WorkshopAttribute<N>: FromAttribute {
    fn retrieve(attrs: &PaMap) -> Option<Self>
    where
        Self: Sized;
    fn store(
        local_attrs: Self,
        attrs: &mut PaMap,
    ) -> Result<(), ComposeError>;
}

//------------ CommunitiesWorkshop -------------------------------------------

impl<N: Clone + Hash + Debug> WorkshopAttribute<N> for Vec<Community> {
    fn retrieve(attrs: &PaMap) -> Option<Self> {
        let mut c = attrs
            .get::<StandardCommunitiesList>()
            .map(|c| c.fmap(|c| Community::Standard(*c)))
            .unwrap_or_default();
        c.append(
            &mut attrs
                .get::<ExtendedCommunitiesList>()
                .map(|c| c.fmap(Community::Extended))
                .unwrap_or_default()
        );
        c.append(
            &mut attrs
                .get::<Ipv6ExtendedCommunitiesList>()
                .map(|c| c.fmap(Community::Ipv6Extended))
                .unwrap_or_default()
        );
        c.append(
            &mut attrs
                .get::<LargeCommunitiesList>()
                .map(|c| c.fmap(Community::Large))
                .unwrap_or_default()
        );

        Some(c)
    }

    fn store(
        local_attr: Self,
        attrs: &mut PaMap,
    ) -> Result<(), ComposeError> {
        for comm in local_attr {
            match comm {
                Community::Standard(c) => {
                    if let Some(mut b) =
                        attrs.get::<StandardCommunitiesList>()
                    {
                        b.add_community(c)
                    }
                }
                Community::Extended(c) => {
                    if let Some(mut b) =
                        attrs.get::<ExtendedCommunitiesList>()
                    {
                        b.add_community(c)
                    }
                }
                Community::Ipv6Extended(c) => {
                    if let Some(mut b) =
                        attrs.get::<Ipv6ExtendedCommunitiesList>()
                    {
                        b.add_community(c)
                    }
                }
                Community::Large(_) => todo!(),
            };
        }

        Ok(())
    }
}

impl FromAttribute for Vec<Community> { }

//------------ NlriWorkshop --------------------------------------------------

impl FromAttribute for Nlri<Vec<u8>> { }

/*
impl<N: Clone + Hash> WorkshopAttribute<N> for Nlri<Vec<u8>> {
    fn retrieve(attrs: &PaMap) -> Option<Self>
    where
        Self: Sized {
        attrs.get::<MpReachNlriBuilder>().and_then(|mr| mr.first_nlri())
    }

    fn store(
        local_attr: Self,
        attrs: &mut PaMap,
    ) -> Result<(), ComposeError> {
        if let Some(mut nlri) = attrs.get::<MpReachNlriBuilder>() {
            nlri.set_nlri(local_attr)
        } else {
            Err(ComposeError::InvalidAttribute)
        }
    }
}
*/

//------------ NextHopWorkshop -----------------------------------------------

impl FromAttribute for crate::bgp::types::NextHop { }

/*
impl<N: Clone + Hash> WorkshopAttribute<N> for crate::bgp::types::NextHop {
    fn retrieve(attrs: &PaMap) -> Option<Self> {
        if let Some(next_hop) =
            attrs.get::<crate::bgp::types::ConventionalNextHop>()
        {
            Some(crate::bgp::types::NextHop::Unicast(next_hop.0.into()))
        } else if let Some(nlri) = attrs.get::<MpReachNlriBuilder>() {
            Some(*nlri.get_nexthop())
        } else {
            Some(crate::bgp::types::NextHop::Empty)
        }
    }

    fn store(
        local_attr: Self,
        attrs: &mut PaMap,
    ) -> Result<(), ComposeError> {
        if let Some(mut nlri) = attrs.get::<MpReachNlriBuilder>() {
            nlri.set_nexthop(local_attr)?;
            attrs.set(nlri).ok_or(ComposeError::InvalidAttribute)?;
            Ok(())
        } else {
            Err(ComposeError::InvalidAttribute)
        }
    }
}
*/



//-----------------------------------------------------------------------------

use crate::bgp::nlri::afisafi::{AfiSafiNlri, AfiSafiParse};

pub fn pdu_into_rws<'a, Octs, T, R>(pdu: &'a UpdateMessage<Octs>) -> Vec<T>
where
    Octs: 'a + Octets<Range<'a> = R>,
    R: Hash + Clone + Debug,
    Vec<u8>: From<Octs::Range<'a>>,
    T: From<RouteWorkshop<Nlri<R>>>,
    //Nlri<R>//: AfiSafiNlri // + Hash + Debug
{

    let pa_map = PaMap::from_update_pdu(pdu).unwrap();

    let mut res = Vec::new();
    for a in pdu.announcements().unwrap() {
        res.push(
            T::from(
                RouteWorkshop::from_pa_map(a.unwrap(), pa_map.clone())
            )
        );
    }

    res
}

pub fn pdu_into_typed_rws<'a, Octs, T, R, AFN>(pdu: &'a UpdateMessage<Octs>) -> Vec<T>
where
    Octs: 'a + Octets<Range<'a> = R>,

    //R: Hash + Clone + Debug + Octets,
    T: From<RouteWorkshop<AFN>>,
    AFN: AfiSafiNlri + AfiSafiParse<'a, R, Octs, Output = AFN>,

    R: Octets,
    Vec<u8>: OctetsFrom<R>,
{

    let pa_map = PaMap::from_update_pdu(pdu).unwrap();

    let mut res = Vec::new();
    if let Ok(Some(iter)) = pdu.typed_announcements::<_, AFN>() {
        for a in iter {
            res.push(
                T::from(
                    RouteWorkshop::from_pa_map(a.unwrap(), pa_map.clone())
                )
            );
        }
    } else {
        eprintln!("empty or invalid NLRI iter");
    }

    res
}



pub fn pdu_into_rws_iter<'a, Octs, T, R>(pdu: &'a UpdateMessage<Octs>)
-> impl Iterator<Item = T> + '_
where
    Octs: 'a + Octets<Range<'a> = R>,
    R: Hash + Clone + Debug,
    Vec<u8>: From<Octs::Range<'a>>,
    T: From<RouteWorkshop<Nlri<R>>>,
    //Nlri<R>//: AfiSafiNlri // + Hash + Debug
{

    let pa_map = PaMap::from_update_pdu(pdu).unwrap();

    pdu.announcements().unwrap().map(move |a|
        T::from(
            RouteWorkshop::from_pa_map(a.unwrap(), pa_map.clone())
        )
    )
}


// XXX to be moved to roto
/*
pub fn pdu_into_rws_basic_iter<'a, Octs, R>(pdu: &'a UpdateMessage<Octs>)
-> impl Iterator<Item = RouteWorkshop<BasicNlri>> + '_
where
    Octs: 'a + Octets<Range<'a> = R>,
    R: Hash + Clone + Debug,
    Vec<u8>: From<Octs::Range<'a>>,
{

    let pa_map = PaMap::from_update_pdu(pdu).unwrap();

    pdu.announcements().unwrap().filter_map(move |a|
        a.ok().map(|n| BasicNlri::try_from(n).ok()).map(|a|
        RouteWorkshop::from_pa_map(a.unwrap(), pa_map.clone())
    ))
}
*/



// XXX to be moved to roto
/*
//------------ BasicNlri again ------------------------------------------------

use inetnum::addr::Prefix;
use std::fmt;
use crate::bgp::nlri::afisafi::{AfiSafiType, IsPrefix};
use crate::bgp::types::PathId;


#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct BasicNlri {
    ty: AfiSafiType,
    prefix: Prefix,
    path_id: Option<PathId>
}

impl BasicNlri {
    pub fn prefix(&self) -> Prefix {
        self.prefix
    }

    pub fn path_id(&self) -> Option<PathId> {
        self.path_id
    }

    pub fn get_type(&self) -> AfiSafiType {
        self.ty
    }
}

impl fmt::Display for BasicNlri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.prefix)
    }
}

impl<N: IsPrefix> From<N> for BasicNlri {
    fn from(n: N) -> BasicNlri {
        BasicNlri {
            ty: N::afi_safi(),
            prefix: n.prefix(),
            path_id: n.path_id(),
        }
    }
}


impl<N> From<RouteWorkshop<N>> for RouteWorkshop<BasicNlri>
where N: IsPrefix
{
    fn from(value: RouteWorkshop<N>) -> Self {
        RouteWorkshop(value.0.into(), value.1)
    }
}


impl<O> TryFrom<Nlri<O>> for BasicNlri {
    type Error = &'static str;

    fn try_from(n: Nlri<O>) -> Result<Self, Self::Error> {
        match n {
            Nlri::Ipv4Unicast(n) => Ok(n.into()),
            Nlri::Ipv4UnicastAddpath(n) => Ok(n.into()),
            Nlri::Ipv4Multicast(n) => Ok(n.into()),
            Nlri::Ipv4MulticastAddpath(n) => Ok(n.into()),
            Nlri::Ipv6Unicast(n) => Ok(n.into()),
            Nlri::Ipv6UnicastAddpath(n) => Ok(n.into()),
            Nlri::Ipv6Multicast(n) => Ok(n.into()),
            Nlri::Ipv6MulticastAddpath(n) => Ok(n.into()),
            _ => Err("NLRI not basic"),
        }
    }
}

*/


#[allow(unused_imports)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::message::update::SessionConfig;

    use crate::bgp::nlri::afisafi::{
        Ipv4UnicastNlri,
        Ipv6UnicastNlri,
        Ipv6UnicastAddpathNlri,
        Ipv4FlowSpecNlri,
    };


    #[test]
    fn pdu_into_rws_vec() {

        // UPDATE with 5 ipv6 nlri
        let raw = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            //0x00, 0x88,
            0x00, 0x88 + 6,
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
            16, 1, 2,
            16, 10, 20

        ];
        let pdu = UpdateMessage::from_octets(&raw, &SessionConfig::modern())
            .unwrap();

        //let res: Vec<RouteWorkshop<_>> = pdu_into_rws(&pdu);
        let res: Vec<RouteWorkshop<_>> = pdu_into_rws(&pdu);
        assert_eq!(res.len(), 7);
        for rws in res {
            println!("{}", rws.nlri());
        }
    }

    #[test]
    fn pdu_into_rws_iter_test() {

        // UPDATE with 5 ipv6 nlri + 2 conventional
        let raw = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            //0x00, 0x88,
            0x00, 0x88 + 6,
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
            16, 1, 2,
            16, 10, 20

        ];
        let pdu = UpdateMessage::from_octets(&raw, &SessionConfig::modern())
            .unwrap();

        assert_eq!(pdu_into_rws_iter::<_, RouteWorkshop<_>, _>(&pdu).count(), 7);
    }

    //XXX to be moved to roto
    /*
    #[test]
    fn pdu_into_rws_typed() {

        // UPDATE with 5 ipv6 nlri + 2 conventional
        let raw = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            //0x00, 0x88,
            0x00, 0x88 + 6,
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
            16, 1, 2,
            16, 10, 20

        ];
        let pdu = UpdateMessage::from_octets(&raw, &SessionConfig::modern())
            .unwrap();

        let res = pdu_into_typed_rws::<_, RouteWorkshop<BasicNlri>, _, Ipv6UnicastNlri>(&pdu);
        for rws in &res {
            println!("{}", rws.nlri());
        }
        assert_eq!(res.len(), 5);

        let res = pdu_into_typed_rws::<_, RouteWorkshop<BasicNlri>, _, Ipv4UnicastNlri>(&pdu);
        for rws in &res {
            println!("{}", rws.nlri());
        }
        assert_eq!(res.len(), 2);

        let res = pdu_into_typed_rws::<_, RouteWorkshop<_>, _, Ipv4FlowSpecNlri<_>>(&pdu);
        for rws in &res {
            println!("{}", rws.nlri());
        }
        assert_eq!(res.len(), 0);
    }

    #[test]
    fn pdu_into_basic() {

        // UPDATE with 5 ipv6 nlri + 2 conventional
        let raw = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            //0x00, 0x88,
            0x00, 0x88 + 6,
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
            16, 1, 2,
            16, 10, 20

        ];
        let pdu = UpdateMessage::from_octets(&raw, &SessionConfig::modern())
            .unwrap();

        let res = pdu_into_rws_basic_iter(&pdu);
        for rws in res {
            println!("{}", rws.nlri());
        }
        let res = pdu_into_rws_basic_iter(&pdu);
        assert_eq!(res.count(), 7);

    }

*/


}
