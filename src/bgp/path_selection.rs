use core::fmt;
use std::cmp;
use std::net;

use inetnum::asn::Asn;
use log::trace;

use super::{
    aspath::HopPath,
    path_attributes::{BgpIdentifier, ClusterIds, PaMap},
    types::{LocalPref, MultiExitDisc, Origin, OriginatorId}
};


/// Wrapper type used for comparison and path selection.
#[derive(Copy, Clone, Debug)]
pub struct OrdRoute<'a, OS> {
    pa_map: &'a PaMap,
    tiebreakers: TiebreakerInfo,
    _strategy: std::marker::PhantomData<OS>,
}

impl<'a, OS> OrdRoute<'a, OS> {
    /// Check if all required path attributes are present and valid.
    ///
    /// This checks that:
    /// * ORIGIN must be present;
    /// * AS_PATH must be present;
    /// * AS_PATH must not be empty in case of EBGP;
    fn eligble(self) -> Result<Self, DecissionError> {
        use DecissionErrorType as DET;

        // Mandatory path attribute Origin must be present.
        if !self.pa_map.contains::<Origin>() {
            return Err(DET::MissingOrigin.into());
        }

        // Mandatory path attribute AS_PATH must be present but might be
        // empty.
        if !self.pa_map.contains::<HopPath>() {
            return Err(DET::MissingAsPath.into());
        }

        // In case of EBGP it must contain a neighbour though.
        if self.tiebreakers.source == RouteSource::Ebgp && 
            self.pa_map.get::<HopPath>().and_then(|asp|
                asp.neighbor_path_selection()
            ).is_none()
        {
            return Err(DET::EbgpWithoutNeighbour.into());
        }

        Ok(self)
    }
}


impl<'a, OS> OrdRoute<'a, OS> {
    /// Create a comparable, orderable route to be used in path selection.
    ///
    /// This function returns an error whenever the path attributes (i.e., the
    /// contents of `pa_map`) are incomplete or invalid for the path selection
    /// process. Also see [`eligble`].
    pub fn try_new(
        pa_map: &'a PaMap,
        tiebreakers: TiebreakerInfo,
    ) -> Result<Self, DecissionError> {
        Self {
            pa_map,
            tiebreakers,
            _strategy: std::marker::PhantomData
        }.eligble()
    }
}

impl<'a> OrdRoute<'a, Rfc4271> {
    /// Create a comparable route using the [`Rfc4271`] ordering strategy.
    pub fn rfc4271(
        pa_map: &'a PaMap,
        tiebreakers: TiebreakerInfo,
    ) -> Result<Self, DecissionError> {
        Self::try_new(pa_map, tiebreakers)
    }
}

impl<'a> OrdRoute<'a, SkipMed> {
    /// Create a comparable route using the [`SkipMed`] ordering strategy.
    pub fn skip_med(
        pa_map: &'a PaMap,
        tiebreakers: TiebreakerInfo,
    ) -> Result<Self, DecissionError> {
        Self::try_new(pa_map, tiebreakers)
    }
}

//------------ Traits --------------------------------------------------------

impl<'a> From<OrdRoute<'a, ()>> for OrdRoute<'a, Rfc4271> {
    fn from(src: OrdRoute<'a, ()>) -> Self {
        Self {
            pa_map: src.pa_map,
            tiebreakers: src.tiebreakers,
            _strategy: std::marker::PhantomData,
        }
    }
}

impl<'a> From<OrdRoute<'a, ()>> for OrdRoute<'a, SkipMed> {
    fn from(src: OrdRoute<'a, ()>) -> Self {
        Self {
            pa_map: src.pa_map,
            tiebreakers: src.tiebreakers,
            _strategy: std::marker::PhantomData,
        }
    }
}


/// Decision process `Ord` strategy.
///
/// For flexibility in the `Ord` implementation of routes, used in the BGP
/// Decision process (path selection), we wrap routes in a struct that is
/// generic over something implementing parts of the ordering strategy via
/// this trait.
trait OrdStrat {
    /// The RFC4271 tie breaker concerning Multi Exit Discriminator.
    fn step_c<OS>(a: &OrdRoute<OS>, b: &OrdRoute<OS>) -> cmp::Ordering;

    /// The RFC4271 tie breaker concerning interior cost.
    ///
    /// This function defaults to returning `Ordering::Equal`, effectively
    /// skipping the entire step. 
    #[allow(unused_variables)]
    fn step_e<OS>(a: &OrdRoute<OS>, b: &OrdRoute<OS>) -> cmp::Ordering {
        cmp::Ordering::Equal
    }
}

/// Decision process strategy as described in RFC 4271.
#[derive(Debug)]
pub struct Rfc4271;
impl OrdStrat for Rfc4271 {
    fn step_c<OS>(a: &OrdRoute<OS>, b: &OrdRoute<OS>) -> cmp::Ordering {
        //  c: if the neighbour ASN is the same, prefer lower MED. No MED
        //     present means the lowest MED is used
        //     also, another can of worms when it comes to ibgp vs ebgp

        // First, Determine whether 'neighbour ASN is the same.
        // If true, go on and compare the MED.
        // Otherwise, consider the routes equal and go on with step d.

        if
            a.pa_map.get::<HopPath>()
                .and_then(|asp| asp.neighbor_path_selection())
                .unwrap_or(a.tiebreakers.local_asn)
            ==
            b.pa_map.get::<HopPath>()
                .and_then(|asp| asp.neighbor_path_selection())
                .unwrap_or(b.tiebreakers.local_asn)
        {
            // neighbor ASN is considered equal, check the MEDs:
            let a_med = a.pa_map.get::<MultiExitDisc>()
                .unwrap_or(MultiExitDisc(0));
            let b_med = b.pa_map.get::<MultiExitDisc>()
                .unwrap_or(MultiExitDisc(0));
            a_med.cmp(&b_med)
        } else {
            cmp::Ordering::Equal
        }
    }
}

/// Decision process strategy skipping comparison of Multi Exit Discriminator.
#[derive(Debug)]
pub struct SkipMed;

impl OrdStrat for SkipMed {
    fn step_c<OS>(_a: &OrdRoute<OS>, _b: &OrdRoute<OS>) -> cmp::Ordering {
        std::cmp::Ordering::Equal
    }
}


impl<'a, OS: OrdStrat> PartialOrd for OrdRoute<'a, OS> {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Ordering for routes, used for comparison and thus path selection.
///
/// The ordering is such that the most preferred route comes first. In other
/// words, RouteA < RouteB means that RouteA is preferred over RouteB. In an
/// ordered collection, the first/minimum is thus the 'best path'.
///
/// **NB**: for a route to be an actual candidate in the path selection
/// process, additional checks need to be performed beforehand. Refer to
/// [`eligble`] for the specific checks.
impl<'a, OS: OrdStrat> Ord for OrdRoute<'a, OS> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        // Degree of preference
        // The DoP is taken from LOCAL_PREF in case of IBGP, or when that's
        // missing or the route comes from EBGP, the DoP is 'computed based on
        // local policy information'. 
       
        // Higher DoP is preferred over lower DoP.
        // If the DoP is explicitly passed in the OrdRoute, use that.
        // Otherwise,  check for LOCAL_PREF if ibgp. Otherwise, None/0.
        let a_dop = self.tiebreakers.degree_of_preference.or_else(|| 
            if self.tiebreakers.source == RouteSource::Ibgp {
                self.pa_map.get::<LocalPref>().map(Into::into)
            } else {
                None
            }
        ).unwrap_or(DegreeOfPreference(0));


        let b_dop = other.tiebreakers.degree_of_preference.or_else(|| 
            if other.tiebreakers.source == RouteSource::Ibgp {
                other.pa_map.get::<LocalPref>().map(Into::into)
            } else {
                None
            }
        ).unwrap_or(DegreeOfPreference(0));

        b_dop.cmp(&a_dop)
        .then_with(||{
        trace!("equal after DoP");
        // Tie breakers
        //
        // Some notes/questions/remarks:
        //  - is there an actual 'default Local Pref value' or is that a
        //  vendor specific thing? many vendor docs mention 100 being the
        //  default
        //  - many online explanations include a 'prefer route that is older /
        //  was learned first' between steps e and f
        //  - the 'weight' that many explanations start out with is a Cisco
        //  specific thing. e.g. a locally originated route gets the max
        //  weight of 32768 and is preferred over everything else.
        //  - after the IGP cost comparison (which we don't do currently),
        //  paths are considered 'equal-cost' and can be used in a BGP
        //  multipath scenario. Can we incorporate this in the Ord impl
        //  somehow? Perhaps introduce (another) wrapper(s) in addition to
        //  OrdRoute that compare only up to that step and after that step,
        //  respectively (which, combined, does the same as OrdRoute currently
        //  does)?
        //  - another possible 'split up point', that also comes after the IGP
        //  cost comparison: in JunOS, when the compared paths are both
        //  external and one is already active, prefer that active one to
        //  minimize route flapping. 
        //
        //  seems that the big vendors all have their custom config switches
        //  to enable/disable/tune certain parts of the tie breakers. Perhaps
        //  we can come up with a way to do such fine-grained tuning (with
        //  minimal user input from say roto required).


        //  a: prefer the shorter aspath len (AS_SET counts as 1)

        match (self.pa_map.get::<HopPath>(), other.pa_map.get::<HopPath>()) {
            (Some(a), Some(b)) => a.hop_count_path_selection().cmp(&b.hop_count_path_selection()),
            (_, _) => {
                panic!("can not compare routes lacking AS_PATH");
                //cmp::Ordering::Equal
            }
        }}).then_with(||{
        trace!("equal after step a");
        //  b: prefer the lower Origin
            match (self.pa_map.get::<Origin>(), other.pa_map.get::<Origin>()) {
                (Some(a), Some(b)) => a.cmp(&b),
                (_, _) => cmp::Ordering::Equal,
            }
        }).then_with(||{
        trace!("equal after step b");

        // The RFC4271 step C is as follows, and the `Rfc4271` impl of
        // `OrdStrat` does just that. The `SkipMed` strategy skips this step.
        //  c: if the neighbour ASN is the same, prefer lower MED. No MED
        //     present means the lowest MED (== 0) is used.
        //

            OS::step_c(self, other)
        }).then_with(||{
        trace!("equal after step c");
        //  d: EBGP is preferred over all IBGP 
            self.tiebreakers.source.cmp(&other.tiebreakers.source)
        }).then_with(||{
        //  e: prefer lower interior cost, or treat all equally if we can not
        //     determine this
            OS::step_e(self, other)
        }).then_with(||{
        trace!("equal after step d+e");
        //  f: prefer the lower BGP Identifier value
        //     *addition from RFC4456 (Route Reflection)*:
        //     If a route carries the ORIGINATOR_ID attribute,
        //     the ORIGINATOR_ID SHOULD be treated as the BGP Identifier of
        //     the BGP speaker that has advertised the route.
            self.pa_map.get::<OriginatorId>()
                .map(|id| id.0.octets())
                .unwrap_or(self.tiebreakers.bgp_identifier.into())
                .cmp(
                    &other.pa_map.get::<OriginatorId>()
                    .map(|id| id.0.octets())
                    .unwrap_or(other.tiebreakers.bgp_identifier.into())
                )

        }).then_with(||{
        trace!("equal after step f");

        // RFC4456 (Route Reflection):
        // the following rule SHOULD be inserted between Steps f) and g):
        // a BGP Speaker SHOULD prefer a route with the shorter CLUSTER_LIST
        // length.  The CLUSTER_LIST length is zero if a route does not carry
        // the CLUSTER_LIST attribute.
            self.pa_map.get::<ClusterIds>()
                .map(|l| l.len()).unwrap_or(0).cmp(
                &other.pa_map.get::<ClusterIds>()
                    .map(|l| l.len()).unwrap_or(0)
            )
        }).then_with(||{
        trace!("equal after step f2");
        //  g: prefer the lower peer address
            self.tiebreakers.peer_addr.cmp(&other.tiebreakers.peer_addr)
        }).then_with(||{
            // this shouldn't happen when doing actual best path selection!
            trace!("equal at end of tie breakers");
            cmp::Ordering::Equal
        })
    }
}

impl<'a, OS: OrdStrat> Eq for OrdRoute<'a, OS> {}


impl<'a, OS: OrdStrat> PartialEq for OrdRoute<'a, OS> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}


//------------ Tiebreaker types ----------------------------------------------

/// Additional information required for the Decision Process.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct TiebreakerInfo {
    source: RouteSource,
    degree_of_preference: Option<DegreeOfPreference>,
    local_asn: Asn,
    bgp_identifier: BgpIdentifier,
    peer_addr:  net::IpAddr,
}


/// Describes whether the route was learned externally or internally.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum RouteSource {
    Ebgp,
    Ibgp,
}

/// The Degree of Preference used in Phase 1 of the Decision Process.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct DegreeOfPreference(pub u32);

impl From<LocalPref> for DegreeOfPreference {
    fn from(value: LocalPref) -> Self {
        Self(value.0)
    }
}

//------------ Errors --------------------------------------------------------

#[derive(Copy, Clone, Debug)]
pub struct DecissionError {
    error_type: DecissionErrorType
}

impl fmt::Display for DecissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.error_type, f)
    }
}

impl std::error::Error for DecissionError { }

#[allow(unused)]
#[derive(Copy, Clone, Debug)]
enum DecissionErrorType {
    EbgpWithoutNeighbour,
    AsPathLoop,
    MissingAsPath,
    MissingOrigin,
}

impl From<DecissionErrorType> for DecissionError {
    fn from(det: DecissionErrorType) -> Self {
        DecissionError { error_type: det }
    }
}

impl fmt::Display for DecissionErrorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use DecissionErrorType as DET;
        match self {
            DET::EbgpWithoutNeighbour => {
                write!(f, "expected non-empty AS_PATH")
            }
            DET::AsPathLoop => write!(f, "AS_PATH loop"),
            DET::MissingAsPath => write!(f, "missing mandatory AS_PATH"),
            DET::MissingOrigin => write!(f, "missing mandatory ORIGIN"),
        }
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use crate::bgp::types::OriginType;

    use super::*;

    #[test]
    fn test1() {

        let mut attrs1 = PaMap::empty();
        let asp = HopPath::from([Asn::from_u32(100), Asn::from_u32(200)]);
        
        attrs1.set(Origin::from(OriginType::Egp));
        attrs1.set(asp);

        let tiebreakers = TiebreakerInfo {
            source: RouteSource::Ebgp,
            degree_of_preference: None,
            local_asn: Asn::from_u32(1234),
            bgp_identifier: [1, 2, 3, 4].into(),
            peer_addr: "9.9.9.9".parse().unwrap(),
        };

        let route1 = OrdRoute::rfc4271(
            &attrs1,
            tiebreakers,
        ).unwrap();

        let mut attrs2 = PaMap::empty();
        let asp = HopPath::from([
            Asn::from_u32(100),
            Asn::from_u32(200),
            Asn::from_u32(300),

        ]);
        
        attrs2.set(Origin::from(OriginType::Egp));
        attrs2.set(asp);

        let route2 = OrdRoute::rfc4271(
            &attrs2,
            tiebreakers,
        ).unwrap();


        assert!(route1 < route2);
    }
}
