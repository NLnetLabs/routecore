//------------ Route Status -------------------------------------------------

// Status is piece of metadata that writes some (hopefully) relevant state of
// per-peer BGP session into every route. The goal is to be able to enable
// the logic in `rib-units` to decide whether routes should be send to its
// output and to be able output this information to API clients, without
// having to go back to the units that keep the per-peer session state.
#[derive(Debug, Eq, PartialEq, Copy, Clone, Default)]
pub enum RouteStatus {
    // Between start and EOR on a BGP peer-session
    InConvergence,
    // After EOR for a BGP peer-session, either `Graceful Restart` or EOR
    UpToDate,
    // After hold-timer expiry
    Stale,
    // After the request for a Route Refresh to a peer and the reception of a
    // new route
    StartOfRouteRefresh,
    // After the reception of a withdrawal
    Withdrawn,
    // Status not relevant, e.g. a RIB that holds archived routes.
    #[default]
    Empty,
}

impl std::fmt::Display for RouteStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteStatus::InConvergence => write!(f, "in convergence"),
            RouteStatus::UpToDate => write!(f, "up to date"),
            RouteStatus::Stale => write!(f, "stale"),
            RouteStatus::StartOfRouteRefresh => {
                write!(f, "start of route refresh")
            }
            RouteStatus::Withdrawn => write!(f, "withdrawn"),
            RouteStatus::Empty => write!(f, "empty"),
        }
    }
}