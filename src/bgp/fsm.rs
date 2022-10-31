use log::{info, error, warn};

#[derive(Clone, Copy, Debug)]
pub struct SessionAttributes {
    // mandatory
    
    state: State, // nr 1, etc
    connect_retry_counter: usize,
    connect_retry_timer: u16, //current value
    connect_retry_time: u16,  // initial value
    hold_timer: u16,         // current value
    hold_time: u16,          // initial value
    keepalive_timer: u16,
    keepalive_time: u16, //nr 8

    // optional
/*
    AcceptConnectionsUnconfiguredPeers, // nr 1, etc
    AllowAutomaticStart,
    AllowAutomaticStop,
    CollisionDetectEstablishedState,
    DampPeerOscillations, // group 2
    // group 1
    DelayOpen,
    DelayOpenTime,
    DelayOpenTimer,
    // --
    IdleHoldTime, // group 2
    IdleHoldTimer, // group 2
    PassiveTcpEstablishment,
    SendNOTIFICATIONwithoutOPEN,
    TrackTcpState, // nr 13
*/
}

impl SessionAttributes {
    pub fn state(self) -> State {
        self.state
    }
}

impl Default for SessionAttributes {
    fn default() -> Self {
        SessionAttributes {
            state: State::Idle,
            connect_retry_counter: 0,
            connect_retry_timer: 120,
            connect_retry_time: 120,
            hold_timer: 90,
            hold_time: 90,
            keepalive_timer: 30,
            keepalive_time: 30,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum State {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

#[derive(Clone, Copy, Debug)]
pub enum Event {
    // mandatory
    ManualStart, // 1
    ManualStop, // 2

    /*  events 3 - 8
    // optional
    AutomaticStart, 
    ManualStartWithPassiveTcpEstablishment,
    AutomaticStartWithPassiveTcpEstablishment,
    AutomaticStartWithDampPeerOscillations,
    AutomaticStartWithDampPeerOscillationsAndPassiveTcpEstablishment,
    AutomaticStop,
    */


    // mandatory timer events

    ConnectRetryTimerExpires, // 9
    HoldTimerExpires, // 10
    KeepaliveTimerExpires, // 11

    /*
    // optional timer events
    DelayOpenTimerExpires, // 12
    IdleHoldTimerExpires, // 13
    */

    /*
    // optional TCP connection-based events
    TcpConnectionValid, // 14
    TcpCrInvalid, //15
    */

    // mandatory TCP connection-based events
    TcpCrAcked, // 16
    TcpConnectionConfirmed, // 17
    TcpConnectionFails, // 18


    // mandatory BGP message-based events
    BgpOpen, // 19

    BgpHeaderErr, // 21
    BgpOpenMsgErr, // 22

    NotifMsgVerErr, // 24
    NotifMsg, // 25
    KeepAliveMsg, // 26
    UpdateMsg, // 27
    UpdateMsgErr, // 28


    /*
    // optional BGP message-based events
    
    BgpOpenWithDelayOpenTimerRunning, // event 20
    OpenCollisionDump, // event 23
    */

}


//---
pub struct BgpSession {
    session_attributes: SessionAttributes
}

impl BgpSession {
    pub fn new() -> Self {
        Self {session_attributes: SessionAttributes::default() }
    }
    fn session(&self) -> SessionAttributes {
        self.session_attributes
    }

    pub fn handle_event(&self, event: Event) {
        use State as S;
        use Event as E;
        match (self.session().state(), event) {
            //--- Idle -------------------------------------------------------
            (S::Idle, E::ManualStart) => { todo!() }
            (S::Idle, E::ManualStop) => {
                info!("ignored ManualStop in Idle state")
            }
            // optional events:
            //(S::Idle, E::AutomaticStart) => { ... }
            //(S::Idle, E::AutomaticStop) => { /* ignore */ }
            //(S::Idle, E::ManualStartWithPassiveTcpEstablishment) => { }
            //(S::Idle, E::AutomaticStartWithPassiveTcpEstablishment) => { }
            
            // if DampPeerOscillations is TRUE:
            //(S::Idle, E::AutomaticStartWithDampPeerOscillations) => { }
            //(S::Idle, E::AutomaticStartWithDampPeerOscillationsAndPassiveTcpEstablishment) => { }
            //(S::Idle, E::IdleHoldTimerExpires) => { }
            (S::Idle, e) => warn!("unexpected event {:?} in state Idle", e),

            //--- Connect ----------------------------------------------------
            (S::Connect, E::ManualStart /* | events 3-7 */ ) => {
                info!("ignored {:?} in state Connect", event)
            }
            (S::Connect, E::ManualStop) => { todo!() }
            (S::Connect, E::ConnectRetryTimerExpires) => { todo!() }
            // optional events:
            //(S::Connect, E::DelayOpenTimerExpires) => {}
            //(S::Connect, E::TcpConnectionValid) => {}
            //(S::Connect, E::TcpCrInvalid) => {}
            
            (S::Connect, E::TcpCrAcked | E::TcpConnectionConfirmed) => {
                todo!()
            }
            (S::Connect, E::TcpConnectionFails) => { todo!() }
            // optional:
            //(S::Connect, E::BgpOpenWithDelayOpenTimerRunning) => {}
            (S::Connect, E::BgpHeaderErr | E::BgpOpenMsgErr) => { todo!() }
            (S::Connect, E::NotifMsgVerErr) => { todo!() }
            (S::Connect, 
                //E::AutomaticStop |
                E::HoldTimerExpires |
                E::KeepaliveTimerExpires |
                //E::IdleHoldTimerExpires |
                E::BgpOpen |
                //E::OpenCollisionDump |
                E::NotifMsg |
                E::KeepAliveMsg |
                E::UpdateMsg |
                E::UpdateMsgErr
                ) => { todo!() }


            //--- Active -----------------------------------------------------
            (S::Active, E::ManualStart /* | events 3-7 */ ) => {
                info!("ignored {:?} in state Active", event)
            }
            (S::Active, E::ManualStop) => { todo!() }
            (S::Active, E::ConnectRetryTimerExpires) => { todo!() }
            // optional:
            //(S::Active, E::DelayOpenTimerExpires) => { todo!() }
            //(S::Active, E::TcpConnectionValid) => { todo!() }
            //(S::Active, E::TcpCrInvalid) => { todo!() }
            (S::Active, E::TcpCrAcked | E::TcpConnectionConfirmed) => {
                todo!()
            }
            (S::Active, E::TcpConnectionFails) => { todo!() }
            // optional:
            //(S::Active, E::BgpOpenWithDelayOpenTimerRunning) => { todo!() }

            (S::Active, E::BgpHeaderErr) => { todo!() }
            (S::Active, E::BgpOpenMsgErr) => { todo!() }

            (S::Active, E::NotifMsgVerErr) => { todo!() }

            (S::Active, 
                //E::AutomaticStop |
                E::HoldTimerExpires |
                E::KeepaliveTimerExpires |
                //E::IdleHoldTimerExpires |
                E::BgpOpen |
                //E::OpenCollisionDump |
                E::NotifMsg |
                E::KeepAliveMsg |
                E::UpdateMsg |
                E::UpdateMsgErr
                ) => { todo!() }


            //--- OpenSent ---------------------------------------------------

            (S::OpenSent, E::ManualStart /* | events 3-7 */ ) => {
                info!("ignored {:?} in state OpenSent", event)
            }
            (S::OpenSent, E::ManualStop) => { todo!() }
            // optional: 
            //S::OpenSent, E::AutomaticStop) => { todo!() }
            (S::OpenSent, E::HoldTimerExpires) => { todo!() }

            (S::OpenSent,
             //E::TcpConnectionValid | // optional
             E::TcpCrAcked | E::TcpConnectionConfirmed ) => { todo!() }

            // optional:
            //(S::OpenSent, E::TcpCrInvalid) => { 
            //    info!("ignored {:?} in state OpenSent", event)
            //}

            (S::OpenSent, E::TcpConnectionFails) => { todo!() }
            (S::OpenSent, E::BgpOpen) => { todo!() }
            (S::OpenSent, E::BgpHeaderErr | E::BgpOpenMsgErr) => { todo!() }
            // optional:
            //(S::OpenSent, E::OpenCollisionDump) => { todo!() }
            (S::OpenSent, E::NotifMsgVerErr) => { todo!() }

            (S::OpenSent, 
                E::ConnectRetryTimerExpires |
                E::KeepaliveTimerExpires |
                //E::DelayOpenTimerExpires |
                //E::IdleHoldTimerExpires |
                //E::BgpOpenWithDelayOpenTimerRunning |
                E::NotifMsg |
                E::KeepAliveMsg |
                E::UpdateMsg |
                E::UpdateMsgErr
            ) => { todo!() }

            
            //--- OpenConfirm ------------------------------------------------


            (S::OpenConfirm, E::ManualStart /* | events 3-7 */ ) => {
                info!("ignored {:?} in state OpenConfirm", event)
            }

            (S::OpenConfirm, E::ManualStop) => { todo!() }
            // optional: 
            //(S::OpenConfirm, E::AutomaticStop) => { todo!() }
           
            (S::OpenConfirm, E::HoldTimerExpires) => { todo!() }
            (S::OpenConfirm, E::KeepaliveTimerExpires) => { todo!() }

            (S::OpenConfirm,
             //E::TcpConnectionValid | // optional
             E::TcpCrAcked | E::TcpConnectionConfirmed ) => { todo!() }


            // optional:
            //(S::OpenConfirm, E::TcpCrInvalid) => { 
            //    info!("ignored {:?} in state OpenConfirm", event)
            //}

            (S::OpenConfirm, E::TcpConnectionFails | E::NotifMsg ) => { todo!() }
            (S::OpenConfirm, E::NotifMsgVerErr) => { todo!() }
            (S::OpenConfirm, E::BgpOpen) => { todo!() }
            (S::OpenConfirm, E::BgpHeaderErr | E::BgpOpenMsgErr) => { todo!() }
            // optional:
            //(S::OpenConfirm, E::OpenCollisionDump) => { todo!() }
            (S::OpenConfirm, E::KeepAliveMsg) => { todo!() }

            (S::OpenConfirm, 
                E::ConnectRetryTimerExpires |
                //E::DelayOpenTimerExpires |
                //E::IdleHoldTimerExpires |
                //E::BgpOpenWithDelayOpenTimerRunning |
                E::UpdateMsg |
                E::UpdateMsgErr
            ) => { todo!() }

            //--- Established ------------------------------------------------

            (S::Established, E::ManualStart /* | events 3-7 */ ) => {
                info!("ignored {:?} in state Established", event)
            }
            (S::Established, E::ManualStop) => { todo!() }
            // optional:
            //(S::Established, E::AutomaticStop) => { todo!() }

            (S::Established, E::HoldTimerExpires) => { todo!() }
            (S::Established, E::KeepaliveTimerExpires) => { todo!() }
            // optional:
            // (S::Established, E::TcpConnectionValid) => { todo!() }
            // (S::Established, E::TcpCrInvalid) => { info!("ignored etc") }

            (S::Established,
             E::TcpCrAcked | E::TcpConnectionConfirmed ) => { todo!() }

            (S::Established, E::BgpOpen) => { todo!() }
            // optional:
            //(S::Established, E::OpenCollisionDump) => { todo!() }
            (S::Established,
             E::NotifMsgVerErr | E::NotifMsg | E::TcpConnectionFails) => {
                todo!()
            }

            (S::Established, E::KeepAliveMsg) => { todo!() }
            (S::Established, E::UpdateMsg) => { todo!() }
            (S::Established, E::UpdateMsgErr) => { todo!() }


            (S::Established, 
                E::ConnectRetryTimerExpires |
                E::BgpHeaderErr |
                E::BgpOpenMsgErr
            ) => { todo!() }



        }
    }
}


