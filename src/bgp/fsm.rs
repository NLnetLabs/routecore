use log::{debug, info, warn};
use std::time::Instant;
use octseq::Octets;
use tokio::sync::mpsc;

use crate::bgp::message::Message as BgpMsg;
use crate::bgp::message::keepalive::KeepaliveBuilder;

// TMP
const HARDCODED_OPEN: &[u8] = &[
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0xb1, 0x01, 0x04, 0xfd, 0xe9, 0x00, 0xb4,
    0x0a, 0x00, 0x00, 0x01, 0x94, 0x02, 0x06, 0x01,
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
    0x04, 0x00, 0x19, 0x00, 0x46, 0x02, 0x06, 0x01,
    0x04, 0x40, 0x04, 0x00, 0x47, 0x02, 0x06, 0x01,
    0x04, 0x40, 0x04, 0x00, 0x48, 0x02, 0x06, 0x41,
    0x04, 0x00, 0x00, 0xfd, 0xe9, 0x02, 0x02, 0x06,
    0x00
    ];

// The SessionAttributes struct keeps track of all the
// parameters/counters/values as described in RFC4271. Fields that we
// introduce ourselves, e.g. the _tick fields to keep track of timers, carry
// the comment 'routecore'.
// Such fields, specific to the routecore implementation of the FSM, might
// eventually render other fields in the struct obsolete. For the _tick
// fields, that would be the corresponding _timer fields, most likely.
#[derive(Clone, Copy, Debug)]
struct SessionAttributes {
    // mandatory
    
    state: State, // nr 1, etc
                  //
    connect_retry_counter: usize,

    connect_retry_timer: u16, //current value
    connect_retry_time: u16,  // initial value
    connect_retry_last_tick: Option<Instant>, // routecore. If counter
                                              // started, then this fields
                                              // contains Some(last_tick).
                                              // If now() - last_tick >
                                              // retry_time, the timeout is
                                              // exceeded.
                              
    hold_timer: u16,         // current value
    hold_time: u16,          // initial value
                             //
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
    fn state(self) -> State {
        self.state
    }

    fn connect_retry_tick(&mut self, t: Instant) {
        self.connect_retry_last_tick = Some(t);
    }
    fn reset_connect_retry(&mut self) {
        self.connect_retry_counter = 0;
    }
    fn stop_connect_retry(&mut self) {
        self.connect_retry_last_tick = None;
    }
}

impl Default for SessionAttributes {
    fn default() -> Self {
        SessionAttributes {
            state: State::Idle,
            connect_retry_counter: 0,
            connect_retry_timer: 120,
            connect_retry_time: 120,
            connect_retry_last_tick: None,
            hold_timer: 90,
            hold_time: 90,
            keepalive_timer: 30,
            keepalive_time: 30,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

#[derive(Clone, Copy, Debug)]
enum Event {
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
//#[derive(Copy, Clone)]
pub struct BgpSession {
    session_attributes: SessionAttributes,
    channel: Option<mpsc::Sender<Vec<u8>>>,
    // XXX should have a ref to the tcpstream/socket in tokio in order to
    // disconnect it
}

impl BgpSession {
    pub fn new(ch: mpsc::Sender<Vec<u8>>) -> Self {
        let ch2 = ch.clone();
        Self {
            session_attributes: SessionAttributes::default(),
            channel: Some(ch),
        }
    }

    fn session(&self) -> &SessionAttributes {
        &self.session_attributes
    }

    fn session_mut(&mut self) -> &mut SessionAttributes {
        &mut self.session_attributes
    }

    pub fn state(&self) -> State {
        self.session_attributes.state
    }

    fn start_connect_retry_timer(&mut self) {
       self.session_mut().connect_retry_tick(Instant::now());
    }

    fn stop_connect_retry_timer(&mut self) {
       self.session_mut().stop_connect_retry();
    }

    // XXX perhaps this should also do the corresonding _tick()?
    // XXX or maybe put this all in tokio sleep/timeouts ?
    fn increase_connect_retry_counter(&mut self) {
        self.session_mut().connect_retry_counter += 1;
    }

    fn reset_connect_retry_counter(&mut self) {
        self.session_mut().connect_retry_counter = 0;
    }

    fn to_state(&mut self, state: State) {
        debug!("FSM {:?} -> {:?}", &self.session().state, state);
        self.session_mut().state = state;
    }

    //--- event functions ----------------------------------------------------
    pub fn manual_start(&mut self) {
        self.handle_event(Event::ManualStart);
    }

    pub fn connection_established(&mut self) {
        self.handle_event(Event::TcpConnectionConfirmed);
    }

    pub fn handle_msg<Octs: Octets>(&mut self, msg: BgpMsg<Octs>) {
       match msg {
           BgpMsg::Open(m) => {
               debug!("got OPEN, generating event");
               self.handle_event(Event::BgpOpen);
           }
           BgpMsg::Keepalive(m) => {
               debug!("got KEEPALIVE, generating event");
               self.handle_event(Event::KeepAliveMsg);
           }
           BgpMsg::Update(m) => {
               debug!("got UPDATE");
               self.handle_event(Event::UpdateMsg);
           }
           _ => todo!()
       }
    }

    //--- emitting over channel ----------------------------------------------
    //fn send_raw(&self, raw: T) {
    fn send_raw(&self, raw: Vec<u8>) {
        //debug!("should send out {:?}...", &raw.as_ref()[..10]);
        let tx = self.channel.clone().unwrap();
        tokio::spawn( async move {
            tx.send(raw.to_vec()).await;
        });
    }

    // state machine transitions
    fn handle_event(&mut self, event: Event) {
        use State as S;
        use Event as E;
        match (self.state(), event) {
            //--- Idle -------------------------------------------------------
            (S::Idle, E::ManualStart) => {

                //- initializes all BGP resources for the peer connection,
                // 
                
                //- sets ConnectRetryCounter to zero,
                self.session_mut().connect_retry_counter = 0;

                //- starts the ConnectRetryTimer with the initial value,
                self.start_connect_retry_timer();

                //- initiates a TCP connection to the other BGP peer,
                // TODO, but, perhaps focus on
                // ManualStartWithPassiveTcpEstablishment first?

                //- listens for a connection that may be initiated by the remote
                //  BGP peer, and
                // TODO tokio listen 
                
                //- changes its state to Connect.
                self.to_state(State::Connect); 
            }
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
            (S::Idle,
                E::ConnectRetryTimerExpires |
                E::HoldTimerExpires |
                E::KeepaliveTimerExpires |
                //E::TcpCrInvalid |
                E::TcpCrAcked |
                E::TcpConnectionConfirmed |
                E::TcpConnectionFails |
                E::BgpOpen |
                //E::BgpOpenWithDelayOpenTimerRunning |
                E::BgpHeaderErr |
                E::BgpOpenMsgErr |
                E::NotifMsgVerErr |
                E::NotifMsg |
                E::KeepAliveMsg |
                E::UpdateMsg |
                E::UpdateMsgErr
             ) => warn!("(unexpected) non-event {:?} in state Idle", event),

            //--- Connect ----------------------------------------------------
            (S::Connect, E::ManualStart /* | events 3-7 */ ) => {
                warn!("ignored {:?} in state Connect", event)
            }
            (S::Connect, E::ManualStop) => {
                // - drops the TCP connection,
                // TODO tokio
                
                // - releases all BGP resources,
                // TODO (is there something we need to do here?)

                // - sets ConnectRetryCounter to zero,
                self.session_mut().reset_connect_retry();

                // - stops the ConnectRetryTimer and sets ConnectRetryTimer to
                //   zero
                self.stop_connect_retry_timer();
                
                // - changes its state to Idle.
                self.to_state(State::Idle);
            }
            (S::Connect, E::ConnectRetryTimerExpires) => {
                todo!();
                //- drops the TCP connection,
                //- restarts the ConnectRetryTimer,
                //- stops the DelayOpenTimer and resets the timer to zero,
                //- initiates a TCP connection to the other BGP peer,
                //- continues to listen for a connection that may be initiated by
                //  the remote BGP peer, and
                //- stays in the Connect state.
            }
            // optional events:
            //(S::Connect, E::DelayOpenTimerExpires) => {}
            //(S::Connect, E::TcpConnectionValid) => {}
            //(S::Connect, E::TcpCrInvalid) => {}
            
            (S::Connect, E::TcpCrAcked | E::TcpConnectionConfirmed) => {
                let delayopen_implemented = false;
                //the local system checks the DelayOpen attribute prior to
                //processing.  If the DelayOpen attribute is set to TRUE, the
                //local system:
                if delayopen_implemented { 
                    todo!();
                    //  - stops the ConnectRetryTimer (if running) and sets
                    //  the ConnectRetryTimer to zero,
                    //  - sets the DelayOpenTimer to the initial value, and
                    //  - stays in the Connect state.
                    
                // If the DelayOpen attribute is set to FALSE, the local
                // system:
                } else {
                    //  - stops the ConnectRetryTimer (if running) and sets
                    //  the ConnectRetryTimer to zero,
                        self.stop_connect_retry_timer();

                    //  - completes BGP initialization
                    //  TODO (do we need to do something here?)

                    //  - sends an OPEN message to its peer,
                    //  TODO implement msgbuilder in routecore::bgp::message
                    self.send_raw(HARDCODED_OPEN.to_vec());
                
                    //  - set the HoldTimer to a large value (suggested: 4min)
                    //  TODO

                    //  - changes its state to OpenSent.
                    self.to_state(State::OpenSent);

                }

            }
            (S::Connect, E::TcpConnectionFails) => {
                let delayopen_implemented_and_running = false;
                if delayopen_implemented_and_running {
                    todo!();
                    //- restarts the ConnectRetryTimer with the initial value,
                    //- stops the DelayOpenTimer and resets its value to zero,
                    //- continues to listen for a connection that may be
                    //  initiated by the remote BGP peer, and
                    //- changes its state to Active.
                } else {
                    //- stops the ConnectRetryTimer to zero,
                    self.stop_connect_retry_timer();

                    //- drops the TCP connection,
                    // TODO tokio
                    
                    //- releases all BGP resources, and
                    // TODO something?
                    
                    //- changes its state to Idle.
                    self.to_state(State::Idle);
                }
            }
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
            ) => {
                //- if the ConnectRetryTimer is running, stops and resets the
                //  ConnectRetryTimer (sets to zero),
                self.stop_connect_retry_timer();

                //- if the DelayOpenTimer is running, stops and resets the
                //  DelayOpenTimer (sets to zero),
                //  TODO

                //- releases all BGP resources,
                //  TODO anything?

                //- drops the TCP connection,
                //  TODO tokio

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- performs peer oscillation damping if the DampPeerOscillations
                //  attribute is set to True, and
                //  TODO

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }


            //--- Active -----------------------------------------------------
            (S::Active, E::ManualStart /* | events 3-7 */ ) => {
                info!("ignored {:?} in state Active", event)
            }
            (S::Active, E::ManualStop) => {

                //- If the DelayOpenTimer is running and the
                //  SendNOTIFICATIONwithoutOPEN session attribute is set, the
                //  local system sends a NOTIFICATION with a Cease,
                //  TODO once the optional DelayOpenTimer is implemented

                //- releases all BGP resources including stopping the
                //  DelayOpenTimer
                //  TODO something?
                
                //- drops the TCP connection,
                // TODO tokio

                //- sets ConnectRetryCounter to zero,
                self.reset_connect_retry_counter();

                //- stops the ConnectRetryTimer and sets the ConnectRetryTimer
                //  to zero
                self.stop_connect_retry_timer();

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }
            (S::Active, E::ConnectRetryTimerExpires) => {

                //- restarts the ConnectRetryTimer (with initial value),
                self.start_connect_retry_timer();

                //- initiates a TCP connection to the other BGP peer,
                // TODO tokio

                //- continues to listen for a TCP connection that may be
                //  initiated by a remote BGP peer
                //  TODO tokio?

                //- changes its state to Connect.
                self.to_state(State::Connect);
            }
            // optional:
            //(S::Active, E::DelayOpenTimerExpires) => { todo!() }
            //(S::Active, E::TcpConnectionValid) => { todo!() }
            //(S::Active, E::TcpCrInvalid) => { todo!() }
            (S::Active, E::TcpCrAcked | E::TcpConnectionConfirmed) => {
                let delayopen_implemented = false;

                if delayopen_implemented {
                    //If the DelayOpen attribute is set to TRUE, the local
                    //system:
                    todo!()
                    //  - stops the ConnectRetryTimer and sets the
                    //  ConnectRetryTimer to zero,
                    //  - sets the DelayOpenTimer to the initial value
                    //    (DelayOpenTime), and
                    //  - stays in the Active state.
                } else {
                    //If the DelayOpen attribute is set to FALSE, the local
                    //system:
                    //  - sets the ConnectRetryTimer to zero,
                    self.start_connect_retry_timer();

                    //  - completes the BGP initialization,
                    //  TODO something?

                    //  - sends the OPEN message to its peer,
                    //  TODO tokio

                    //  - sets its HoldTimer to a large value (sugg: 4min), 
                    //  TODO

                    //  - changes its state to OpenSent.
                    self.to_state(State::OpenSent);
                }
            }
            (S::Active, E::TcpConnectionFails) => {
                //- restarts the ConnectRetryTimer (with the initial value),
                self.start_connect_retry_timer();

                //- stops and clears the DelayOpenTimer (sets the value to
                // zero),
                // TODO once DelayOpenTimer is implemented

                //- releases all BGP resource,
                // TODO something?

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- optionally performs peer oscillation damping if the
                //  DampPeerOscillations attribute is set to TRUE, and
                //  TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }
            // optional:
            //(S::Active, E::BgpOpenWithDelayOpenTimerRunning) => { todo!() }

            (S::Active, E::BgpHeaderErr | E::BgpOpenMsgErr) => { 
                //- (optionally) sends a NOTIFICATION message with the
                //appropriate error code if the SendNOTIFICATIONwithoutOPEN
                //attribute is set to TRUE,
                // TODO

                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection,
                // TODO tokio

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();
                
                //- (optionally) performs peer oscillation damping if the
                //  DampPeerOscillations attribute is set to TRUE, and
                //  TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }

            (S::Active, E::NotifMsgVerErr) => {
                let delayopen_implemented_and_running = false;
                if delayopen_implemented_and_running {
                    // If the DelayOpenTimer is running, the local system:
                    //- stops the ConnectRetryTimer (if running) and sets the
                    //  ConnectRetryTimer to zero,
                    self.stop_connect_retry_timer();

                    //- stops and resets the DelayOpenTimer (sets to zero),
                    // TODO once DelayOpenTimer is implemented
                    
                    //- releases all BGP resources,
                    // TODO something?
                    
                    //- drops the TCP connection, and
                    // TODO tokio
                    
                    //- changes its state to Idle.
                    self.to_state(State::Idle);
                } else {
                    //If the DelayOpenTimer is not running, the local system:
                    //  - sets the ConnectRetryTimer to zero,
                    self.start_connect_retry_timer();

                    //  - releases all BGP resources,
                    //  TODO something?

                    //  - drops the TCP connection,
                    //  TODO tokio

                    //  - increments the ConnectRetryCounter by 1,
                    self.increase_connect_retry_counter();

                    //  - (optionally) performs peer oscillation damping if
                    //  the DampPeerOscillations attribute is set to TRUE, and
                    // TODO once DampPeerOscillations is implemented

                    //  - changes its state to Idle.
                    self.to_state(State::Idle);
                }
            }

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
                ) => {
                    //- sets the ConnectRetryTimer to zero,
                    self.start_connect_retry_timer();

                    //- releases all BGP resources,
                    // TODO something?

                    //- drops the TCP connection,
                    // TODO tokio

                    //- increments the ConnectRetryCounter by one,
                    self.increase_connect_retry_counter();

                    //- (optionally) performs peer oscillation damping if the
                    //  DampPeerOscillations attribute is set to TRUE, and
                    //  TODO once DampPeerOscillations is implemented

                    //- changes its state to Idle.
                    self.to_state(State::Idle);
            }


            //--- OpenSent ---------------------------------------------------

            (S::OpenSent, E::ManualStart /* | events 3-7 */ ) => {
                info!("ignored {:?} in state OpenSent", event)
            }
            (S::OpenSent, E::ManualStop) => {
                //- sends the NOTIFICATION with a Cease,
                // TODO tokio

                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection,
                // TODO tokio

                //- sets the ConnectRetryCounter to zero, and
                self.reset_connect_retry_counter();

                //- changes its state to Idle.
                self.to_state(State::Idle);

            }
            // optional: 
            //S::OpenSent, E::AutomaticStop) => { todo!() }
            (S::OpenSent, E::HoldTimerExpires) => {
                //- sends a NOTIFICATION message with the error code Hold
                //Timer Expired,
                // TODO tokio

                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection,
                // TODO tokio

                //- increments the ConnectRetryCounter,
                self.increase_connect_retry_counter();

                //- (optionally) performs peer oscillation damping if the
                //  DampPeerOscillations attribute is set to TRUE, and
                // TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }
            (S::OpenSent,
             //E::TcpConnectionValid | // optional
             E::TcpCrAcked | E::TcpConnectionConfirmed ) => {
                todo!()
                  //If a TcpConnection_Valid (Event 14), Tcp_CR_Acked (Event
                  //16), or a TcpConnectionConfirmed event (Event 17) is
                  //received, a second TCP connection may be in progress.
                  //This second TCP connection is tracked per Connection
                  //Collision processing (Section 6.8) until an OPEN message
                  //is received.
            }

            // optional:
            //(S::OpenSent, E::TcpCrInvalid) => { 
            //    info!("ignored {:?} in state OpenSent", event)
            //}

            (S::OpenSent, E::TcpConnectionFails) => {
                //- closes the BGP connection,
                // TODO tokio

                //- restarts the ConnectRetryTimer,
                self.start_connect_retry_timer();

                //- continues to listen for a connection that may be initiated
                //  by the remote BGP peer, and
                //  TODO tokio

                //- changes its state to Active.
                self.to_state(State::Active);
            }
            (S::OpenSent, E::BgpOpen) => {
                //- resets the DelayOpenTimer to zero,
                // TODO once DelayOpenTimer is implemented

                //- sets the BGP ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- sends a KEEPALIVE message, and
                // TODO tokio
                self.send_raw(KeepaliveBuilder::new_vec().finish());

                //- sets a KeepaliveTimer:
                // If the negotiated hold time value is zero, then the
                // HoldTimer and KeepaliveTimer are not started.  If the value
                // of the Autonomous System field is the same as the local
                // Autonomous System number, then the connection is an
                // "internal" connection; otherwise, it is an "external"
                // connection.  (This will impact UPDATE processing as
                // described below.)
                // TODO

                //- sets the HoldTimer according to the negotiated value (see
                //  Section 4.2),
                //  TODO

                //- changes its state to OpenConfirm.
                self.to_state(State::OpenConfirm);
            }
            (S::OpenSent, E::BgpHeaderErr | E::BgpOpenMsgErr) => {
                //- sends a NOTIFICATION message with the appropriate error
                //code,
                // TODO tokio

                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection,
                // TODO tokio

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- (optionally) performs peer oscillation damping if the
                //  DampPeerOscillations attribute is TRUE, and
                //  TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }
            // optional:
            //(S::OpenSent, E::OpenCollisionDump) => { todo!() }
            (S::OpenSent, E::NotifMsgVerErr) => {
                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection, and
                // TODO tokio

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }
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
            ) => {
                //- sends the NOTIFICATION with the Error Code Finite State
                //Machine Error,
                // TODO tokio

                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- releases all BGP resources,
                //TODO something?

                //- drops the TCP connection,
                // TODO tokio?

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- (optionally) performs peer oscillation damping if the
                //DampPeerOscillations attribute is set to TRUE, and
                // TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }

            
            //--- OpenConfirm ------------------------------------------------


            (S::OpenConfirm, E::ManualStart /* | events 3-7 */ ) => {
                info!("ignored {:?} in state OpenConfirm", event)
            }
            (S::OpenConfirm, E::ManualStop) => {
                //- sends the NOTIFICATION message with a Cease,
                // TODO tokio

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection,
                // TODO tokio

                //- sets the ConnectRetryCounter to zero,
                self.reset_connect_retry_counter();

                //- sets the ConnectRetryTimer to zero, and
                self.start_connect_retry_timer();

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }
            // optional: 
            //(S::OpenConfirm, E::AutomaticStop) => { todo!() }
           
            (S::OpenConfirm, E::HoldTimerExpires) => {
                //- sends the NOTIFICATION message with the Error Code Hold
                //Timer Expired,
                // TODO tokio

                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection,
                // TODO tokio

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- (optionally) performs peer oscillation damping if the
                // DampPeerOscillations attribute is set to TRUE, and
                // TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }
            (S::OpenConfirm, E::KeepaliveTimerExpires) => {
                //- sends a KEEPALIVE message,
                // TODO tokio

                //- restarts the KeepaliveTimer, and
                // TODO

                //- remains in the OpenConfirmed state.
                // noop
            }

            (S::OpenConfirm,
             //E::TcpConnectionValid | // optional
             E::TcpCrAcked | E::TcpConnectionConfirmed ) => {
                todo!()
                // TODO: track second connection
            }

            // optional:
            //(S::OpenConfirm, E::TcpCrInvalid) => { 
            //    info!("ignored {:?} in state OpenConfirm", event)
            //}

            (S::OpenConfirm, E::TcpConnectionFails | E::NotifMsg ) => {
                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection,
                // TODO tokio

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- (optionally) performs peer oscillation damping if the
                // DampPeerOscillations attribute is set to TRUE, and
                // TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }
            (S::OpenConfirm, E::NotifMsgVerErr) => {
                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- releases all BGP resources,
                //TODO something?

                //- drops the TCP connection, and
                //TODO tokio

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }
            (S::OpenConfirm, E::BgpOpen) => {
                // If the local system receives a valid OPEN message (BGPOpen
                // (Event 19)), the collision detect function is processed per
                //    Section 6.8.  If this connection is to be dropped due to
                //    connection collision, the local system:

                //- sends a NOTIFICATION with a Cease,
                // TODO tokio

                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection (send TCP FIN),
                // TODO tokio

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- (optionally) performs peer oscillation damping if the
                //  DampPeerOscillations attribute is set to TRUE, and
                //  TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }
            (S::OpenConfirm, E::BgpHeaderErr | E::BgpOpenMsgErr) => {
                //- sends a NOTIFICATION message with the appropriate error
                //code,
                // TODO tokio

                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection,
                // TODO tokio

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- (optionally) performs peer oscillation damping if the
                //  DampPeerOscillations attribute is set to TRUE, and
                //  TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }
            // optional:
            //(S::OpenConfirm, E::OpenCollisionDump) => { todo!() }
            (S::OpenConfirm, E::KeepAliveMsg) => {
                //- restarts the HoldTimer and
                // TODO

                //- changes its state to Established.
                self.to_state(State::Established);
            }
            (S::OpenConfirm, 
                E::ConnectRetryTimerExpires |
                //E::DelayOpenTimerExpires |
                //E::IdleHoldTimerExpires |
                //E::BgpOpenWithDelayOpenTimerRunning |
                E::UpdateMsg |
                E::UpdateMsgErr
            ) => {
                //- sends a NOTIFICATION with a code of Finite State Machine
                //  Error,
                //  TODO tokio

                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- releases all BGP resources,
                //TODO something?

                //- drops the TCP connection,
                //TODO tokio

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- (optionally) performs peer oscillation damping if the
                //  DampPeerOscillations attribute is set to TRUE, and
                //  TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }

            //--- Established ------------------------------------------------

            (S::Established, E::ManualStart /* | events 3-7 */ ) => {
                info!("ignored {:?} in state Established", event)
            }
            (S::Established, E::ManualStop) => {
                //- sends the NOTIFICATION message with a Cease,
                //TODO tokio

                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- deletes all routes associated with this connection,
                //TODO manage store

                //- releases BGP resources,
                //TODO something?

                //- drops the TCP connection,
                //TODO tokio

                //- sets the ConnectRetryCounter to zero, and
                self.reset_connect_retry_counter();

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }
            // optional:
            //(S::Established, E::AutomaticStop) => { todo!() }

            (S::Established, E::HoldTimerExpires) => {

                //- sends a NOTIFICATION message with the Error Code Hold Timer
                //  Expired,
                //  TODO tokio

                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- releases all BGP resources,
                // TODO store

                //- drops the TCP connection,
                //TODO tokio

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- (optionally) performs peer oscillation damping if the
                //  DampPeerOscillations attribute is set to TRUE, and
                //  TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }
            (S::Established, E::KeepaliveTimerExpires) => {
                //- sends a KEEPALIVE message, and
                // TODO tokio

                //- restarts its KeepaliveTimer, unless the negotiated HoldTime
                //  value is zero.
                //  TODO
            }
            // optional:
            // (S::Established, E::TcpConnectionValid) => { todo!() }
            // (S::Established, E::TcpCrInvalid) => { info!("ignored etc") }

            (S::Established,
             E::TcpCrAcked | E::TcpConnectionConfirmed ) => {
                todo!()
                // In response to an indication that the TCP connection is
                // successfully established (Event 16 or Event 17), the second
                // connection SHALL be tracked until it sends an OPEN message.
            }
            (S::Established, E::BgpOpen) => {
                todo!()
                // once CollisionDetectEstablishedState is implemented, things
                // need to happen here
            }
            // optional:
            //(S::Established, E::OpenCollisionDump) => { todo!() }
            (S::Established,
             E::NotifMsgVerErr | E::NotifMsg | E::TcpConnectionFails) => {

                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- deletes all routes associated with this connection,
                // TODO store

                //- releases all the BGP resources,
                // TODO something?

                //- drops the TCP connection,
                // TODO tokio

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }

            (S::Established, E::KeepAliveMsg) => {
                //- restarts its HoldTimer, if the negotiated HoldTime value is
                //  non//-zero, and
                // TODO

                //- remains in the Established state.
                //self.to_state(State::Established);
            }
            (S::Established, E::UpdateMsg) => {
                //- processes the message,
                // TODO

                //- restarts its HoldTimer, if the negotiated HoldTime value is
                //  non//-zero, and
                //  TODO

                //- remains in the Established state.
                // noop
            }
            (S::Established, E::UpdateMsgErr) => {
                //- sends a NOTIFICATION message with an Update error,
                //TODO tokio

                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- deletes all routes associated with this connection,
                // TODO store

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection,
                // TODO tokio

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- (optionally) performs peer oscillation damping if the
                // DampPeerOscillations attribute is set to TRUE, and
                // TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }


            (S::Established, 
                E::ConnectRetryTimerExpires |
                E::BgpHeaderErr |
                E::BgpOpenMsgErr
            ) => {
                //- sends a NOTIFICATION message with the Error Code Finite State
                //  Machine Error,
                // TODO tokio

                //- deletes all routes associated with this connection,
                // TODO store

                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection,
                // TODO tokio

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- (optionally) performs peer oscillation damping if the
                //  DampPeerOscillations attribute is set to TRUE, and
                //  TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }
        }
    }
}

//--- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;

    //--- Idle ---------------------------------------------------------------
    #[test]
    fn idle_to_connect() {
        let mut s = BgpSession::new();
        assert_eq!(s.state(), State::Idle);
        let t1 = s.session().connect_retry_last_tick;
        assert!(t1.is_none());

        s.handle_event(Event::ManualStart);
        assert_eq!(s.state(), State::Connect);
        
        let t2 = s.session().connect_retry_last_tick;
        assert!(t2.is_some());
    }

    #[test]
    fn idle_manualstop() {
        let mut s = BgpSession::new();
        assert_eq!(s.state(), State::Idle);
        s.handle_event(Event::ManualStop);
        assert_eq!(s.state(), State::Idle);
    }

    //--- Connect ------------------------------------------------------------
    #[test]
    fn connect_manualstop() {
        let mut s = BgpSession::new();
        s.handle_event(Event::ManualStart);
        s.handle_event(Event::ManualStop);
        assert_eq!(s.state(), State::Idle);


    }

}
