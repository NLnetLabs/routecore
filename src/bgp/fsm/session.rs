use std::io::Cursor;
use std::net::{IpAddr, SocketAddr};

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::AsyncReadExt;
use tokio::net::tcp::OwnedReadHalf;
use tokio::sync::{mpsc, oneshot};

use crate::bgp::message::keepalive::KeepaliveBuilder;
use crate::bgp::message::notification::{
    CeaseSubcode, Details, FiniteStateMachineSubcode, NotificationBuilder,
    OpenMessageSubcode,
};
use crate::bgp::message::open::{Capability, OpenBuilder};
use crate::bgp::message::{
    Message as BgpMsg, NotificationMessage, SessionConfig, UpdateMessage,
};
use crate::bgp::types::{AddpathDirection, AddpathFamDir, AfiSafiType};
use crate::bgp::ParseError;
use inetnum::asn::Asn;
use log::{debug, error, info, warn};

use super::state_machine::{Event, SessionAttributes, State};
use super::timers::Timer;

#[allow(unused_imports)]
use super::util::to_pcap;

//------------ Session -------------------------------------------------------
/// BGP Session holding the FSM and (local/negotiated) configuration.
///
/// To establish a Session, we need local configuration (something that
/// implements the `BgpConfig` trait), and a `TcpStream` that is part of the
/// `Connection` struct owned by the Session. Details and parameters described
/// in RFC4271 are kept in the `attributes` struct, expect for the actual
/// timers. We use tokio based timers (see [`bgp::timers`]), which are part of
/// Session instead of the `SessionAttributes`.
#[derive(Debug)]
pub struct Session<C> {
    /// Local configuration
    config: C,

    /// Negotiated configuration
    negotiated: Option<NegotiatedConfig>,

    /// Parameters and FSM
    attributes: SessionAttributes, // contains the actual FSM

    /// The TCP connection, once established
    connection: Option<Connection>,

    /// Channel to send e.g. UPDATEs to the user of this Session
    channel: mpsc::Sender<Message>,

    /// Channel to ingest commands from the user of this Session
    commands: mpsc::Receiver<Command>,

    /// Channel to send out BGP PDUs to the peer
    pdu_out_tx: mpsc::Sender<BgpMsg<Bytes>>,

    //--- Timers
    /// Connect Retry Timer
    connect_retry_timer: Timer,

    /// Hold Timer
    hold_timer: Timer,

    /// Keepalive Timer
    keepalive_timer: Timer,

    /// Delay Open Timer
    delay_open_timer: Timer,
}

impl<C: BgpConfig + Send> Session<C> {
    /*
    pub fn _new_idle(
        config: C,
        channel: mpsc::Sender<Message>,
    ) -> (Self, mpsc::Sender<Command>, mpsc::Sender<BgpMsg<Bytes>>) {
        let attributes = SessionAttributes::from_bgp_config(&config);
        let (tx_commands, rx_commands) = mpsc::channel(16);
        let (tx_pdu_out, rx_pdu_out) = mpsc::channel(16);
        let res = Self {
            config,
            negotiated: None,
            attributes,
            connection: None,
            channel,
            commands: rx_commands,
            pdu_out_rx: rx_pdu_out,
            connect_retry_timer: Timer::new(attributes.connect_retry_time().into()),
            hold_timer: Timer::new(attributes.hold_time().into()),
            keepalive_timer: Timer::new(u64::from(attributes.hold_time() / 3)),
            delay_open_timer: Timer::new(attributes.delay_open_time().into()),
        };
        (res, tx_commands, tx_pdu_out)
    }
    */

    /// Creates a new Session.
    pub fn new(
        config: C,
        //stream: TcpStream,
        tcp_in: OwnedReadHalf,
        channel: mpsc::Sender<Message>,
        commands: mpsc::Receiver<Command>,
        pdu_out_tx: mpsc::Sender<BgpMsg<Bytes>>,
    ) -> Self {
        let mut attributes = SessionAttributes::default();
        if let Some(hold_time) = config.hold_time() {
            attributes.set_hold_time(hold_time);
        }

        Self {
            config,
            negotiated: None,
            attributes,
            connection: Some(Connection::for_read_half(tcp_in)),
            channel,
            commands,
            pdu_out_tx,
            connect_retry_timer: Timer::new(
                attributes.connect_retry_time().into(),
            ),
            hold_timer: Timer::new(attributes.hold_time().into()),
            keepalive_timer: Timer::new(u64::from(
                attributes.hold_time() / 3,
            )),
            delay_open_timer: Timer::new(u64::from(
                attributes.delay_open_time(),
            )),
        }
    }

    /// Attach a TCP stream to this Session.
    pub async fn attach_stream(&mut self, stream: OwnedReadHalf) {
        let _socket_status = stream.readable().await;
        self.connection = Some(Connection::for_read_half(stream));
        self.connection_established().await;
    }

    /// Returns the remote address, if there is a connection.
    pub fn connected_addr(&self) -> Option<SocketAddr> {
        self.connection.as_ref().map(|c| c.remote_addr)
    }

    /// Returns a reference to the configuration.
    pub const fn config(&self) -> &C {
        &self.config
    }

    /// Sets the negotiated config.
    pub fn set_negotiated_config(&mut self, config: NegotiatedConfig) {
        self.negotiated = Some(config);
        if let Some(sc) = self.connection.as_mut() {
            for famdir in &self.negotiated.as_ref().unwrap().addpath {
                sc.session_config_mut().add_famdir(*famdir);
            }
        } else {
            warn!("set_negotiated_config: no Connection for Session");
        }
    }
    /// Returns the negotiated config.
    pub const fn negotiated(&self) -> Option<&NegotiatedConfig> {
        self.negotiated.as_ref()
    }

    // XXX doesnt need to be async anymore?
    fn drop_connection(&mut self) {
        //if let Some(ref mut conn) = self.connection {
        //    conn.disconnect().await;
        //} else {
        //    warn!("trying to disconnect non-existing connection");
        //}
        if self.connection.take().is_none() {
            warn!("trying to disconnect non-existing connection");
        }
    }

    fn disconnect(&mut self, reason: DisconnectReason) {
        match reason {
            DisconnectReason::ConnectionRejected => {
                self.send_notification(CeaseSubcode::ConnectionRejected);
            }
            DisconnectReason::Reconfiguration => {
                self.send_notification(
                    CeaseSubcode::OtherConfigurationChange,
                );
            }
            DisconnectReason::Deconfigured => {
                self.send_notification(CeaseSubcode::PeerDeconfigured);
            }
            DisconnectReason::HoldTimerExpired => {
                self.send_notification(Details::HoldTimerExpired);
            }
            DisconnectReason::Shutdown => {
                self.send_notification(CeaseSubcode::AdministrativeShutdown);
            }
            DisconnectReason::FsmViolation(maybe_notification) => {
                if let Some(details) = maybe_notification {
                    self.send_notification(details);
                }
            }
            DisconnectReason::Other => {
                //todo!();
                debug!("DisconnectReason::Other, not sending NOTIFICATION");
            }
        }
        debug!(
            "disconnecting peer {:?}: {:?}",
            self.connection.as_ref().map(|c| c.remote_addr),
            reason,
        );

        self.keepalive_timer.stop_and_reset();
        self.hold_timer.stop_and_reset();
        self.drop_connection();
    }

    /*
    /// Attempts to create a Session, depending on the connection.
    pub async fn try_for_connection(
        config: C,
        connection: TcpStream,
        channel: mpsc::Sender<Message>,
        pdu_out_rx: mpsc::Receiver<BgpMsg<Bytes>>,
    ) -> Result<(Self, mpsc::Sender<Command>), ConnectionError> {
        if !config.remote_addr_allowed(connection.peer_addr()?.ip()) {
            return Err(UnexpectedPeer(connection.peer_addr()?.ip()))?
        }
        let (tx_commands, rx_commands) = mpsc::channel(16);
        let mut session = Self::new(
            config,
            connection,
            channel,
            rx_commands,
            pdu_out_tx
        );

        // fast-forward our FSM
        session.manual_start().await;
        session.connection_established().await;

        Ok((session, tx_commands))
    }
    */

    /// Process the next event.
    ///
    /// Note that this takes a mutable reference so the caller keeps ownership
    /// of the Session.
    pub async fn tick(&mut self) -> Result<(), Error> {
        tokio::select! {
            // command from application:
            Some(cmd) = self.commands.recv() => {
                match cmd {
                    Command::AttachStream{stream} => {
                        debug!("Command::AttachStream");
                        self.attach_stream(stream).await;
                    }
                    Command::GetAttributes{resp} => {
                        let _ = resp.send(self.attributes);
                    }
                    Command::Disconnect(reason) => {
                        self.disconnect(reason);
                    }
                    Command::ForcedKeepalive => {
                        self.send_keepalive();
                    }
                    //Command::RawUpdate(pdu) => {
                    //    debug!("got Command::RawUpdate");
                    //    self.send_raw(pdu.as_ref().to_vec())
                    //}
                }
            }
            // message from peer:
            Some(msg) = maybe_read_frame(self.connection.as_mut()) => {
                match msg {
                    Ok(Some(m)) => {
                        //debug!("maybe_read_frame returned Some(..) len {}",
                        //    m.as_ref().len()
                        //);
                        if let Err(msg) = self.handle_msg(m).await {
                            debug!("handle_msg returned err: {msg}, break");
                            self.set_state(State::Connect);
                            return Err(Error { msg: "handle_msg failed" });
                        }
                    }
                    Ok(None) => {
                        if let Some(ref connection) = self.connection {
                            warn!(
                                "[{}] Connection lost",
                                connection.remote_addr
                                );
                            let _ = self.channel.send(
                                Message::ConnectionLost(
                                    Some(connection.remote_addr)
                                )
                            ).await;
                        } else {
                            // Should never happen.
                            error!("Connection lost but no stream attached");
                        }
                        self.connection = None;
                        self.set_state(State::Connect);
                    }
                    Err(e) => {
                        error!("{e}");
                        self.connection = None;
                        self.set_state(State::Connect);
                        return Err(Error { msg: "error from read_frame" });
                    }
                }
            }
            // Timers expiring:
            _ = self.keepalive_timer.tick() => {
                self.handle_event(Event::KeepaliveTimerExpires).await?;
            }
            _ = self.hold_timer.tick() => {
                self.handle_event(Event::HoldTimerExpires).await?;
            }
            _ = self.delay_open_timer.tick() => {
                self.handle_event(Event::DelayOpenTimerExpires).await?;
            }
        }
        Ok(())
    }

    /// Process all future events.
    ///
    /// This takes ownership of the Session. So, while the caller only needs
    /// to call this once, e.g. like
    ///
    /// ```ignore
    ///     tokio::spawn(async {
    ///         session.process().await;
    ///     });
    /// ```
    /// other possibilities to interact with the Session is lost.
    /// If fine grained control is required, use [`Session::tick`].
    pub async fn process(mut self) -> Result<(), Error> {
        loop {
            self.tick().await?;
        }
    }

    /*
    fn send_raw(&self, raw: Vec<u8>) {
        if let Some(conn) = &self.connection {
            if conn.stream.try_write(&raw).is_err() {
                warn!(
                    "[{:?}@{}] failed to send_raw, connection borked?",
                    self.negotiated().as_ref().map(|n| n.remote_asn()),
                    conn.remote_addr,
                );
                debug!("failed send_raw buf was: {:?}", &raw);
            }
        } else {
            warn!("trying to send_raw without an actual connection");
        }
    }
    */
    fn send_pdu(&self, pdu: BgpMsg<Bytes>) {
        if self.pdu_out_tx.try_send(pdu).is_err() {
            warn!("outgoing pdu queue blocked");
        }
    }

    pub fn send_open(&self) {
        let mut openbuilder =
            OpenBuilder::from_target(BytesMut::new()).unwrap();
        openbuilder.set_asn(self.config.local_asn());
        openbuilder.set_holdtime(self.attributes.hold_time());
        openbuilder.set_bgp_id(self.config.bgp_id());

        openbuilder.four_octet_capable(self.config.local_asn());

        for afisafi in &self.config.protocols() {
            openbuilder.add_mp(*afisafi);
        }

        for fam in self.config.addpath() {
            openbuilder.add_addpath(fam, AddpathDirection::SendReceive);
        }

        // and for our bgpsink, we should copy all the capabilities
        // from the received OPEN

        //self.send_raw(openbuilder.finish());
        self.send_pdu(BgpMsg::Open(openbuilder.into_message()));
    }

    fn send_notification<S>(&self, subcode: S)
    where
        S: Into<Details>,
    {
        let msg = NotificationBuilder::new_vec_nodata(subcode);
        //self.send_raw(msg);
        self.send_pdu(BgpMsg::Notification(
            NotificationMessage::from_octets(Bytes::from(msg)).unwrap(),
        ));
    }

    fn send_keepalive(&self) {
        self.send_pdu(BgpMsg::Keepalive(
            KeepaliveBuilder::from_target(BytesMut::new())
                .unwrap()
                .into_message(),
        ));
    }

    /// Returns the local ASN for this session.
    pub fn local_asn(&self) -> Asn {
        self.config.local_asn()
    }

    /// Returns a reference to the session attributes.
    pub const fn attributes(&self) -> &SessionAttributes {
        &self.attributes
    }

    /// Returns the hold time.
    pub const fn hold_time(&self) -> u16 {
        self.attributes().hold_time()
    }

    /// Sets the hold time.
    pub fn set_hold_time(&mut self, time: u16) {
        self.attributes_mut().set_hold_time(time);
    }

    /// Enable the Delay Open Timer for this session.
    pub fn enable_delay_open(&mut self) {
        self.attributes_mut().enable_delay_open();
    }

    fn attributes_mut(&mut self) -> &mut SessionAttributes {
        &mut self.attributes
    }

    /// Returns the current FSM state.
    pub const fn state(&self) -> State {
        self.attributes.state()
    }

    fn increase_connect_retry_counter(&mut self) {
        self.attributes_mut().increase_connect_retry_counter();
    }

    fn reset_connect_retry_counter(&mut self) {
        self.attributes_mut().reset_connect_retry_counter();
    }

    fn set_state(&mut self, state: State) {
        self.attributes_mut().set_state(state);
    }

    //--- event functions ----------------------------------------------------
    /// Trigger a ManualStart event.
    pub async fn manual_start(&mut self) {
        if self.attributes.passive_tcp_establishment() {
            let _ = self
                .handle_event(Event::ManualStartWithPassiveTcpEstablishment)
                .await;
        } else {
            let _ = self.handle_event(Event::ManualStart).await;
        }
    }

    /// Trigger a ConnectionEstablished event.
    pub async fn connection_established(&mut self) {
        let _ = self.handle_event(Event::TcpConnectionConfirmed).await;
    }

    async fn handle_msg(&mut self, msg: BgpMsg<Bytes>) -> Result<(), Error> {
        match msg {
            BgpMsg::Open(m) => {
                debug!("got OPEN from {}, generating event", m.my_asn());
                if self.delay_open_timer.is_running() {
                    self.handle_event(
                        Event::BgpOpenWithDelayOpenTimerRunning(m),
                    )
                    .await?;
                } else {
                    self.handle_event(Event::BgpOpen(m)).await?;
                }
            }
            BgpMsg::Keepalive(_m) => {
                self.handle_event(Event::KeepaliveMsg).await?;
            }
            BgpMsg::Update(m) => {
                self.handle_event(Event::UpdateMsg).await?;
                let tx = self.channel.clone();
                let _ = tx.send(Message::UpdateMessage(m)).await;
            }
            BgpMsg::Notification(m) => {
                let tx = self.channel.clone();
                let _ = tx.send(Message::NotificationMessage(m)).await;
            }
            BgpMsg::RouteRefresh(_m) => {
                debug!("got ROUTEREFRESH, not doing anything");
            }
        }
        Ok(())
    }

    // state machine transitions
    #[allow(unreachable_code)]
    #[allow(clippy::too_many_lines)]
    async fn handle_event(&mut self, event: Event) -> Result<(), Error> {
        use Event as E;
        use State as S;
        match (self.state(), &event) {
            //--- Idle -------------------------------------------------------
            (S::Idle, E::ManualStart | E::AutomaticStart) => {

                //- initializes all BGP resources for the peer connection,
                // 
                
                //- sets ConnectRetryCounter to zero,
                self.reset_connect_retry_counter();

                //- starts the ConnectRetryTimer with the initial value,
                self.connect_retry_timer.start();

                //- initiates a TCP connection to the other BGP peer,
                // TODO, we focus on ManualStartWithPassiveTcpEstablishment
                // first.
                todo!();

                //- listens for a connection that may be initiated by the remote
                //  BGP peer, and
                // (handled by tokio elsewhere)
                
                //- changes its state to Connect.
                self.set_state(State::Connect); 
            }
            (S::Idle,
                E::ManualStartWithPassiveTcpEstablishment |
                E::AutomaticStartWithPassiveTcpEstablishment
            ) => {
                //- initializes all BGP resources for the peer connection,
                
                //- sets ConnectRetryCounter to zero,
                self.reset_connect_retry_counter();

                //- starts the ConnectRetryTimer with the initial value,
                self.connect_retry_timer.start();

                //- listens for a connection that may be initiated by the
                // remote peer, and
                // (handled by tokio elsewhere)

                //- changes its state to Active.
                self.set_state(State::Active); 
            }
            (S::Idle, E::ManualStop) => {
                info!("ignored ManualStop in Idle state");
            }
            // optional events:
            //(S::Idle, E::AutomaticStop) => { /* ignore */ }
            
            // if DampPeerOscillations is TRUE:
            //(S::Idle, E::AutomaticStartWithDampPeerOscillations) => { }
            //(S::Idle, E::AutomaticStartWithDampPeerOscillationsAndPassiveTcpEstablishment) => { }
            //(S::Idle, E::IdleHoldTimerExpires) => { }
            (S::Idle,
                E::ConnectRetryTimerExpires |
                E::HoldTimerExpires |
                E::KeepaliveTimerExpires |
                E::DelayOpenTimerExpires |
                //E::TcpCrInvalid |
                E::TcpCrAcked |
                E::TcpConnectionConfirmed |
                E::TcpConnectionFails |
                E::BgpOpen(_) |
                E::BgpOpenWithDelayOpenTimerRunning(_) |
                E::BgpHeaderErr |
                E::BgpOpenMsgErr |
                E::NotifMsgVerErr |
                E::NotifMsg |
                E::KeepaliveMsg |
                E::UpdateMsg |
                E::UpdateMsgErr
             ) => warn!("(unexpected) non-event {:?} in state Idle", event),

            //--- Connect ----------------------------------------------------
            (S::Connect,
                 E::ManualStart |
                 E::AutomaticStart |
                 E::ManualStartWithPassiveTcpEstablishment |
                 E::AutomaticStartWithPassiveTcpEstablishment
                 /* | events 6, 7: Auto start with damp peer oscillations */
            ) => {
                warn!("ignored {:?} in state Connect", event);
            }
            (S::Connect, E::ManualStop) => {
                // - drops the TCP connection,
                // TODO tokio
                
                // - releases all BGP resources,
                // TODO (is there something we need to do here?)

                // - sets ConnectRetryCounter to zero,
                self.reset_connect_retry_counter();

                // - stops the ConnectRetryTimer and sets ConnectRetryTimer to
                //   zero
                self.connect_retry_timer.stop_and_reset();
                
                // - changes its state to Idle.
                self.set_state(State::Idle);
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
            (S::Connect, E::DelayOpenTimerExpires) => {
                    //- sends an OPEN message to its peer,
                    self.send_open();

                    //- sets the HoldTimer to a large value, and
                    // TODO

                    //- changes its state to OpenSent.
                    self.set_state(State::OpenSent);
            }
            //(S::Connect, E::TcpConnectionValid) => {}
            //(S::Connect, E::TcpCrInvalid) => {}
            
            (S::Connect, E::TcpCrAcked | E::TcpConnectionConfirmed) => {
                //the local system checks the DelayOpen attribute prior to
                //processing.  If the DelayOpen attribute is set to TRUE, the
                //local system:
                if self.attributes().delay_open() {
                    //  - stops the ConnectRetryTimer (if running) and sets
                    //  the ConnectRetryTimer to zero,
                    self.connect_retry_timer.stop_and_reset();

                    //  - sets the DelayOpenTimer to the initial value, and
                    self.delay_open_timer.start();

                    //  - stays in the Connect state.
                    //  (noop)
                    
                // If the DelayOpen attribute is set to FALSE, the local
                // system:
                } else {
                    //  - stops the ConnectRetryTimer (if running) and sets
                    //  the ConnectRetryTimer to zero,
                    self.connect_retry_timer.stop_and_reset();

                    //  - completes BGP initialization
                    //  TODO (do we need to do something here?)

                    //  - sends an OPEN message to its peer,
                    self.send_open();


                    //  - set the HoldTimer to a large value (suggested: 4min)
                    //  TODO


                    //  - changes its state to OpenSent.
                    self.set_state(State::OpenSent);

                }

            }
            (S::Connect, E::TcpConnectionFails) => {
                if self.delay_open_timer.is_running() {
                    todo!();
                    //- restarts the ConnectRetryTimer with the initial value,
                    //- stops the DelayOpenTimer and resets its value to zero,
                    //- continues to listen for a connection that may be
                    //  initiated by the remote BGP peer, and
                    //- changes its state to Active.
                } else {
                    //- stops the ConnectRetryTimer to zero,
                    self.connect_retry_timer.stop_and_reset();

                    //- drops the TCP connection,
                    // TODO tokio
                    
                    //- releases all BGP resources, and
                    // TODO something?
                    
                    //- changes its state to Idle.
                    self.set_state(State::Idle);
                }
            }
            // optional:
            (S::Connect, E::BgpOpenWithDelayOpenTimerRunning(_open_msg)) => {
                // The TCP connection has been established but we waited for
                // the other side to send a BGP OPEN first, which now
                // happened. 

                debug!("Received OPEN during DelayOpen");
                todo!();

        //- stops the ConnectRetryTimer (if running) and sets the
        //  ConnectRetryTimer to zero,

        //- completes the BGP initialization,
        //- stops and clears the DelayOpenTimer (sets the value to zero),

        //- sends an OPEN message,

        //- sends a KEEPALIVE message,

        //- if the HoldTimer initial value is non-zero,

        //    - starts the KeepaliveTimer with the initial value and

        //    - resets the HoldTimer to the negotiated value,

        //  else, if the HoldTimer initial value is zero,

        //    - resets the KeepaliveTimer and

        //    - resets the HoldTimer value to zero,

        //- and changes its state to OpenConfirm.
            }
            (S::Connect, E::BgpHeaderErr | E::BgpOpenMsgErr) => { todo!() }
            (S::Connect, E::NotifMsgVerErr) => { todo!() }
            (S::Connect, 
                //E::AutomaticStop |
                E::HoldTimerExpires |
                E::KeepaliveTimerExpires |
                //E::IdleHoldTimerExpires |
                E::BgpOpen(_) |
                //E::OpenCollisionDump |
                E::NotifMsg |
                E::KeepaliveMsg |
                E::UpdateMsg |
                E::UpdateMsgErr
            ) => {
                //- if the ConnectRetryTimer is running, stops and resets the
                //  ConnectRetryTimer (sets to zero),
                self.connect_retry_timer.stop_and_reset();

                //- if the DelayOpenTimer is running, stops and resets the
                //  DelayOpenTimer (sets to zero),
                self.delay_open_timer.stop_and_reset();

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
                self.set_state(State::Idle);
            }


            //--- Active -----------------------------------------------------
            (S::Active,
                 E::ManualStart |
                 E::AutomaticStart |
                 E::ManualStartWithPassiveTcpEstablishment |
                 E::AutomaticStartWithPassiveTcpEstablishment
                 /* | events 6, 7 */
            ) => {
                info!("ignored {:?} in state Active", event);
            }
            (S::Active, E::ManualStop) => {
                //- If the DelayOpenTimer is running and the
                //  SendNOTIFICATIONwithoutOPEN session attribute is set, the
                //  local system sends a NOTIFICATION with a Cease,
                if self.delay_open_timer.is_running() &&
                   self.attributes().notification_without_open()
                {
                    self.disconnect(DisconnectReason::Shutdown);
                }

                //- releases all BGP resources including stopping the
                //  DelayOpenTimer
                //  TODO something regarding the BGP resources?
                self.delay_open_timer.stop_and_reset();
                
                //- drops the TCP connection,
                // (handled by self.disconnect above)

                //- sets ConnectRetryCounter to zero,
                self.reset_connect_retry_counter();

                //- stops the ConnectRetryTimer and sets the ConnectRetryTimer
                //  to zero
                self.connect_retry_timer.stop_and_reset();

                //- changes its state to Idle.
                self.set_state(State::Idle);
            }
            (S::Active, E::ConnectRetryTimerExpires) => {

                //- restarts the ConnectRetryTimer (with initial value),
                // (our timers restart automatically upon expiry)

                // XXX: we can only actively connect if our candidate config
                // has an exact IP address, not a prefix.
                // In case of a prefix, we fallback to the `else` case below,
                // which is not part of 4271.
                if self.config.is_exact() {
                    //- initiates a TCP connection to the other BGP peer,
                    todo!();

                    //- continues to listen for a TCP connection that may be
                    //  initiated by a remote BGP peer
                    //  (handled by tokio elsewhere)
                    
                    //- changes its state to Connect.
                    self.set_state(State::Connect);
                } else {
                    // XXX this is not described in 4271.

                    warn!(
                        "ConnectRetry expired for flexible config, \
                        staying in State::Active"
                    );

                    // We stay in State::Active
                    // (noop) 
                }
            }
            // optional:
            (S::Active, E::DelayOpenTimerExpires) => {
                //- sets the ConnectRetryTimer to zero,
                self.connect_retry_timer.stop_and_reset();

                //- stops and clears the DelayOpenTimer (set to zero),
                self.delay_open_timer.stop_and_reset();

                //- completes the BGP initialization,
                // TODO anything?

                //- sends the OPEN message to its remote peer,
                self.send_open();

                //- sets its hold timer to a large value, and
                // TODO

                //- changes its state to OpenSent.
                self.set_state(State::OpenSent);
            }
            //(S::Active, E::TcpConnectionValid) => { todo!() }
            //(S::Active, E::TcpCrInvalid) => { todo!() }
            (S::Active, E::TcpCrAcked | E::TcpConnectionConfirmed) => {
                if self.attributes.delay_open() {
                    //If the DelayOpen attribute is set to TRUE, the local
                    //system:
                    //  - stops the ConnectRetryTimer and sets the
                    //    ConnectRetryTimer to zero,
                    self.connect_retry_timer.stop_and_reset();
                    
                    //  - sets the DelayOpenTimer to the initial value
                    //    (DelayOpenTime), and
                    self.delay_open_timer.start();

                    //  - stays in the Active state.
                    // (noop)
                } else {
                    //If the DelayOpen attribute is set to FALSE, the local
                    //system:
                    //  - sets the ConnectRetryTimer to zero,
                    self.connect_retry_timer.start();

                    //  - completes the BGP initialization,
                    //  TODO something?

                    //  - sends the OPEN message to its peer,
                    debug!("send_open in Active, no DelayOpen");
                    self.send_open();

                    //  - sets its HoldTimer to a large value (sugg: 4min), 
                    //  TODO

                    //  - changes its state to OpenSent.
                    self.set_state(State::OpenSent);
                }
            }
            (S::Active, E::TcpConnectionFails) => {
                //- restarts the ConnectRetryTimer (with the initial value),
                self.connect_retry_timer.start();

                //- stops and clears the DelayOpenTimer (sets the value to
                // zero),
                self.delay_open_timer.stop_and_reset();

                //- releases all BGP resource,
                // TODO something?

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- optionally performs peer oscillation damping if the
                //  DampPeerOscillations attribute is set to TRUE, and
                //  TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.set_state(State::Idle);
            }
            // optional:
            // XXX D-R-Y with (S::Connect, E::BgpOpen(_)) case
            (S::Active, E::BgpOpenWithDelayOpenTimerRunning(open_msg)) => {
                //- stops the ConnectRetryTimer (if running) and sets the
                //  ConnectRetryTimer to zero,
                self.connect_retry_timer.stop_and_reset();

                //- stops and clears the DelayOpenTimer (sets to zero),
                self.delay_open_timer.stop_and_reset();

                //- completes the BGP initialization,
                // do we need to do something here?

                //- sends an OPEN message,
                if !self.config.remote_asn_allowed(open_msg.my_asn()) {
                    warn!(
                        "unexpected ASN {} in OPEN",
                        open_msg.my_asn()
                    );
                    self.disconnect(DisconnectReason::FsmViolation(Some(
                                OpenMessageSubcode::BadPeerAs.into()
                                )));
                    self.set_state(State::Idle);
                    return Err(Error { msg: "stop processing" })
                }

                let received_addpaths = open_msg.addpath_families_vec()
                    .map_err(|_| Error { msg: "failed to parse addpath caps" })?;
                let intersection = received_addpaths.iter().filter(|(fam, dir)|{
                    matches!(
                        dir,
                        AddpathDirection::Send |
                        AddpathDirection::SendReceive
                    ) &&
                    self.config.addpath().contains(fam)
                }).map(|(fam, dir)| AddpathFamDir::new(*fam, *dir)).collect::<Vec<_>>();
                debug!("addpath intersection: {:?}", &intersection);


                let negotiated = NegotiatedConfig {
                    hold_time: std::cmp::min(open_msg.holdtime(), self.hold_time()),
                    // TODO rename .identifier() and its return type in
                    // routecore?
                    remote_bgp_id: open_msg.identifier()[0..4].try_into().unwrap(),
                    remote_asn: open_msg.my_asn(),
                    // XXX yeah..
                    remote_addr: self.connection.as_ref().unwrap().remote_addr(),
                    addpath: intersection,
                };
                self.send_open();
                self.set_negotiated_config(negotiated.clone());
                debug!(
                    "Negotiated: {}@{} id {:?}, hold time {}s",
                    negotiated.remote_asn,
                    negotiated.remote_addr,
                    negotiated.remote_bgp_id,
                    negotiated.hold_time,
                );
                let _ = self.channel.send(Message::SessionNegotiated(negotiated)).await;


                //- sends a KEEPALIVE message,
                self.send_keepalive();

                // TODO support for holdtime == 0
                //- if the HoldTimer value is non-zero,

                    //- starts the KeepaliveTimer to initial value,
                self.keepalive_timer.start();

                    //- resets the HoldTimer to the negotiated value,

                //else if the HoldTimer is zero

                    //- resets the KeepaliveTimer (set to zero),

                    //- resets the HoldTimer to zero, and
                self.hold_timer.start();

                //- changes its state to OpenConfirm.
                self.set_state(State::OpenConfirm);

              //If the value of the autonomous system field is the same as the
              //local Autonomous System number, set the connection status to an
              //internal connection; otherwise it will be external.
            },

            (S::Active, E::BgpHeaderErr | E::BgpOpenMsgErr) => { 
                //- (optionally) sends a NOTIFICATION message with the
                //appropriate error code if the SendNOTIFICATIONwithoutOPEN
                //attribute is set to TRUE,
                if self.attributes().notification_without_open() {
                    todo!();
                }

                //- sets the ConnectRetryTimer to zero,
                self.connect_retry_timer.stop_and_reset();

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
                self.set_state(State::Idle);
            }

            (S::Active, E::NotifMsgVerErr) => {
                if self.delay_open_timer.is_running() {
                    // If the DelayOpenTimer is running, the local system:
                    //- stops the ConnectRetryTimer (if running) and sets the
                    //  ConnectRetryTimer to zero,
                    self.connect_retry_timer.stop_and_reset();

                    //- stops and resets the DelayOpenTimer (sets to zero),
                    self.delay_open_timer.stop_and_reset();
                    
                    //- releases all BGP resources,
                    // TODO something?
                    
                    //- drops the TCP connection, and
                    // TODO tokio
                    
                } else {
                    //If the DelayOpenTimer is not running, the local system:
                    //  - sets the ConnectRetryTimer to zero,
                    self.connect_retry_timer.stop_and_reset();

                    //  - releases all BGP resources,
                    //  TODO something?

                    //  - drops the TCP connection,
                    //  TODO tokio

                    //  - increments the ConnectRetryCounter by 1,
                    self.increase_connect_retry_counter();

                    //  - (optionally) performs peer oscillation damping if
                    //  the DampPeerOscillations attribute is set to TRUE, and
                    // TODO once DampPeerOscillations is implemented

                }
                //  - changes its state to Idle.
                self.set_state(State::Idle);
            }
            (S::Active, 
                //E::AutomaticStop |
                E::HoldTimerExpires |
                E::KeepaliveTimerExpires |
                //E::IdleHoldTimerExpires |
                E::BgpOpen(_) |
                //E::OpenCollisionDump |
                E::NotifMsg |
                E::KeepaliveMsg |
                E::UpdateMsg |
                E::UpdateMsgErr
                ) => {
                    //- sets the ConnectRetryTimer to zero,
                    self.connect_retry_timer.stop_and_reset();

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
                    warn!(
                        "Changing from Active to Idle because of {:?}",
                        event
                    );
                    self.set_state(State::Idle);
            }


            //--- OpenSent ---------------------------------------------------
            (S::OpenSent,
                 E::ManualStart |
                 E::AutomaticStart |
                 E::ManualStartWithPassiveTcpEstablishment |
                 E::AutomaticStartWithPassiveTcpEstablishment
                 /* | events 6, 7 */
            ) => {
                info!("ignored {:?} in state OpenSent", event);
            }
            (S::OpenSent, E::ManualStop) => {
                //- sends the NOTIFICATION with a Cease,
                // TODO tokio
                self.disconnect(DisconnectReason::Shutdown);

                //- sets the ConnectRetryTimer to zero,
                self.connect_retry_timer.stop_and_reset();

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection,
                // (handled y the self.disconnect above)

                //- sets the ConnectRetryCounter to zero, and
                self.reset_connect_retry_counter();

                //- changes its state to Idle.
                self.set_state(State::Idle);

            }
            // optional: 
            //S::OpenSent, E::AutomaticStop) => { todo!() }
            (S::OpenSent, E::HoldTimerExpires) => {
                //- sends a NOTIFICATION message with the error code Hold
                //Timer Expired,
                self.disconnect(DisconnectReason::HoldTimerExpired);

                //- sets the ConnectRetryTimer to zero,
                self.connect_retry_timer.stop_and_reset();

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection,
                // already done in self.disconnect();

                //- increments the ConnectRetryCounter,
                self.increase_connect_retry_counter();

                //- (optionally) performs peer oscillation damping if the
                //  DampPeerOscillations attribute is set to TRUE, and
                // TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.set_state(State::Idle);
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
                self.connect_retry_timer.reset();

                //- continues to listen for a connection that may be initiated
                //  by the remote BGP peer, and
                //  (handled by tokio elsewhere)

                //- changes its state to Active.
                self.set_state(State::Active);
            }
            (S::OpenSent, E::BgpOpen(open_msg)) => {
                //- resets the DelayOpenTimer to zero,
                self.delay_open_timer.stop_and_reset();

                //- sets the BGP ConnectRetryTimer to zero,
                self.connect_retry_timer.stop_and_reset();

                // TODO XXX check the contents of the received OPEN
                // - expected remote ASN?
                // - extract and store capabilities:
                //      we know what we are capable of ourselves
                //      determine the intersection of that
                //      that will make up our SessionConfig or whatever we'll
                //      rename it to
                // - check all other possible subcodes in Notification

        // rfc4271, if the received OPEN is not correct, then:
        //- (optionally) sends a NOTIFICATION message with the appropriate
        //  error code if the SendNOTIFICATIONwithoutOPEN attribute is set
        //  to TRUE,

        //- sets the ConnectRetryTimer to zero,

        //- releases all BGP resources,

        //- drops the TCP connection,

        //- increments the ConnectRetryCounter by 1,

        //- (optionally) performs peer oscillation damping if the
        //  DampPeerOscillations attribute is set to TRUE, and

        //- changes its state to Idle.

                if !self.config.remote_asn_allowed(open_msg.my_asn()) {
                    warn!(
                        "unexpected ASN {} in OPEN",
                        open_msg.my_asn()
                    );
                    self.disconnect(DisconnectReason::FsmViolation(Some(
                                OpenMessageSubcode::BadPeerAs.into()
                                )));
                    self.set_state(State::Idle);
                    return Err(Error { msg: "stop processing" })
                }

                let received_addpaths = open_msg.addpath_families_vec()
                    .map_err(|_| Error { msg: "failed to parse addpath caps" })?;
                let intersection = received_addpaths.iter().filter(|(fam, dir)|{
                    matches!(
                        dir,
                        AddpathDirection::Send |
                        AddpathDirection::SendReceive
                    ) &&
                    self.config.addpath().contains(fam)
                }).map(|(fam, dir)| AddpathFamDir::new(*fam, *dir)).collect::<Vec<_>>();
                debug!("addpath intersection: {:?}", &intersection);

                let negotiated = NegotiatedConfig {
                    hold_time: std::cmp::min(open_msg.holdtime(), self.hold_time()),
                    // TODO rename .identifier() and its return type in
                    // routecore?
                    remote_bgp_id: open_msg.identifier()[0..4].try_into().unwrap(),
                    remote_asn: open_msg.my_asn(),
                    // XXX yeah..
                    remote_addr: self.connection.as_ref().unwrap().remote_addr(),
                    addpath: intersection,
                };

                debug!(
                    "Negotiated: {}@{} id {:?}, hold time {}s",
                    negotiated.remote_asn,
                    negotiated.remote_addr,
                    negotiated.remote_bgp_id,
                    negotiated.hold_time,
                );


                self.set_negotiated_config(negotiated.clone());
                let _ = self.channel.send(Message::SessionNegotiated(negotiated)).await;

                //- sends a KEEPALIVE message, and
                self.send_keepalive();

                //- sets a KeepaliveTimer:
                // If the negotiated hold time value is zero, then the
                // HoldTimer and KeepaliveTimer are not started.  If the value
                // of the Autonomous System field is the same as the local
                // Autonomous System number, then the connection is an
                // "internal" connection; otherwise, it is an "external"
                // connection.  (This will impact UPDATE processing as
                // described below.)
                self.keepalive_timer.start();

                //- sets the HoldTimer according to the negotiated value (see
                //  Section 4.2),
                //
                //  Not very clear from the standard if we also need to
                //  actually start it, but it makes sense to do so.
                self.hold_timer.start();

                //- changes its state to OpenConfirm.
                self.set_state(State::OpenConfirm);
            }
            (S::OpenSent, E::BgpHeaderErr | E::BgpOpenMsgErr) => {
                //- sends a NOTIFICATION message with the appropriate error
                //code,
                // TODO tokio

                //- sets the ConnectRetryTimer to zero,
                self.connect_retry_timer.stop_and_reset();

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection,
                self.drop_connection();

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- (optionally) performs peer oscillation damping if the
                //  DampPeerOscillations attribute is TRUE, and
                //  TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.set_state(State::Idle);
            }
            // optional:
            //(S::OpenSent, E::OpenCollisionDump) => { todo!() }
            (S::OpenSent, E::NotifMsgVerErr) => {
                //- sets the ConnectRetryTimer to zero,
                self.connect_retry_timer.stop_and_reset();

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection, and
                self.drop_connection();

                //- changes its state to Idle.
                self.set_state(State::Idle);
            }
            (S::OpenSent, 
                E::ConnectRetryTimerExpires |
                E::KeepaliveTimerExpires |
                E::DelayOpenTimerExpires |
                //E::IdleHoldTimerExpires |
                E::BgpOpenWithDelayOpenTimerRunning(_) |
                E::NotifMsg |
                E::KeepaliveMsg |
                E::UpdateMsg |
                E::UpdateMsgErr
            ) => {
                //- sends the NOTIFICATION with the Error Code Finite State
                //Machine Error,
                self.disconnect(DisconnectReason::FsmViolation(Some(
                    FiniteStateMachineSubcode::
                        UnexpectedMessageInOpenSentState.into()
                )));

                //- sets the ConnectRetryTimer to zero,
                self.connect_retry_timer.stop_and_reset();

                //- releases all BGP resources,
                //TODO something?

                //- drops the TCP connection,
                // (handled in the self.disconnect above)

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- (optionally) performs peer oscillation damping if the
                //DampPeerOscillations attribute is set to TRUE, and
                // TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.set_state(State::Idle);
            }

            
            //--- OpenConfirm ------------------------------------------------


            (S::OpenConfirm,
                 E::ManualStart |
                 E::AutomaticStart |
                 E::ManualStartWithPassiveTcpEstablishment |
                 E::AutomaticStartWithPassiveTcpEstablishment
                 /* | events 6, 7 */
            ) => {
                info!("ignored {:?} in state OpenConfirm", event);
            }
            (S::OpenConfirm, E::ManualStop) => {
                //- sends the NOTIFICATION message with a Cease,
                self.disconnect(DisconnectReason::Shutdown);

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection,
                // (handled by self.disconnect above)

                //- sets the ConnectRetryCounter to zero,
                self.reset_connect_retry_counter();

                //- sets the ConnectRetryTimer to zero, and
                self.connect_retry_timer.stop_and_reset();

                //- changes its state to Idle.
                self.set_state(State::Idle);
            }
            // optional: 
            //(S::OpenConfirm, E::AutomaticStop) => { todo!() }
           
            (S::OpenConfirm, E::HoldTimerExpires) => {
                //- sends the NOTIFICATION message with the Error Code Hold
                //Timer Expired,
                self.disconnect(DisconnectReason::HoldTimerExpired);

                //- sets the ConnectRetryTimer to zero,
                self.connect_retry_timer.stop_and_reset();

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection,
                // already done in self.disconnect()

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- (optionally) performs peer oscillation damping if the
                // DampPeerOscillations attribute is set to TRUE, and
                // TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.set_state(State::Idle);
            }
            (S::OpenConfirm, E::KeepaliveTimerExpires) => {
                //- sends a KEEPALIVE message,
                self.send_keepalive();

                //- restarts the KeepaliveTimer
                // (Our Timers restart automatically)

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
                self.connect_retry_timer.stop_and_reset();

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection,
                self.drop_connection();

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- (optionally) performs peer oscillation damping if the
                // DampPeerOscillations attribute is set to TRUE, and
                // TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.set_state(State::Idle);
            }
            (S::OpenConfirm, E::NotifMsgVerErr) => {
                //- sets the ConnectRetryTimer to zero,
                self.connect_retry_timer.stop_and_reset();

                //- releases all BGP resources,
                //TODO something?

                //- drops the TCP connection, and
                self.drop_connection();

                //- changes its state to Idle.
                self.set_state(State::Idle);
            }
            (S::OpenConfirm, E::BgpOpen(_)) => {
                // If the local system receives a valid OPEN message (BGPOpen
                // (Event 19)), the collision detect function is processed per
                //    Section 6.8.  If this connection is to be dropped due to
                //    connection collision, the local system:

                //TODO implement the collision resolution
                todo!();
                       
                //- sends a NOTIFICATION with a Cease,
                //self.disconnect(DisconnectReason::Collision).await;

                //- sets the ConnectRetryTimer to zero,
                self.connect_retry_timer.stop_and_reset();

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
                self.set_state(State::Idle);
            }
            (S::OpenConfirm, E::BgpHeaderErr | E::BgpOpenMsgErr) => {
                //- sends a NOTIFICATION message with the appropriate error
                //code,
                // TODO tokio

                //- sets the ConnectRetryTimer to zero,
                self.connect_retry_timer.stop_and_reset();

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
                self.set_state(State::Idle);
            }
            // optional:
            //(S::OpenConfirm, E::OpenCollisionDump) => { todo!() }
            (S::OpenConfirm, E::KeepaliveMsg) => {
                //- restarts the HoldTimer and
                self.hold_timer.reset();

                //- changes its state to Established.
                self.set_state(State::Established);
            }
            (S::OpenConfirm, 
                E::ConnectRetryTimerExpires |
                E::DelayOpenTimerExpires |
                //E::IdleHoldTimerExpires |
                E::BgpOpenWithDelayOpenTimerRunning(_) |
                E::UpdateMsg |
                E::UpdateMsgErr
            ) => {
                //- sends a NOTIFICATION with a code of Finite State Machine
                //  Error,
                self.disconnect(DisconnectReason::FsmViolation(Some(
                    FiniteStateMachineSubcode::
                        UnexpectedMessageInOpenConfirmState.into()
                )));

                //- sets the ConnectRetryTimer to zero,
                self.connect_retry_timer.stop_and_reset();

                //- releases all BGP resources,
                //TODO something?

                //- drops the TCP connection,
                // (handled in the self.disconnect above)

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- (optionally) performs peer oscillation damping if the
                //  DampPeerOscillations attribute is set to TRUE, and
                //  TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.set_state(State::Idle);
            }

            //--- Established ------------------------------------------------

            (S::Established,
                 E::ManualStart |
                 E::AutomaticStart |
                 E::ManualStartWithPassiveTcpEstablishment |
                 E::AutomaticStartWithPassiveTcpEstablishment
                 /* | events 6, 7 */
            ) => {
                info!("ignored {:?} in state Established", event);
            }
            (S::Established, E::ManualStop) => {
                //- sends the NOTIFICATION message with a Cease,
                self.disconnect(DisconnectReason::Shutdown);

                //- sets the ConnectRetryTimer to zero,
                self.connect_retry_timer.stop_and_reset();

                //- deletes all routes associated with this connection,
                //TODO manage store

                //- releases BGP resources,
                //TODO something?

                //- drops the TCP connection,
                // (handled y the self.disconnect above)

                //- sets the ConnectRetryCounter to zero, and
                self.reset_connect_retry_counter();

                //- changes its state to Idle.
                self.set_state(State::Idle);
            }
            // optional:
            //(S::Established, E::AutomaticStop) => { todo!() }

            (S::Established, E::HoldTimerExpires) => {

                //- sends a NOTIFICATION message with the Error Code Hold Timer
                //  Expired,
                self.disconnect(DisconnectReason::HoldTimerExpired);

                //- sets the ConnectRetryTimer to zero,
                self.connect_retry_timer.stop_and_reset();

                //- releases all BGP resources,
                // TODO store

                //- drops the TCP connection,
                // already done in self.disconnect();

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- (optionally) performs peer oscillation damping if the
                //  DampPeerOscillations attribute is set to TRUE, and
                //  TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.set_state(State::Idle);
            }
            (S::Established, E::KeepaliveTimerExpires) => {
                //- sends a KEEPALIVE message, and
                self.send_keepalive();

                //- restarts its KeepaliveTimer, unless the negotiated
                //  HoldTime value is zero.
                //  (Our Timer restarts automatically after expiring.)
            }
            // optional:
            // (S::Established, E::TcpConnectionValid) => { todo!() }
            // (S::Established, E::TcpCrInvalid) => { info!("ignored etc") }

            (S::Established,
             E::TcpCrAcked | E::TcpConnectionConfirmed ) => {
                // In response to an indication that the TCP connection is
                // successfully established (Event 16 or Event 17), the second
                // connection SHALL be tracked until it sends an OPEN message.

                // TODO implement collision detection.
                todo!()
            }
            (S::Established, E::BgpOpen(_)) => {
                todo!()
                // once CollisionDetectEstablishedState is implemented, things
                // need to happen here
            }
            // optional:
            //(S::Established, E::OpenCollisionDump) => { todo!() }
            (S::Established,
             E::NotifMsgVerErr | E::NotifMsg | E::TcpConnectionFails) => {

                //- sets the ConnectRetryTimer to zero,
                self.connect_retry_timer.stop_and_reset();

                //- deletes all routes associated with this connection,
                // TODO store

                //- releases all the BGP resources,
                // TODO something?

                //- drops the TCP connection,
                self.drop_connection();

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- changes its state to Idle.
                self.set_state(State::Idle);
            }

            (S::Established, E::KeepaliveMsg) => {
                //- restarts its HoldTimer, if the negotiated HoldTime value
                //  is non-zero
                self.hold_timer.reset();

                //- remains in the Established state.
                // (noop)
            }
            (S::Established, E::UpdateMsg) => {
                //- processes the message
                // (PDU is passed over the channel to the user of this
                // Session, we do not do anything with its contents here.)

                //- restarts its HoldTimer, if the negotiated HoldTime value is
                //  non-zero
                self.hold_timer.reset();

                //- remains in the Established state.
                //  (noop)
            }
            (S::Established, E::UpdateMsgErr) => {
                //- sends a NOTIFICATION message with an Update error,
                //TODO enhance E::UpdateMsgErr with a specific subtype so we
                //can create the correct NOTIFICATION. Also, depending on
                //rfc7606, we might not need to shutdown the TCP session.

                //- sets the ConnectRetryTimer to zero,
                self.connect_retry_timer.stop_and_reset();

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
                self.set_state(State::Idle);
            }


            (S::Established, 
                E::ConnectRetryTimerExpires |
                E::DelayOpenTimerExpires |
                //E::IdleHoldTimerExpires |
                E::BgpOpenWithDelayOpenTimerRunning(_) |
                E::BgpHeaderErr |
                E::BgpOpenMsgErr
            ) => {
                debug!("got unexpected {event:?} in S::Established");
                //- sends a NOTIFICATION message with the Error Code Finite State
                //  Machine Error,
                self.disconnect(DisconnectReason::FsmViolation(Some(
                    FiniteStateMachineSubcode::
                        UnexpectedMessageInEstablishedState.into()
                )));

                //- deletes all routes associated with this connection,
                // TODO store

                //- sets the ConnectRetryTimer to zero,
                self.connect_retry_timer.stop_and_reset();

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection,
                // (handled in self.disconnect above)

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- (optionally) performs peer oscillation damping if the
                //  DampPeerOscillations attribute is set to TRUE, and
                //  TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.set_state(State::Idle);
            }
        }
        Ok(())
    }
}

//------------ Messages & Commands -------------------------------------------
//
// These are enums used to send received PDUs (e.g. UPDATEs) and such to the
// user of a Session. The Command enum is used to instruct the Session to
// perform certain actions, or to query its statistics.

/// Messages sent to user of this Session.
pub enum Message {
    UpdateMessage(UpdateMessage<Bytes>),
    NotificationMessage(NotificationMessage<Bytes>),
    Attributes(SessionAttributes),
    SessionNegotiated(NegotiatedConfig),
    ConnectionLost(Option<SocketAddr>),
}

/// Commands sent from user to this Session.
#[derive(Debug)]
pub enum Command {
    AttachStream {
        stream: OwnedReadHalf,
    },
    GetAttributes {
        resp: oneshot::Sender<SessionAttributes>,
    },
    Disconnect(DisconnectReason),
    ForcedKeepalive,
    //RawUpdate(UpdateMessage<Vec<u8>>),
}

/// Reason for disconnecting the peer.
///
/// When disconnecting a peer, a NOTIFICATION PDU is send out with an error
/// (sub)code depending on the variant.
#[derive(Copy, Clone, Debug)]
pub enum DisconnectReason {
    ConnectionRejected,
    Reconfiguration,
    Deconfigured,
    HoldTimerExpired,
    Shutdown,
    FsmViolation(Option<Details>),
    Other,
}

//------------ Connection ----------------------------------------------------
/// TCP-level connection carrying the BGP session.
#[derive(Debug)]
pub struct Connection {
    remote_addr: SocketAddr,
    //stream: TcpStream,
    tcp_in: OwnedReadHalf,
    buffer: BytesMut,
    session_config: SessionConfig,
}

impl Connection {
    /// Construct a `Connection` for a `TcpStream`.
    /*
     pub fn for_stream(stream: TcpStream) -> Connection {
        Connection {
            remote_addr: stream.peer_addr().unwrap(),
            stream,
            buffer: BytesMut::with_capacity(2^20),
            session_config: SessionConfig::modern(),
        }
    }
    */

    pub const fn remote_addr(&self) -> IpAddr {
        self.remote_addr.ip()
    }

    pub fn for_read_half(tcp_in: OwnedReadHalf) -> Self {
        Self {
            remote_addr: tcp_in.peer_addr().unwrap(),
            tcp_in,
            buffer: BytesMut::with_capacity(2 ^ 20),
            session_config: SessionConfig::modern(),
        }
    }

    pub fn session_config_mut(&mut self) -> &mut SessionConfig {
        &mut self.session_config
    }

    /*
    async fn disconnect(&mut self) {
        //let _ = self.stream.shutdown().await;
        //todo!()
        //self.tcp_in.as_ref().shutdown();
        debug!("disconnect, noop");
    }
    */

    async fn read_frame(&mut self) -> Result<Option<BgpMsg<Bytes>>, Error> {
        loop {
            if let Some(frame) = self.parse_frame()? {
                return Ok(Some(frame));
            }
            if 0 == self.tcp_in.read_buf(&mut self.buffer).await? {
                if self.buffer.is_empty() {
                    return Ok(None);
                }
                return Err(Error::for_str("connection reset by peer"));
            }
        }
    }

    // XXX maybe turn this into a take_frame
    // and do the parsing within the FSM so we can send the correct
    // NOTIFICATIONs etc?
    fn parse_frame(&mut self) -> Result<Option<BgpMsg<Bytes>>, ParseError> {
        let mut buf = Cursor::new(&self.buffer[..]);

        if buf.remaining() >= 16 + 2 {
            buf.set_position(16);
            let len = buf.get_u16();
            if buf.remaining() >= ((len as usize) - 18) {
                //return Ok(len)
                buf.set_position(0);
                let b =
                    Bytes::copy_from_slice(&buf.into_inner()[..len.into()]);
                // XXX the SessionConfig needs to be updated based on the
                // exchanged BGP OPENs
                let msg = BgpMsg::from_octets(b, Some(&self.session_config))?;
                self.buffer.advance(len.into());
                return Ok(Some(msg));
            }
        }
        Ok(None)
    }
}

async fn maybe_read_frame(
    conn: Option<&mut Connection>,
) -> Option<Result<Option<BgpMsg<Bytes>>, Error>> {
    if let Some(c) = conn {
        Some(c.read_frame().await)
    } else {
        None
    }
}

//------------ BgpConfig ------------------------------------------------------

/// Mandatory methods to represent local BGP configuration.
pub trait BgpConfig {
    fn local_asn(&self) -> Asn;
    fn bgp_id(&self) -> [u8; 4];
    fn remote_addr_allowed(&self, remote_addr: IpAddr) -> bool;
    fn remote_asn_allowed(&self, remote_asn: Asn) -> bool;
    fn hold_time(&self) -> Option<u16>;
    fn is_exact(&self) -> bool;

    fn protocols(&self) -> Vec<AfiSafiType>;
    fn addpath(&self) -> Vec<AfiSafiType>;
}

//------------ BasicConfig ---------------------------------------------------
/// Basic local configuration of a BGP session.
///
/// This holds all the information needed to setup a BGP session with a remote
/// peer.
///
/// **NB**: this is different from the `SessionConfig` in routecore (which
/// should be renamed) used to parse BGP (UPDATE) PDUs.
///
/// Furthermore, this is not to be confused with [`NegotiatedConfig`] which
/// holds the actual parameters for a (established) BGP session.
#[derive(Clone, Debug)]
pub struct BasicConfig {
    local_asn: Asn,
    bgp_id: [u8; 4],
    pub remote_asn: Asn,
    pub remote_addr: IpAddr,
    pub hold_time: Option<u16>,
    _capabilities: Vec<Capability<Vec<u8>>>,
}

impl BasicConfig {
    pub const fn new(
        local_asn: Asn,
        bgp_id: [u8; 4],
        remote_addr: IpAddr,
        remote_asn: Asn,
        hold_time: Option<u16>,
    ) -> Self {
        Self {
            local_asn,
            bgp_id,
            remote_asn,
            remote_addr,
            hold_time,
            _capabilities: vec![],
        }
    }
}

impl BgpConfig for BasicConfig {
    fn local_asn(&self) -> Asn {
        self.local_asn
    }

    fn bgp_id(&self) -> [u8; 4] {
        self.bgp_id
    }

    fn remote_addr_allowed(&self, remote_addr: IpAddr) -> bool {
        remote_addr == self.remote_addr
    }

    fn remote_asn_allowed(&self, remote_asn: Asn) -> bool {
        remote_asn == self.remote_asn
    }

    fn hold_time(&self) -> Option<u16> {
        self.hold_time
    }

    fn is_exact(&self) -> bool {
        true
    }

    fn protocols(&self) -> Vec<AfiSafiType> {
        vec![AfiSafiType::Ipv4Unicast, AfiSafiType::Ipv6Unicast]
    }

    fn addpath(&self) -> Vec<AfiSafiType> {
        vec![]
    }
}

//------------ NegotiatedConfig ----------------------------------------------

/// The parameters for a (established) BGP session.
///
/// The NegotiatedConfig is based on local configuration, i.e. something that
/// implements the [`BgpConfig`] trait, and the BGP OPEN message received from
/// the remote peer.
/// Note that a NegotiatedConfig might be a subset of the parameters defined
/// in the local configuration (e.g. capabilities that are locally configured
/// but not signaled by the peer), or contain different values (e.g. a lower
/// hold time than locally configured, because the peer sent a lower hold time
/// in the BGP OPEN message).
// TODO impl Into<SessionConfig> (or Into<ParseInfo>, rather)
// TODO create convenience functions to create a NegotiatedConfig from a
// BgpConfig and an OpenMessage.
#[derive(Clone, Debug)]
pub struct NegotiatedConfig {
    //capabilities: Vec<Capability<Vec<u8>>,
    hold_time: u16, // smaller of the two OPENs, 0 or >= 3
    remote_bgp_id: [u8; 4],
    remote_asn: Asn,
    remote_addr: IpAddr,
    addpath: Vec<AddpathFamDir>,
}

impl NegotiatedConfig {
    pub const fn remote_asn(&self) -> Asn {
        self.remote_asn
    }

    pub const fn remote_addr(&self) -> IpAddr {
        self.remote_addr
    }

    /// Dummy constructor, only useful for testing.
    pub fn dummy() -> Self {
        Self {
            hold_time: 0,
            remote_bgp_id: [1, 2, 3, 4],
            remote_asn: Asn::from_u32(12345),
            remote_addr: IpAddr::V4([1, 2, 3, 4].into()),
            addpath: vec![],
        }
    }
}

//=========== Error Types ====================================================

use std::fmt;
#[derive(Debug)]
pub struct ConnectionError(String);
impl std::error::Error for ConnectionError {}
impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Connection error: {}", self.0)
    }
}
impl From<std::io::Error> for ConnectionError {
    fn from(e: std::io::Error) -> Self {
        Self(format!("Connection io error: {e}"))
    }
}

#[derive(Debug)]
pub struct UnexpectedPeer(IpAddr);
impl std::error::Error for UnexpectedPeer {}
impl fmt::Display for UnexpectedPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unexpected peer {}", self.0)
    }
}
impl From<UnexpectedPeer> for ConnectionError {
    fn from(e: UnexpectedPeer) -> Self {
        Self(e.to_string())
    }
}

#[derive(Debug)]
pub struct Error {
    msg: &'static str,
}
impl std::fmt::Display for Error {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter,
    ) -> Result<(), std::fmt::Error> {
        write!(f, "error: {}", self.msg)
    }
}

impl Error {
    pub const fn for_str(msg: &'static str) -> Self {
        Self { msg }
    }
}
impl From<std::io::Error> for Error {
    fn from(_e: std::io::Error) -> Self {
        Self::for_str("io error")
    }
}

impl From<ParseError> for Error {
    fn from(_e: ParseError) -> Self {
        Self::for_str("parse error")
    }
}

//--- Tests ------------------------------------------------------------------

/* FIXME
#[cfg(test)]
mod tests {

    use super::*;

    fn test_session() -> Session<DefaultHandler> {
        Session::new(Asn::from_u32(12345), [192, 0, 2, 1])
    }

    //--- Idle ---------------------------------------------------------------
    #[test]
    fn idle_to_connect() {
        let mut s = test_session();
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
        let mut s = Session::new();
        assert_eq!(s.state(), State::Idle);
        s.handle_event(Event::ManualStop);
        assert_eq!(s.state(), State::Idle);
    }

    //--- Connect ------------------------------------------------------------
    #[test]
    fn connect_manualstop() {
        let mut s = Session::new();
        s.handle_event(Event::ManualStart);
        s.handle_event(Event::ManualStop);
        assert_eq!(s.state(), State::Idle);


    }

}
*/
