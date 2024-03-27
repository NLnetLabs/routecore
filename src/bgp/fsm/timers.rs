use tokio::time::{interval, Instant};
use std::time::Duration;
use std::fmt;
use std::cmp;

use tokio::sync::{mpsc, oneshot};

use log::{debug, warn};

// TODO
//  - write out what all these do
//  - their relations 
//  - their recommended default values
//
// the fsm needs
//   hold timer
//   connect retry time
//   keepalive timer
//
//   and apparently, there is more:
//     MinASOriginationIntervalTimer (see Section 9.2.1.2), and
//     MinRouteAdvertisementIntervalTimer (see Section 9.2.1.1).
//
//   mentioned in 4271 as being optional:
//     group 1: DelayOpen, DelayOpenTime, DelayOpenTimer
//     group 2: DampPeerOscillations, IdleHoldTime, IdleHoldTimer
//
//

// Hold time: the smallest of the two Hold times exchanged in the BGP OPENs
// will be the hold time for the session, and must be 0 or >=3 seconds.
// When 0, no periodic KEEPALIVEs will be sent.
// If no UPDATE/KEEPALIVE/NOTIFICATION is received within the hold time, the
// BGP connection should be closed.
// Whenever an UPDATE/KEEPALIVE/NOTIFICATION is received, this timer is reset
// (if the negotiated time was not 0).
// Recommend value is 90s in 4271, though in early stages of the session this
// should be raised to 'a large value' (of 4 minutes).
//
// Connect retry timer: started when a TCP connection attempt is made. When
// expired, the current connection attempt is aborted, and a new connection is
// initialized.
//
// Keepalive timer is used to prevent the hold timer of the remote peer
// expiring. Upon expiration of the keepalive timer, a KEEPALIVE pdu is sent
// out, and the timer is reset. The keepalive timer is started after we've
// sent out our OPEN + KEEPALIVE to setup the session.
// It can be reset after each UPDATE/NOTIFICATION that we send out, though
// that is not explicitly written out in 4271.
// The period of the keepalive timer is typically 1/3 of the period of the
// Hold timer. Note that the hold timer is set to 'a large value' in early
// stages of the session.

#[derive(Debug)]
pub struct Timer {
    interval: Duration,
    started: bool,
    last_tick: Instant,
    last_reset: Instant,
    tick_recv: mpsc::Receiver<Instant>,
    tick_send: mpsc::Sender<Instant>,
    stop_send: Option<oneshot::Sender<()>>,
    reset_send: Option<mpsc::Sender<()>>,
}

impl Timer {
    /// Creates a new timer with an interval of `secs`.
    pub fn new(secs: u64) -> Self {
        let (tick_send, tick_recv) = mpsc::channel(1);
        Self {
            interval: Duration::from_secs(secs),
            started: false,
            last_tick: Instant::now(),
            last_reset: Instant::now(),
            tick_recv,
            tick_send,
            stop_send: None,
            reset_send: None,
        }
    }

    pub async fn tick(&mut self) -> Instant {
        self.last_tick = self.tick_recv.recv().await
            .expect("channel should never close");
        self.last_tick
    }

    pub fn start(&mut self) {
        self.started = true;
        let (stop_send, stop_recv) = oneshot::channel();
        let (reset_send, reset_recv) = mpsc::channel(1);

        self.stop_send = Some(stop_send);
        self.reset_send = Some(reset_send);

        let tick_send = self.tick_send.clone();
        let interval = self.interval;

        tokio::spawn(async move {
            tokio::select! {
                () = Self::timer_inner(interval, tick_send, reset_recv) => { },
                _ = stop_recv => {
                    debug!("timer stopped");
                }
            }
        });
    }

    async fn timer_inner(
        i: Duration,
        tick_send: mpsc::Sender<Instant>,
        mut reset_recv: mpsc::Receiver<()>,
    ) {
        let mut interval = interval(i);
        let tick_send = tick_send.clone();
        interval.tick().await;
        loop {
            tokio::select!{
                instant = interval.tick() => {
                    let _ = tick_send.send(instant).await;
                }
                _ = reset_recv.recv() => {
                    interval.reset();
                }
            }
        }
    }

    pub fn stop_and_reset(&mut self) {
        if let Some(tx) = self.stop_send.take() {
            let _ = tx.send(());
            self.last_reset = Instant::now();
        } else {
            warn!("trying to stop stopped timer");
        }
        self.started = false;
    }

    pub const fn is_running(&self) -> bool {
        self.started
    }

    pub fn reset(&mut self) {
        if let Some(tx) = &self.reset_send {
            let _ = tx.try_send(());
            self.last_reset = Instant::now();
        } else {
            warn!("trying to reset a stopped timer");
        }
    }
}

impl fmt::Display for Timer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let since = cmp::max(self.last_tick, self.last_reset);
        let togo = self.interval.checked_sub(
            Instant::now().duration_since(since)
        ).unwrap_or_default(); // Default is Duration::ZERO

        write!(f, "{:.2}/{} {}",
               togo.as_secs_f64(),
               self.interval.as_secs(),
               if self.started { "" } else { "(stopped)" }
        )
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use tokio::time::{sleep, timeout};

    #[allow(dead_code)]
    fn ptime() {
        println!("ptime: {:?}", Instant::now());
    }

    #[tokio::test]
    async fn works() {
        let secs = 1;
        let mut t = Timer::new(secs);
        let d = Duration::from_secs(secs);

        println!("{t}");
        let tstart = Instant::now();
        t.start();

        println!("{t}");

        let t0 = t.tick().await;
        assert!(tstart.elapsed() >= d);
        assert!(t0.elapsed() < d);
        let t1 = t.tick().await;
        assert!(t0.elapsed() >= d);
        let t2 = t.tick().await;
        assert!(t1.elapsed() >= d);
        let t3 = t.tick().await;
        assert!(t2.elapsed() >= d);

        sleep(Duration::from_millis(500)).await;
        println!("{t}");
        t.reset().await;
        println!("{t}");
        sleep(Duration::from_millis(500)).await;
        println!("{t}");
        t.reset().await;
        println!("{t}");
        let t4 = t.tick().await;
        assert!(t3.elapsed() >= 2*d);

        t.stop_and_reset();

        if let Err(_) = timeout(d*2, t.tick()).await {
            //println!("did not receive value within two intervals, Ok");
            assert!(t4.elapsed() >= d*2);
        } else {
            panic!("wrong");
        }

        println!("{t}");

        let t5 = Instant::now();
        t.start();
        let _ = t.tick().await;
        assert!(t5.elapsed() >= d);

    }
}
