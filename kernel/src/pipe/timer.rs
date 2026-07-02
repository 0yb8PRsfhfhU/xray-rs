//! Idle-activity timer: cancels a connection after a period with no traffic
//! in either direction (SPEC §1, default 300s).

use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// Shared idle timer. Both copy loops call [`Timer::update`] per chunk; a
/// background task cancels the token once `idle` elapses with no update.
#[derive(Clone)]
pub struct Timer {
    deadline: Arc<Mutex<Instant>>,
    idle: Duration,
    token: CancellationToken,
}

impl Timer {
    /// Start a timer with the given idle timeout and a fresh cancellation token.
    pub fn new(idle: Duration) -> Timer {
        let token = CancellationToken::new();
        let deadline = Arc::new(Mutex::new(
            Instant::now()
                .checked_add(idle)
                .unwrap_or_else(Instant::now),
        ));
        let timer = Timer {
            deadline,
            idle,
            token: token.clone(),
        };
        let bg = timer.clone();
        tokio::spawn(async move {
            loop {
                // Guard is copied out and dropped before any `.await`, so a
                // sync `parking_lot::Mutex` is correct here (never held across
                // the `select!`).
                let next = *bg.deadline.lock();
                tokio::select! {
                    _ = bg.token.cancelled() => break,
                    _ = tokio::time::sleep_until(next) => {
                        if Instant::now() >= *bg.deadline.lock() {
                            bg.token.cancel();
                            break;
                        }
                    }
                }
            }
        });
        timer
    }

    /// Reset the idle deadline to `now + idle`.
    pub fn update(&self) {
        *self.deadline.lock() = Instant::now()
            .checked_add(self.idle)
            .unwrap_or_else(Instant::now);
    }

    /// The token cancelled on idle timeout (or manual interrupt).
    pub fn token(&self) -> CancellationToken {
        self.token.clone()
    }

    /// Cancel immediately (interrupt).
    pub fn cancel(&self) {
        self.token.cancel();
    }
}
