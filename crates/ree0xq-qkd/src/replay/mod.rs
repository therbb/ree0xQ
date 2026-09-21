//! Replay scenarios for the KME emulator.
//!
//! A replay file is a YAML / JSON document describing a sequence of
//! timed [`ControlOp`](crate::emulator::ControlOp) events. The driver
//! reads the file, sleeps to each event's timestamp, and posts the op
//! to the emulator's `/control` endpoint.
//!
//! The five scenarios referenced in the paper ship in the repo at
//! `scenarios/{r1,r2,r3,r4,r5}.yaml`. The format is intentionally
//! minimal so additional scenarios are trivial to add.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::emulator::ControlOp;

/// One timed control event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReplayEvent {
    /// Wall-clock offset from scenario start, in seconds.
    pub at_seconds: u64,
    /// The control op to apply.
    pub op: ControlOp,
    /// Optional human-readable label (used for logging).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// A full replay scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayScenario {
    /// Short identifier (`r1-steady`, `r2-degradation`, ...).
    pub id: String,
    /// One-line description (rendered in logs and captures).
    pub description: String,
    /// Total scenario duration, in seconds.
    pub duration_seconds: u64,
    /// Timed control events, sorted by `at_seconds`.
    pub events: Vec<ReplayEvent>,
}

impl ReplayScenario {
    /// Validate that events are sorted by `at_seconds` and fit within
    /// `duration_seconds`.
    pub fn validate(&self) -> Result<(), ReplayError> {
        let mut prev = 0u64;
        for ev in &self.events {
            if ev.at_seconds < prev {
                return Err(ReplayError::OutOfOrder {
                    at: ev.at_seconds,
                    prev,
                });
            }
            if ev.at_seconds > self.duration_seconds {
                return Err(ReplayError::PastEnd {
                    at: ev.at_seconds,
                    duration: self.duration_seconds,
                });
            }
            prev = ev.at_seconds;
        }
        Ok(())
    }
}

/// Errors produced when loading / validating a scenario.
#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    /// Events are not sorted by `at_seconds` ascending.
    #[error("event at {at}s precedes earlier event at {prev}s")]
    OutOfOrder {
        /// Out-of-order event's timestamp.
        at: u64,
        /// The preceding event's timestamp.
        prev: u64,
    },
    /// An event's `at_seconds` exceeds the scenario `duration_seconds`.
    #[error("event at {at}s falls past scenario end {duration}s")]
    PastEnd {
        /// Offending event timestamp.
        at: u64,
        /// Scenario duration.
        duration: u64,
    },
}

/// Convert an `at_seconds` to a [`Duration`].
pub fn at_to_duration(at_seconds: u64) -> Duration {
    Duration::from_secs(at_seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(at: u64, op: ControlOp) -> ReplayEvent {
        ReplayEvent {
            at_seconds: at,
            op,
            label: None,
        }
    }

    #[test]
    fn r1_steady_state_is_trivially_valid() {
        let s = ReplayScenario {
            id: "r1-steady".into(),
            description: "24h steady-state at default QBER and key rate.".into(),
            duration_seconds: 86_400,
            events: vec![],
        };
        s.validate().unwrap();
    }

    #[test]
    fn r2_degradation_validates() {
        let s = ReplayScenario {
            id: "r2-degradation".into(),
            description: "Gradual QBER ramp from 0.018 to 0.085 over 4h.".into(),
            duration_seconds: 14_400,
            events: vec![
                ev(0, ControlOp::SetQber { qber: 0.018 }),
                ev(3600, ControlOp::SetQber { qber: 0.035 }),
                ev(7200, ControlOp::SetQber { qber: 0.055 }),
                ev(10800, ControlOp::SetQber { qber: 0.075 }),
                ev(14400, ControlOp::SetQber { qber: 0.085 }),
            ],
        };
        s.validate().unwrap();
    }

    #[test]
    fn out_of_order_events_rejected() {
        let s = ReplayScenario {
            id: "broken".into(),
            description: "out of order".into(),
            duration_seconds: 1000,
            events: vec![
                ev(100, ControlOp::SetQber { qber: 0.02 }),
                ev(50, ControlOp::SetQber { qber: 0.03 }),
            ],
        };
        assert!(matches!(s.validate(), Err(ReplayError::OutOfOrder { .. })));
    }
}
