//! KonoMind is the optional adaptive decision layer for KonoNexus.
//!
//! It learns bounded, local per-path quality from authenticated runtime
//! outcomes. It does not control cryptography, authentication, replay
//! protection, admission, or packet validation. Those remain hard protocol
//! rules in KNP Core.

const PATH_KIND_COUNT: usize = 3;
const EWMA_ALPHA: f32 = 0.2;
const LEARNING_CONFIDENCE_SAMPLES: f32 = 20.0;
const MAX_LEARNED_ADJUSTMENT: f32 = 0.15;
const MAX_OBSERVED_RTT_MS: f32 = 120_000.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    Direct,
    HolePunch,
    Relay,
}

impl PathKind {
    const fn index(self) -> usize {
        match self {
            Self::Direct => 0,
            Self::HolePunch => 1,
            Self::Relay => 2,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PathMetrics {
    pub rtt_ms: f32,
    pub packet_loss: f32,
    pub stability: f32,
    pub relay_load: f32,
}

impl PathMetrics {
    pub fn sanitized(self) -> Self {
        Self {
            rtt_ms: sanitize_rtt(self.rtt_ms),
            packet_loss: sanitize_ratio(self.packet_loss, 1.0),
            stability: sanitize_ratio(self.stability, 0.0),
            relay_load: sanitize_ratio(self.relay_load, 1.0),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RouteCandidate {
    pub path: PathKind,
    pub metrics: PathMetrics,
}

#[derive(Debug, Clone, Copy)]
pub struct NetworkObservation {
    pub path: PathKind,
    pub success: bool,
    pub rtt_ms: f32,
    pub packet_loss: f32,
}

impl NetworkObservation {
    fn sanitized(self) -> Self {
        Self {
            path: self.path,
            success: self.success,
            rtt_ms: sanitize_rtt(self.rtt_ms),
            packet_loss: sanitize_ratio(self.packet_loss, 1.0),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RouteRecommendation {
    pub path: PathKind,
    pub score: f32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PathLearningSnapshot {
    pub samples: u64,
    pub successes: u64,
    pub success_rate: f32,
    pub average_rtt_ms: f32,
    pub average_packet_loss: f32,
}

#[derive(Debug, Clone, Copy, Default)]
struct PathLearningState {
    samples: u64,
    successes: u64,
    ewma_rtt_ms: f32,
    ewma_packet_loss: f32,
}

impl PathLearningState {
    fn observe(&mut self, observation: NetworkObservation) {
        let first_sample = self.samples == 0;
        self.samples = self.samples.saturating_add(1);
        if observation.success {
            self.successes = self.successes.saturating_add(1);
        }

        if first_sample {
            self.ewma_rtt_ms = observation.rtt_ms;
            self.ewma_packet_loss = observation.packet_loss;
        } else {
            self.ewma_rtt_ms = ewma(self.ewma_rtt_ms, observation.rtt_ms, EWMA_ALPHA);
            self.ewma_packet_loss =
                ewma(self.ewma_packet_loss, observation.packet_loss, EWMA_ALPHA);
        }
    }

    fn snapshot(self) -> PathLearningSnapshot {
        PathLearningSnapshot {
            samples: self.samples,
            successes: self.successes,
            success_rate: ratio(self.successes, self.samples),
            average_rtt_ms: self.ewma_rtt_ms,
            average_packet_loss: self.ewma_packet_loss,
        }
    }
}

#[derive(Debug, Default)]
pub struct KonoMindAdvisor {
    samples_seen: u64,
    successful_samples: u64,
    paths: [PathLearningState; PATH_KIND_COUNT],
}

impl KonoMindAdvisor {
    pub fn observe(&mut self, observation: NetworkObservation) {
        let observation = observation.sanitized();
        self.samples_seen = self.samples_seen.saturating_add(1);
        if observation.success {
            self.successful_samples = self.successful_samples.saturating_add(1);
        }
        self.paths[observation.path.index()].observe(observation);
    }

    pub fn samples_seen(&self) -> u64 {
        self.samples_seen
    }

    pub fn success_rate(&self) -> f32 {
        ratio(self.successful_samples, self.samples_seen)
    }

    pub fn path_learning(&self, path: PathKind) -> PathLearningSnapshot {
        self.paths[path.index()].snapshot()
    }

    pub fn recommend(&self, candidates: &[RouteCandidate]) -> Option<RouteRecommendation> {
        candidates
            .iter()
            .map(|candidate| RouteRecommendation {
                path: candidate.path,
                score: (baseline_score(candidate.metrics)
                    + self.learning_adjustment(candidate.path))
                .clamp(0.0, 1.0),
            })
            .max_by(|a, b| a.score.total_cmp(&b.score))
    }

    fn learning_adjustment(&self, path: PathKind) -> f32 {
        let learned = self.path_learning(path);
        if learned.samples == 0 {
            return 0.0;
        }

        let confidence = (learned.samples as f32 / LEARNING_CONFIDENCE_SAMPLES).clamp(0.0, 1.0);
        let latency_score = 1.0 / (1.0 + learned.average_rtt_ms / 50.0);
        let quality = (learned.success_rate * 0.55)
            + ((1.0 - learned.average_packet_loss) * 0.30)
            + (latency_score * 0.15);
        let centered_quality = (quality - 0.5) * 2.0;

        (centered_quality * MAX_LEARNED_ADJUSTMENT * confidence)
            .clamp(-MAX_LEARNED_ADJUSTMENT, MAX_LEARNED_ADJUSTMENT)
    }
}

fn baseline_score(metrics: PathMetrics) -> f32 {
    let metrics = metrics.sanitized();

    let latency_score = 1.0 / (1.0 + metrics.rtt_ms / 50.0);
    let loss_score = 1.0 - metrics.packet_loss;
    let stability_score = metrics.stability;
    let load_score = 1.0 - metrics.relay_load;

    (latency_score * 0.35) + (loss_score * 0.30) + (stability_score * 0.25) + (load_score * 0.10)
}

fn sanitize_rtt(value: f32) -> f32 {
    if value.is_finite() {
        value.clamp(0.0, MAX_OBSERVED_RTT_MS)
    } else {
        MAX_OBSERVED_RTT_MS
    }
}

fn sanitize_ratio(value: f32, non_finite_fallback: f32) -> f32 {
    if value.is_finite() {
        value.clamp(0.0, 1.0)
    } else {
        non_finite_fallback
    }
}

fn ratio(numerator: u64, denominator: u64) -> f32 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f32 / denominator as f32
    }
}

fn ewma(previous: f32, current: f32, alpha: f32) -> f32 {
    previous + (current - previous) * alpha
}

#[cfg(test)]
mod tests {
    use super::*;

    fn neutral_metrics() -> PathMetrics {
        PathMetrics {
            rtt_ms: 50.0,
            packet_loss: 0.02,
            stability: 0.9,
            relay_load: 0.0,
        }
    }

    #[test]
    fn advisor_tracks_global_and_per_path_observations() {
        let mut advisor = KonoMindAdvisor::default();

        advisor.observe(NetworkObservation {
            path: PathKind::Direct,
            success: true,
            rtt_ms: 22.0,
            packet_loss: 0.0,
        });
        advisor.observe(NetworkObservation {
            path: PathKind::Relay,
            success: false,
            rtt_ms: 210.0,
            packet_loss: 0.2,
        });

        assert_eq!(advisor.samples_seen(), 2);
        assert_eq!(advisor.success_rate(), 0.5);
        assert_eq!(advisor.path_learning(PathKind::Direct).samples, 1);
        assert_eq!(advisor.path_learning(PathKind::Direct).successes, 1);
        assert_eq!(advisor.path_learning(PathKind::Relay).samples, 1);
        assert_eq!(advisor.path_learning(PathKind::HolePunch).samples, 0);
    }

    #[test]
    fn advisor_prefers_healthier_path_without_learning() {
        let advisor = KonoMindAdvisor::default();
        let recommendation = advisor
            .recommend(&[
                RouteCandidate {
                    path: PathKind::Relay,
                    metrics: PathMetrics {
                        rtt_ms: 180.0,
                        packet_loss: 0.08,
                        stability: 0.75,
                        relay_load: 0.7,
                    },
                },
                RouteCandidate {
                    path: PathKind::Direct,
                    metrics: PathMetrics {
                        rtt_ms: 28.0,
                        packet_loss: 0.01,
                        stability: 0.95,
                        relay_load: 0.0,
                    },
                },
            ])
            .expect("a recommendation should be produced");

        assert_eq!(recommendation.path, PathKind::Direct);
    }

    #[test]
    fn bounded_local_learning_can_break_an_equal_metric_tie() {
        let mut advisor = KonoMindAdvisor::default();

        for _ in 0..20 {
            advisor.observe(NetworkObservation {
                path: PathKind::Direct,
                success: false,
                rtt_ms: 250.0,
                packet_loss: 0.5,
            });
            advisor.observe(NetworkObservation {
                path: PathKind::Relay,
                success: true,
                rtt_ms: 40.0,
                packet_loss: 0.0,
            });
        }

        let recommendation = advisor
            .recommend(&[
                RouteCandidate {
                    path: PathKind::Direct,
                    metrics: neutral_metrics(),
                },
                RouteCandidate {
                    path: PathKind::Relay,
                    metrics: neutral_metrics(),
                },
            ])
            .expect("learned recommendation should be produced");

        assert_eq!(recommendation.path, PathKind::Relay);
        assert!(recommendation.score <= 1.0);
    }

    #[test]
    fn learning_isolated_between_path_kinds() {
        let mut advisor = KonoMindAdvisor::default();
        advisor.observe(NetworkObservation {
            path: PathKind::HolePunch,
            success: true,
            rtt_ms: 35.0,
            packet_loss: 0.01,
        });

        assert_eq!(advisor.path_learning(PathKind::HolePunch).samples, 1);
        assert_eq!(advisor.path_learning(PathKind::Direct).samples, 0);
        assert_eq!(advisor.path_learning(PathKind::Relay).samples, 0);
    }

    #[test]
    fn non_finite_observations_are_sanitized_fail_closed() {
        let mut advisor = KonoMindAdvisor::default();
        advisor.observe(NetworkObservation {
            path: PathKind::Relay,
            success: false,
            rtt_ms: f32::NAN,
            packet_loss: f32::INFINITY,
        });

        let learned = advisor.path_learning(PathKind::Relay);
        assert_eq!(learned.average_rtt_ms, MAX_OBSERVED_RTT_MS);
        assert_eq!(learned.average_packet_loss, 1.0);
        let recommendation = advisor
            .recommend(&[RouteCandidate {
                path: PathKind::Relay,
                metrics: PathMetrics {
                    rtt_ms: f32::NAN,
                    packet_loss: f32::NAN,
                    stability: f32::NAN,
                    relay_load: f32::NAN,
                },
            }])
            .unwrap();
        assert!(recommendation.score.is_finite());
        assert!((0.0..=1.0).contains(&recommendation.score));
    }

    #[test]
    fn metrics_are_bounded_before_scoring() {
        let metrics = PathMetrics {
            rtt_ms: -10.0,
            packet_loss: 4.0,
            stability: 2.0,
            relay_load: -1.0,
        }
        .sanitized();

        assert_eq!(metrics.rtt_ms, 0.0);
        assert_eq!(metrics.packet_loss, 1.0);
        assert_eq!(metrics.stability, 1.0);
        assert_eq!(metrics.relay_load, 0.0);
    }
}
