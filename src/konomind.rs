//! KonoMind is the optional adaptive decision layer for KonoNexus.
//!
//! In the current phase it deliberately uses a deterministic baseline scorer.
//! It does not control cryptography, authentication, replay protection, or
//! packet validation. Those remain hard protocol rules in KNP Core.
//!
//! Future versions may replace the baseline scorer with a locally trained
//! model once NAT traversal and cooperative relay produce enough real data.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    Direct,
    HolePunch,
    Relay,
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
            rtt_ms: self.rtt_ms.max(0.0),
            packet_loss: self.packet_loss.clamp(0.0, 1.0),
            stability: self.stability.clamp(0.0, 1.0),
            relay_load: self.relay_load.clamp(0.0, 1.0),
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

#[derive(Debug, Clone, Copy)]
pub struct RouteRecommendation {
    pub path: PathKind,
    pub score: f32,
}

#[derive(Debug, Default)]
pub struct KonoMindAdvisor {
    samples_seen: u64,
    successful_samples: u64,
}

impl KonoMindAdvisor {
    pub fn observe(&mut self, observation: NetworkObservation) {
        let _ = observation.path;
        let _ = observation.rtt_ms;
        let _ = observation.packet_loss;

        self.samples_seen = self.samples_seen.saturating_add(1);
        if observation.success {
            self.successful_samples = self.successful_samples.saturating_add(1);
        }
    }

    pub fn samples_seen(&self) -> u64 {
        self.samples_seen
    }

    pub fn success_rate(&self) -> f32 {
        if self.samples_seen == 0 {
            return 0.0;
        }

        self.successful_samples as f32 / self.samples_seen as f32
    }

    pub fn recommend(&self, candidates: &[RouteCandidate]) -> Option<RouteRecommendation> {
        candidates
            .iter()
            .map(|candidate| RouteRecommendation {
                path: candidate.path,
                score: baseline_score(candidate.metrics),
            })
            .max_by(|a, b| a.score.total_cmp(&b.score))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advisor_tracks_observations() {
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
    }

    #[test]
    fn advisor_prefers_healthier_path() {
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
