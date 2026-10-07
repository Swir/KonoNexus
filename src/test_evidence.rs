use crate::identity::node_id_from_public_key;
use crate::{
    FilterCellStatus, NatFilteringEvidence, NatMappingBehavior, NetworkDiagnostics, NodeIdentity,
    PathMethod,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

pub const WAN_TEST_REPORT_DOMAIN: &str = "kononexus/wan-test-evidence";
pub const WAN_TEST_REPORT_VERSION: u8 = 1;
pub const WAN_TEST_PAIR_DOMAIN: &str = "kononexus/wan-test-pair";
pub const WAN_TEST_PAIR_VERSION: u8 = 1;
pub const WAN_TEST_PAIR_MAX_SKEW_MS: u64 = 60 * 60 * 1_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WanPathEvidence {
    pub method: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WanNatEvidence {
    pub observed_external_endpoint: Option<String>,
    pub mapping: String,
    pub filtering: String,
    pub contacted_endpoint: String,
    pub same_address_different_port: String,
    pub different_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WanTestMetrics {
    pub sent: usize,
    pub delivered: usize,
    pub explicit_failed: usize,
    pub timed_out: usize,
    pub average_rtt_ms: f32,
    pub packet_loss_percent: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WanTestEvidence {
    pub domain: String,
    pub version: u8,
    pub generated_unix_ms: u64,
    pub tester_version: String,
    pub local_node_id: String,
    pub target_node_id: String,
    pub local_endpoint: String,
    pub path: Option<WanPathEvidence>,
    pub nat: WanNatEvidence,
    pub metrics: WanTestMetrics,
    pub delivery_passed: bool,
    pub eligible_for_wan_matrix: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedWanTestReport {
    pub evidence: WanTestEvidence,
    pub signer_public_key: String,
    pub signature: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WanTestScenario {
    SameLan,
    HomeNatPair,
    HomeToMobile,
    DualMobileCgnat,
    PublicIpv6,
    DirectInterruption,
    RestartReconnect,
}

impl fmt::Display for WanTestScenario {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SameLan => "same_lan",
            Self::HomeNatPair => "home_nat_pair",
            Self::HomeToMobile => "home_to_mobile",
            Self::DualMobileCgnat => "dual_mobile_cgnat",
            Self::PublicIpv6 => "public_ipv6",
            Self::DirectInterruption => "direct_interruption",
            Self::RestartReconnect => "restart_reconnect",
        })
    }
}

impl FromStr for WanTestScenario {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value.replace('-', "_").to_ascii_lowercase().as_str() {
            "same_lan" => Ok(Self::SameLan),
            "home_nat_pair" => Ok(Self::HomeNatPair),
            "home_to_mobile" => Ok(Self::HomeToMobile),
            "dual_mobile_cgnat" => Ok(Self::DualMobileCgnat),
            "public_ipv6" => Ok(Self::PublicIpv6),
            "direct_interruption" => Ok(Self::DirectInterruption),
            "restart_reconnect" => Ok(Self::RestartReconnect),
            _ => Err(format!(
                "unknown WAN scenario {value:?}; expected same_lan, home_nat_pair, home_to_mobile, dual_mobile_cgnat, public_ipv6, direct_interruption, or restart_reconnect"
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WanTestPairBundle {
    pub domain: String,
    pub version: u8,
    pub generated_unix_ms: u64,
    pub scenario: WanTestScenario,
    pub network_label: String,
    pub report_a_sha256: String,
    pub report_b_sha256: String,
    pub report_a: SignedWanTestReport,
    pub report_b: SignedWanTestReport,
    pub timestamp_skew_ms: u64,
    pub reciprocal_node_ids: bool,
    pub matrix_row_eligible: bool,
}

impl WanTestPairBundle {
    pub fn new(
        report_a: SignedWanTestReport,
        report_b: SignedWanTestReport,
        scenario: WanTestScenario,
        network_label: impl Into<String>,
    ) -> Result<Self> {
        let generated_unix_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("system clock is before Unix epoch")?
                .as_millis(),
        )
        .unwrap_or(u64::MAX);
        Self::at(
            report_a,
            report_b,
            scenario,
            network_label,
            generated_unix_ms,
        )
    }

    pub fn at(
        report_a: SignedWanTestReport,
        report_b: SignedWanTestReport,
        scenario: WanTestScenario,
        network_label: impl Into<String>,
        generated_unix_ms: u64,
    ) -> Result<Self> {
        report_a.verify()?;
        report_b.verify()?;
        let reciprocal_node_ids = reports_are_reciprocal(&report_a, &report_b);
        if !reciprocal_node_ids {
            bail!("WAN pair reports must name each other's local NodeID");
        }
        let timestamp_skew_ms = report_a
            .evidence
            .generated_unix_ms
            .abs_diff(report_b.evidence.generated_unix_ms);
        let matrix_row_eligible = report_a.evidence.eligible_for_wan_matrix
            && report_b.evidence.eligible_for_wan_matrix
            && timestamp_skew_ms <= WAN_TEST_PAIR_MAX_SKEW_MS;
        let bundle = Self {
            domain: WAN_TEST_PAIR_DOMAIN.to_owned(),
            version: WAN_TEST_PAIR_VERSION,
            generated_unix_ms,
            scenario,
            network_label: network_label.into(),
            report_a_sha256: report_sha256(&report_a)?,
            report_b_sha256: report_sha256(&report_b)?,
            report_a,
            report_b,
            timestamp_skew_ms,
            reciprocal_node_ids,
            matrix_row_eligible,
        };
        bundle.verify()?;
        Ok(bundle)
    }

    pub fn verify(&self) -> Result<()> {
        if self.domain != WAN_TEST_PAIR_DOMAIN || self.version != WAN_TEST_PAIR_VERSION {
            bail!("unsupported WAN test pair schema");
        }
        validate_network_label(&self.network_label)?;
        self.report_a.verify().context("invalid pair report A")?;
        self.report_b.verify().context("invalid pair report B")?;
        if !reports_are_reciprocal(&self.report_a, &self.report_b) || !self.reciprocal_node_ids {
            bail!("WAN pair reports do not contain reciprocal NodeIDs");
        }
        if self.report_a_sha256 != report_sha256(&self.report_a)?
            || self.report_b_sha256 != report_sha256(&self.report_b)?
        {
            bail!("WAN pair report digest mismatch");
        }
        let expected_skew = self
            .report_a
            .evidence
            .generated_unix_ms
            .abs_diff(self.report_b.evidence.generated_unix_ms);
        if self.timestamp_skew_ms != expected_skew {
            bail!("WAN pair timestamp skew mismatch");
        }
        let expected_eligibility = self.report_a.evidence.eligible_for_wan_matrix
            && self.report_b.evidence.eligible_for_wan_matrix
            && expected_skew <= WAN_TEST_PAIR_MAX_SKEW_MS;
        if self.matrix_row_eligible != expected_eligibility {
            bail!("WAN pair matrix eligibility mismatch");
        }
        Ok(())
    }

    pub fn to_pretty_json(&self) -> Result<String> {
        self.verify()?;
        serde_json::to_string_pretty(self).context("failed to encode WAN test pair")
    }

    pub fn from_json_verified(encoded: &str) -> Result<Self> {
        let bundle: Self =
            serde_json::from_str(encoded).context("failed to decode WAN test pair")?;
        bundle.verify()?;
        Ok(bundle)
    }

    pub fn write_atomic(&self, path: &Path) -> Result<()> {
        self.verify()?;
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let file_name = path
            .file_name()
            .context("WAN pair output must include a file name")?
            .to_string_lossy();
        let temporary_path = path.with_file_name(format!(".{file_name}.tmp"));
        fs::write(&temporary_path, self.to_pretty_json()?)
            .with_context(|| format!("failed to write {}", temporary_path.display()))?;
        fs::rename(&temporary_path, path)
            .with_context(|| format!("failed to publish {}", path.display()))
    }

    pub fn read_verified(path: &Path) -> Result<Self> {
        let encoded = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        Self::from_json_verified(&encoded)
    }
}

impl SignedWanTestReport {
    #[allow(clippy::too_many_arguments)]
    pub fn from_runtime(
        identity: &NodeIdentity,
        target_node_id: &str,
        snapshot: &NetworkDiagnostics,
        sent: usize,
        delivered: usize,
        explicit_failed: usize,
        average_rtt_ms: f32,
        tester_version: &str,
    ) -> Result<Self> {
        let generated_unix_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("system clock is before Unix epoch")?
                .as_millis(),
        )
        .unwrap_or(u64::MAX);
        Self::signed_at(
            identity,
            target_node_id,
            snapshot,
            sent,
            delivered,
            explicit_failed,
            average_rtt_ms,
            tester_version,
            generated_unix_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn signed_at(
        identity: &NodeIdentity,
        target_node_id: &str,
        snapshot: &NetworkDiagnostics,
        sent: usize,
        delivered: usize,
        explicit_failed: usize,
        average_rtt_ms: f32,
        tester_version: &str,
        generated_unix_ms: u64,
    ) -> Result<Self> {
        if !average_rtt_ms.is_finite() || average_rtt_ms < 0.0 {
            bail!("average RTT must be finite and non-negative");
        }
        if delivered > sent || explicit_failed > sent.saturating_sub(delivered) {
            bail!("invalid delivery counters");
        }

        let timed_out = sent.saturating_sub(delivered + explicit_failed);
        let packet_loss_percent = if sent == 0 {
            100.0
        } else {
            100.0 * sent.saturating_sub(delivered) as f32 / sent as f32
        };
        let path = snapshot
            .active_paths
            .iter()
            .find(|path| path.peer_node_id == target_node_id)
            .map(|path| WanPathEvidence {
                method: path_method_code(path.method).to_owned(),
                endpoint: path.endpoint.to_string(),
            });
        let delivery_passed = delivered > 0;
        let eligible_for_wan_matrix =
            delivery_passed && snapshot.observed_external_endpoint.is_some() && path.is_some();

        let evidence = WanTestEvidence {
            domain: WAN_TEST_REPORT_DOMAIN.to_owned(),
            version: WAN_TEST_REPORT_VERSION,
            generated_unix_ms,
            tester_version: tester_version.to_owned(),
            local_node_id: identity.node_id(),
            target_node_id: target_node_id.to_owned(),
            local_endpoint: snapshot.local_addr.to_string(),
            path,
            nat: WanNatEvidence {
                observed_external_endpoint: snapshot
                    .observed_external_endpoint
                    .map(|endpoint| endpoint.to_string()),
                mapping: nat_mapping_code(snapshot.nat_behavior).to_owned(),
                filtering: nat_filtering_code(snapshot.filtering_evidence).to_owned(),
                contacted_endpoint: filter_cell_code(snapshot.filtering_matrix.contacted_endpoint)
                    .to_owned(),
                same_address_different_port: filter_cell_code(
                    snapshot.filtering_matrix.same_address_different_port,
                )
                .to_owned(),
                different_address: filter_cell_code(snapshot.filtering_matrix.different_address)
                    .to_owned(),
            },
            metrics: WanTestMetrics {
                sent,
                delivered,
                explicit_failed,
                timed_out,
                average_rtt_ms,
                packet_loss_percent,
            },
            delivery_passed,
            eligible_for_wan_matrix,
        };
        let payload = serde_json::to_vec(&evidence)?;
        let report = Self {
            evidence,
            signer_public_key: identity.public_key_hex(),
            signature: hex::encode(identity.sign(&payload)),
        };
        report.verify()?;
        Ok(report)
    }

    pub fn verify(&self) -> Result<()> {
        self.validate_evidence()?;

        let public_key_raw =
            hex::decode(&self.signer_public_key).context("report public key is not valid hex")?;
        let public_key: [u8; 32] = public_key_raw
            .try_into()
            .map_err(|_| anyhow::anyhow!("report public key must contain 32 bytes"))?;
        if node_id_from_public_key(&public_key) != self.evidence.local_node_id {
            bail!("report signer does not match local NodeID");
        }

        let signature_raw =
            hex::decode(&self.signature).context("report signature is not valid hex")?;
        let signature: [u8; 64] = signature_raw
            .try_into()
            .map_err(|_| anyhow::anyhow!("report signature must contain 64 bytes"))?;
        let payload = serde_json::to_vec(&self.evidence)?;
        NodeIdentity::verify_with_public_key(&public_key, &payload, &signature)
            .context("WAN test report signature verification failed")
    }

    pub fn to_pretty_json(&self) -> Result<String> {
        self.verify()?;
        serde_json::to_string_pretty(self).context("failed to encode WAN test report")
    }

    pub fn from_json_verified(encoded: &str) -> Result<Self> {
        let report: Self =
            serde_json::from_str(encoded).context("failed to decode WAN test report")?;
        report.verify()?;
        Ok(report)
    }

    pub fn write_atomic(&self, directory: &Path) -> Result<PathBuf> {
        self.verify()?;
        fs::create_dir_all(directory)
            .with_context(|| format!("failed to create {}", directory.display()))?;
        let target_hint: String = self
            .evidence
            .target_node_id
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .take(16)
            .collect();
        let file_name = format!(
            "KonoNexus-WAN-{}-{}.json",
            self.evidence.generated_unix_ms, target_hint
        );
        let final_path = directory.join(&file_name);
        let temporary_path = directory.join(format!(".{file_name}.tmp"));
        fs::write(&temporary_path, self.to_pretty_json()?)
            .with_context(|| format!("failed to write {}", temporary_path.display()))?;
        fs::rename(&temporary_path, &final_path)
            .with_context(|| format!("failed to publish {}", final_path.display()))?;
        Ok(final_path)
    }

    pub fn read_verified(path: &Path) -> Result<Self> {
        let encoded = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        Self::from_json_verified(&encoded)
    }

    fn validate_evidence(&self) -> Result<()> {
        let evidence = &self.evidence;
        if evidence.domain != WAN_TEST_REPORT_DOMAIN || evidence.version != WAN_TEST_REPORT_VERSION
        {
            bail!("unsupported WAN test report schema");
        }
        validate_node_id(&evidence.local_node_id)?;
        validate_node_id(&evidence.target_node_id)?;
        if evidence.local_node_id == evidence.target_node_id {
            bail!("report target must differ from local NodeID");
        }
        evidence
            .local_endpoint
            .parse::<SocketAddr>()
            .context("invalid local endpoint in report")?;
        if let Some(endpoint) = &evidence.nat.observed_external_endpoint {
            endpoint
                .parse::<SocketAddr>()
                .context("invalid observed external endpoint in report")?;
        }
        if let Some(path) = &evidence.path {
            path.endpoint
                .parse::<SocketAddr>()
                .context("invalid selected path endpoint in report")?;
            if !matches!(path.method.as_str(), "direct" | "hole_punch" | "relay") {
                bail!("invalid selected path method in report");
            }
        }

        let metrics = &evidence.metrics;
        if metrics.delivered + metrics.explicit_failed + metrics.timed_out != metrics.sent {
            bail!("WAN test counters do not balance");
        }
        if !metrics.average_rtt_ms.is_finite() || metrics.average_rtt_ms < 0.0 {
            bail!("WAN test RTT is invalid");
        }
        if !metrics.packet_loss_percent.is_finite()
            || !(0.0..=100.0).contains(&metrics.packet_loss_percent)
        {
            bail!("WAN test packet loss is invalid");
        }
        let expected_loss = if metrics.sent == 0 {
            100.0
        } else {
            100.0 * metrics.sent.saturating_sub(metrics.delivered) as f32 / metrics.sent as f32
        };
        if (metrics.packet_loss_percent - expected_loss).abs() > 0.01 {
            bail!("WAN test packet loss does not match counters");
        }

        let expected_pass = metrics.delivered > 0;
        if evidence.delivery_passed != expected_pass {
            bail!("WAN test delivery verdict does not match counters");
        }
        let expected_eligibility = expected_pass
            && evidence.nat.observed_external_endpoint.is_some()
            && evidence.path.is_some();
        if evidence.eligible_for_wan_matrix != expected_eligibility {
            bail!("WAN matrix eligibility does not match evidence");
        }
        Ok(())
    }
}

fn reports_are_reciprocal(a: &SignedWanTestReport, b: &SignedWanTestReport) -> bool {
    a.evidence.local_node_id != b.evidence.local_node_id
        && a.evidence.local_node_id == b.evidence.target_node_id
        && a.evidence.target_node_id == b.evidence.local_node_id
}

fn report_sha256(report: &SignedWanTestReport) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(report)?)))
}

fn validate_network_label(label: &str) -> Result<()> {
    if label.trim().is_empty() || label.len() > 128 || label.chars().any(char::is_control) {
        bail!("network label must contain 1-128 printable bytes");
    }
    Ok(())
}

fn validate_node_id(node_id: &str) -> Result<()> {
    let Some(encoded) = node_id.strip_prefix("knp1") else {
        bail!("invalid KNP NodeID prefix");
    };
    let raw = hex::decode(encoded).context("invalid KNP NodeID encoding")?;
    if raw.len() != 20 {
        bail!("invalid KNP NodeID length");
    }
    Ok(())
}

fn path_method_code(method: PathMethod) -> &'static str {
    match method {
        PathMethod::Direct => "direct",
        PathMethod::HolePunch => "hole_punch",
        PathMethod::Relay => "relay",
    }
}

fn nat_mapping_code(behavior: NatMappingBehavior) -> &'static str {
    match behavior {
        NatMappingBehavior::Unknown => "unknown",
        NatMappingBehavior::SingleObservation => "single_observation",
        NatMappingBehavior::StableEndpoint => "stable_endpoint",
        NatMappingBehavior::PortVariant => "port_variant",
        NatMappingBehavior::AddressVariant => "address_variant",
    }
}

fn nat_filtering_code(evidence: NatFilteringEvidence) -> &'static str {
    match evidence {
        NatFilteringEvidence::Unknown => "unknown",
        NatFilteringEvidence::Inconclusive => "inconclusive",
        NatFilteringEvidence::ContactedEndpointObserved => "contacted_endpoint_observed",
        NatFilteringEvidence::SameAddressDifferentPortObserved => {
            "same_address_different_port_observed"
        }
        NatFilteringEvidence::EndpointIndependentObserved => "endpoint_independent_observed",
        NatFilteringEvidence::EndpointIndependentRepeated => "endpoint_independent_repeated",
    }
}

fn filter_cell_code(status: FilterCellStatus) -> &'static str {
    match status {
        FilterCellStatus::Unknown => "unknown",
        FilterCellStatus::Observed => "observed",
        FilterCellStatus::InconclusiveTimedOut => "inconclusive_timed_out",
        FilterCellStatus::InconclusiveControlCorrelatedTimeout => {
            "inconclusive_control_correlated_timeout"
        }
        FilterCellStatus::InconclusiveUnavailable => "inconclusive_unavailable",
        FilterCellStatus::InconclusiveSendFailed => "inconclusive_send_failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FilterMatrixSnapshot, PathDiagnostic};

    fn snapshot(peer_node_id: String, external: Option<SocketAddr>) -> NetworkDiagnostics {
        NetworkDiagnostics {
            local_addr: "0.0.0.0:47000".parse().unwrap(),
            observed_external_endpoint: external,
            nat_behavior: NatMappingBehavior::StableEndpoint,
            filtering_evidence: NatFilteringEvidence::ContactedEndpointObserved,
            filtering_matrix: FilterMatrixSnapshot {
                target_endpoint: external,
                contacted_endpoint: FilterCellStatus::Observed,
                same_address_different_port: FilterCellStatus::InconclusiveTimedOut,
                different_address: FilterCellStatus::InconclusiveUnavailable,
            },
            authenticated_peers: 1,
            dht_records: 1,
            active_paths: vec![PathDiagnostic {
                peer_node_id,
                method: PathMethod::HolePunch,
                endpoint: "198.51.100.20:47000".parse().unwrap(),
            }],
            pending_punches: 0,
        }
    }

    fn reciprocal_reports(
        generated_a: u64,
        generated_b: u64,
    ) -> (SignedWanTestReport, SignedWanTestReport) {
        let identity_a = NodeIdentity::generate();
        let identity_b = NodeIdentity::generate();
        let node_a = identity_a.node_id();
        let node_b = identity_b.node_id();
        let report_a = SignedWanTestReport::signed_at(
            &identity_a,
            &node_b,
            &snapshot(node_b.clone(), Some("203.0.113.10:47000".parse().unwrap())),
            10,
            9,
            1,
            42.5,
            "test",
            generated_a,
        )
        .unwrap();
        let report_b = SignedWanTestReport::signed_at(
            &identity_b,
            &node_a,
            &snapshot(node_a.clone(), Some("198.51.100.20:47000".parse().unwrap())),
            10,
            10,
            0,
            38.0,
            "test",
            generated_b,
        )
        .unwrap();
        (report_a, report_b)
    }

    #[test]
    fn signed_wan_report_round_trips_and_is_matrix_eligible() {
        let identity = NodeIdentity::generate();
        let target = NodeIdentity::generate().node_id();
        let report = SignedWanTestReport::signed_at(
            &identity,
            &target,
            &snapshot(target.clone(), Some("203.0.113.10:47000".parse().unwrap())),
            10,
            9,
            1,
            42.5,
            "test",
            123,
        )
        .unwrap();

        assert!(report.evidence.delivery_passed);
        assert!(report.evidence.eligible_for_wan_matrix);
        assert_eq!(report.evidence.metrics.timed_out, 0);
        let encoded = report.to_pretty_json().unwrap();
        assert_eq!(
            SignedWanTestReport::from_json_verified(&encoded).unwrap(),
            report
        );
    }

    #[test]
    fn tampered_wan_report_is_rejected() {
        let identity = NodeIdentity::generate();
        let target = NodeIdentity::generate().node_id();
        let mut report = SignedWanTestReport::signed_at(
            &identity,
            &target,
            &snapshot(target.clone(), Some("203.0.113.10:47000".parse().unwrap())),
            10,
            8,
            1,
            30.0,
            "test",
            456,
        )
        .unwrap();

        report.evidence.metrics.average_rtt_ms = 1.0;
        assert!(report.verify().is_err());
    }

    #[test]
    fn local_delivery_does_not_claim_wan_matrix_evidence() {
        let identity = NodeIdentity::generate();
        let target = NodeIdentity::generate().node_id();
        let report = SignedWanTestReport::signed_at(
            &identity,
            &target,
            &snapshot(target.clone(), None),
            10,
            10,
            0,
            2.0,
            "test",
            789,
        )
        .unwrap();

        assert!(report.evidence.delivery_passed);
        assert!(!report.evidence.eligible_for_wan_matrix);
    }

    #[test]
    fn reciprocal_wan_pair_round_trips_and_is_matrix_row_eligible() {
        let (report_a, report_b) = reciprocal_reports(1_000, 2_000);
        let bundle = WanTestPairBundle::at(
            report_a,
            report_b,
            WanTestScenario::HomeNatPair,
            "ISP A / ISP B",
            3_000,
        )
        .unwrap();

        assert!(bundle.reciprocal_node_ids);
        assert!(bundle.matrix_row_eligible);
        assert_eq!(bundle.timestamp_skew_ms, 1_000);
        assert_eq!(bundle.report_a_sha256.len(), 64);
        let encoded = bundle.to_pretty_json().unwrap();
        assert_eq!(
            WanTestPairBundle::from_json_verified(&encoded).unwrap(),
            bundle
        );
    }

    #[test]
    fn wan_pair_rejects_nonreciprocal_reports() {
        let (report_a, _) = reciprocal_reports(1_000, 2_000);
        let unrelated_identity = NodeIdentity::generate();
        let unrelated_target = NodeIdentity::generate().node_id();
        let unrelated = SignedWanTestReport::signed_at(
            &unrelated_identity,
            &unrelated_target,
            &snapshot(
                unrelated_target.clone(),
                Some("192.0.2.40:47000".parse().unwrap()),
            ),
            10,
            10,
            0,
            20.0,
            "test",
            2_000,
        )
        .unwrap();

        assert!(WanTestPairBundle::at(
            report_a,
            unrelated,
            WanTestScenario::HomeToMobile,
            "home/mobile",
            3_000,
        )
        .is_err());
    }

    #[test]
    fn wan_pair_rejects_tampered_embedded_report_or_digest() {
        let (report_a, report_b) = reciprocal_reports(1_000, 2_000);
        let mut bundle = WanTestPairBundle::at(
            report_a,
            report_b,
            WanTestScenario::PublicIpv6,
            "native IPv6",
            3_000,
        )
        .unwrap();

        bundle.report_a.evidence.metrics.average_rtt_ms = 0.5;
        assert!(bundle.verify().is_err());

        let (report_a, report_b) = reciprocal_reports(1_000, 2_000);
        let mut bundle = WanTestPairBundle::at(
            report_a,
            report_b,
            WanTestScenario::PublicIpv6,
            "native IPv6",
            3_000,
        )
        .unwrap();
        bundle.report_b_sha256 = "00".to_owned();
        assert!(bundle.verify().is_err());
    }

    #[test]
    fn excessive_pair_skew_is_valid_but_not_matrix_row_eligible() {
        let (report_a, report_b) = reciprocal_reports(1_000, 1_000 + WAN_TEST_PAIR_MAX_SKEW_MS + 1);
        let bundle = WanTestPairBundle::at(
            report_a,
            report_b,
            WanTestScenario::DualMobileCgnat,
            "two carriers",
            5_000,
        )
        .unwrap();

        bundle.verify().unwrap();
        assert!(!bundle.matrix_row_eligible);
    }
}
