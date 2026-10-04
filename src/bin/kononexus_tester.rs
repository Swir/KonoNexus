#![cfg_attr(windows, windows_subsystem = "windows")]

use anyhow::{Context, Result};
use eframe::egui::{self, Color32, FontFamily, FontId, RichText, Stroke, Vec2};
use kononexus::{
    FilterCellStatus, InviteCode, KonofixSdkConfig, KonofixTransport, NatFilteringEvidence,
    NatMappingBehavior, NetworkDiagnostics, NodeIdentity, PathMethod, RelayAppEvent,
};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};
use tokio::sync::mpsc as tokio_mpsc;
use tokio::time;

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const TEST_SAMPLE_COUNT: usize = 10;
const TEST_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug)]
enum Command {
    Connect(InviteCode),
    StartTest,
}

#[derive(Debug)]
enum WorkerEvent {
    Ready { node_id: String, invite: String },
    InviteUpdated(String),
    Target(String),
    Snapshot(NetworkDiagnostics),
    TestStarted,
    TestProgress { delivered: usize, sent: usize },
    TestFinished { rtt_ms: f32, packet_loss: f32 },
    Log(String),
    Error(String),
}

struct ActiveTest {
    target: String,
    started: Instant,
    next_send: Instant,
    sent: usize,
    delivered: usize,
    failed: usize,
    pending: HashMap<u64, Instant>,
    rtts: Vec<f32>,
}

impl ActiveTest {
    fn new(target: String) -> Self {
        let now = Instant::now();
        Self {
            target,
            started: now,
            next_send: now,
            sent: 0,
            delivered: 0,
            failed: 0,
            pending: HashMap::new(),
            rtts: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UiStatus {
    Starting,
    Waiting,
    Connecting,
    Testing,
    Connected,
    Failed,
}

struct TesterApp {
    command_tx: tokio_mpsc::UnboundedSender<Command>,
    event_rx: Receiver<WorkerEvent>,
    clipboard: Option<arboard::Clipboard>,
    status: UiStatus,
    node_id: String,
    target_node_id: Option<String>,
    invite: String,
    invite_input: String,
    snapshot: Option<NetworkDiagnostics>,
    rtt_ms: Option<f32>,
    packet_loss: Option<f32>,
    progress: (usize, usize),
    logs: Vec<String>,
    error: Option<String>,
}

impl TesterApp {
    fn new(
        cc: &eframe::CreationContext<'_>,
        command_tx: tokio_mpsc::UnboundedSender<Command>,
        event_rx: Receiver<WorkerEvent>,
    ) -> Self {
        configure_style(&cc.egui_ctx);
        Self {
            command_tx,
            event_rx,
            clipboard: arboard::Clipboard::new().ok(),
            status: UiStatus::Starting,
            node_id: String::new(),
            target_node_id: None,
            invite: String::new(),
            invite_input: String::new(),
            snapshot: None,
            rtt_ms: None,
            packet_loss: None,
            progress: (0, TEST_SAMPLE_COUNT),
            logs: Vec::new(),
            error: None,
        }
    }

    fn poll_events(&mut self) {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                WorkerEvent::Ready { node_id, invite } => {
                    self.node_id = node_id;
                    self.invite = invite;
                    self.status = UiStatus::Waiting;
                    self.push_log("Runtime KNP uruchomiony; oczekiwanie na drugi komputer.");
                }
                WorkerEvent::InviteUpdated(invite) => {
                    self.invite = invite;
                    self.push_log("Kod invite odświeżony o nowy endpoint evidence.");
                }
                WorkerEvent::Target(node_id) => {
                    self.target_node_id = Some(node_id);
                }
                WorkerEvent::Snapshot(snapshot) => {
                    if self.target_node_id.is_none() {
                        if let Some(path) = snapshot.active_paths.first() {
                            self.target_node_id = Some(path.peer_node_id.clone());
                        }
                    }
                    self.snapshot = Some(snapshot);
                }
                WorkerEvent::TestStarted => {
                    self.status = UiStatus::Testing;
                    self.progress = (0, TEST_SAMPLE_COUNT);
                    self.rtt_ms = None;
                    self.packet_loss = None;
                    self.error = None;
                    self.push_log("Rozpoczęto serię 10 szyfrowanych próbek z potwierdzeniami.");
                }
                WorkerEvent::TestProgress { delivered, sent } => {
                    self.progress = (delivered, sent);
                }
                WorkerEvent::TestFinished {
                    rtt_ms,
                    packet_loss,
                } => {
                    self.rtt_ms = Some(rtt_ms);
                    self.packet_loss = Some(packet_loss);
                    if packet_loss < 100.0 {
                        self.status = UiStatus::Connected;
                        self.push_log(format!(
                            "Test zakończony: RTT {:.1} ms, utrata {:.0}%.",
                            rtt_ms, packet_loss
                        ));
                    } else {
                        self.status = UiStatus::Failed;
                        self.error = Some("Brak potwierdzonej dostawy w czasie testu.".into());
                    }
                }
                WorkerEvent::Log(message) => self.push_log(message),
                WorkerEvent::Error(message) => {
                    self.status = UiStatus::Failed;
                    self.error = Some(message.clone());
                    self.push_log(format!("BŁĄD: {message}"));
                }
            }
        }
    }

    fn push_log(&mut self, message: impl Into<String>) {
        self.logs
            .push(format!("[{:02}] {}", self.logs.len() + 1, message.into()));
        if self.logs.len() > 300 {
            self.logs.drain(..50);
        }
    }

    fn paste_and_connect(&mut self) {
        if let Some(clipboard) = self.clipboard.as_mut() {
            match clipboard.get_text() {
                Ok(text) => self.invite_input = text,
                Err(error) => {
                    self.error = Some(format!("Nie można odczytać schowka: {error}"));
                    return;
                }
            }
        }
        match InviteCode::decode(&self.invite_input) {
            Ok(invite) => {
                self.target_node_id = Some(invite.node_id.clone());
                self.status = UiStatus::Connecting;
                self.error = None;
                let _ = self.command_tx.send(Command::Connect(invite));
            }
            Err(error) => {
                self.status = UiStatus::Failed;
                self.error = Some(format!("Nieprawidłowy invite: {error:#}"));
            }
        }
    }

    fn copy_invite(&mut self, ctx: &egui::Context) {
        ctx.copy_text(self.invite.clone());
        if let Some(clipboard) = self.clipboard.as_mut() {
            let _ = clipboard.set_text(self.invite.clone());
        }
        self.push_log("Invite skopiowany do schowka.");
    }

    fn start_test(&mut self) {
        if self.target_node_id.is_some() {
            self.status = UiStatus::Testing;
            let _ = self.command_tx.send(Command::StartTest);
        } else {
            self.error = Some(
                "Najpierw wklej invite z drugiego komputera albo poczekaj na połączenie.".into(),
            );
        }
    }

    fn path_label(&self) -> (&'static str, Color32) {
        let target = self.target_node_id.as_deref();
        let method = self.snapshot.as_ref().and_then(|snapshot| {
            snapshot
                .active_paths
                .iter()
                .find(|path| target.is_none() || Some(path.peer_node_id.as_str()) == target)
                .map(|path| path.method)
        });
        match method {
            Some(PathMethod::Direct) => ("DIRECT", Color32::from_rgb(68, 211, 155)),
            Some(PathMethod::HolePunch) => ("UDP HOLE PUNCH", Color32::from_rgb(67, 187, 255)),
            Some(PathMethod::Relay) => ("RELAY", Color32::from_rgb(180, 125, 255)),
            None => ("SZUKANIE ŚCIEŻKI", Color32::from_rgb(139, 153, 181)),
        }
    }

    fn has_wan_evidence(&self) -> bool {
        self.snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.observed_external_endpoint)
            .is_some()
    }
}

impl eframe::App for TesterApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_events();
        ctx.request_repaint_after(Duration::from_millis(100));

        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(Color32::from_rgb(8, 13, 27))
                    .inner_margin(24.0),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new("KONONEXUS")
                                .size(12.0)
                                .color(Color32::from_rgb(83, 215, 255))
                                .strong(),
                        );
                        ui.label(
                            RichText::new("Network Tester")
                                .size(28.0)
                                .color(Color32::WHITE)
                                .strong(),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new(format!("{APP_VERSION}  •  Windows x64  •  UDP 47000"))
                                .size(11.0)
                                .color(Color32::from_rgb(122, 139, 171)),
                        );
                    });
                });
                ui.add_space(18.0);

                status_card(ui, self);
                ui.add_space(14.0);

                ui.columns(2, |columns| {
                    invite_creator(&mut columns[0], self, ctx);
                    invite_joiner(&mut columns[1], self);
                });
                ui.add_space(14.0);

                metrics_row(ui, self);
                ui.add_space(14.0);

                ui.horizontal(|ui| {
                    let enabled = self.target_node_id.is_some() && self.status != UiStatus::Testing;
                    let button =
                        egui::Button::new(RichText::new("▶  START TESTU WAN").size(16.0).strong())
                            .fill(Color32::from_rgb(21, 132, 225))
                            .stroke(Stroke::new(1.0_f32, Color32::from_rgb(89, 207, 255)))
                            .min_size(Vec2::new(230.0, 46.0));
                    if ui.add_enabled(enabled, button).clicked() {
                        self.start_test();
                    }
                    if self.status == UiStatus::Testing {
                        ui.add(
                            egui::ProgressBar::new(
                                self.progress.0 as f32 / TEST_SAMPLE_COUNT as f32,
                            )
                            .text(format!(
                                "Potwierdzone: {} / {}",
                                self.progress.0, self.progress.1
                            ))
                            .desired_width(280.0),
                        );
                    }
                });

                if let Some(error) = &self.error {
                    ui.add_space(10.0);
                    ui.label(
                        RichText::new(error)
                            .color(Color32::from_rgb(255, 118, 133))
                            .strong(),
                    );
                }

                ui.add_space(8.0);
                egui::CollapsingHeader::new(
                    RichText::new("Szczegóły techniczne i log")
                        .color(Color32::from_rgb(167, 185, 216)),
                )
                .default_open(false)
                .show(ui, |ui| {
                    technical_details(ui, self);
                    ui.separator();
                    egui::ScrollArea::vertical()
                        .max_height(150.0)
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            for line in &self.logs {
                                ui.label(
                                    RichText::new(line)
                                        .monospace()
                                        .size(11.0)
                                        .color(Color32::from_rgb(150, 169, 202)),
                                );
                            }
                        });
                });
            });
    }
}

fn status_card(ui: &mut egui::Ui, app: &TesterApp) {
    let (title, subtitle, color) = match app.status {
        UiStatus::Starting => (
            "URUCHAMIANIE…",
            "Inicjalizacja bezpiecznej tożsamości i UDP",
            Color32::from_rgb(113, 151, 220),
        ),
        UiStatus::Waiting => (
            "GOTOWY",
            "Skopiuj invite na drugi komputer albo wklej otrzymany kod",
            Color32::from_rgb(69, 193, 255),
        ),
        UiStatus::Connecting => (
            "ŁĄCZENIE…",
            "DIRECT → UDP HOLE PUNCH → RELAY",
            Color32::from_rgb(83, 174, 255),
        ),
        UiStatus::Testing => (
            "TESTOWANIE…",
            "Szyfrowane próbki i potwierdzenia dostawy",
            Color32::from_rgb(83, 174, 255),
        ),
        UiStatus::Connected => (
            "CONNECTED  ✓",
            "KNP potwierdził dostawę end-to-end",
            Color32::from_rgb(68, 211, 155),
        ),
        UiStatus::Failed => (
            "FAILED  ✕",
            "Sprawdź szczegóły techniczne poniżej",
            Color32::from_rgb(255, 101, 122),
        ),
    };
    egui::Frame::new()
        .fill(Color32::from_rgb(15, 25, 47))
        .stroke(Stroke::new(1.0_f32, color.gamma_multiply(0.65)))
        .corner_radius(14.0)
        .inner_margin(18.0)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(RichText::new(title).size(30.0).color(color).strong());
                    ui.label(
                        RichText::new(subtitle)
                            .size(13.0)
                            .color(Color32::from_rgb(171, 188, 218)),
                    );
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let (path, path_color) = app.path_label();
                    ui.label(RichText::new(path).size(15.0).color(path_color).strong());
                });
            });
        });
}

fn invite_creator(ui: &mut egui::Ui, app: &mut TesterApp, ctx: &egui::Context) {
    card(ui, |ui| {
        ui.label(
            RichText::new("PC A — UTWÓRZ INVITE")
                .strong()
                .color(Color32::from_rgb(92, 211, 255)),
        );
        ui.add_space(8.0);
        ui.add(
            egui::TextEdit::multiline(&mut app.invite)
                .desired_rows(3)
                .font(egui::TextStyle::Monospace)
                .interactive(false),
        );
        ui.add_space(8.0);
        if ui.button("Kopiuj invite").clicked() {
            app.copy_invite(ctx);
        }
        let (text, color) = if app.has_wan_evidence() {
            (
                "Publiczny endpoint potwierdzony przez peer evidence.",
                Color32::from_rgb(68, 211, 155),
            )
        } else {
            ("Brak publicznego endpoint evidence — kod zawiera bieżący adres lokalny. WAN wymaga osiągalnego peera/bootstrapu.", Color32::from_rgb(241, 181, 72))
        };
        ui.add_space(6.0);
        ui.label(RichText::new(text).size(10.5).color(color));
    });
}

fn invite_joiner(ui: &mut egui::Ui, app: &mut TesterApp) {
    card(ui, |ui| {
        ui.label(
            RichText::new("PC B — DOŁĄCZ I TESTUJ")
                .strong()
                .color(Color32::from_rgb(177, 132, 255)),
        );
        ui.add_space(8.0);
        ui.add(
            egui::TextEdit::multiline(&mut app.invite_input)
                .desired_rows(3)
                .hint_text("Wklej kod KNX1…")
                .font(egui::TextStyle::Monospace),
        );
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui.button("Wklej invite").clicked() {
                app.paste_and_connect();
            }
            if ui.button("Połącz").clicked() {
                app.paste_and_connect();
            }
        });
        ui.add_space(6.0);
        ui.label(
            RichText::new("Kod jest podpisany Ed25519 i nie zawiera klucza prywatnego.")
                .size(10.5)
                .color(Color32::from_rgb(139, 156, 187)),
        );
    });
}

fn metrics_row(ui: &mut egui::Ui, app: &TesterApp) {
    ui.columns(4, |columns| {
        metric(
            &mut columns[0],
            "RTT / ping",
            app.rtt_ms
                .map(|v| format!("{v:.1} ms"))
                .unwrap_or_else(|| "—".into()),
        );
        metric(
            &mut columns[1],
            "Packet loss",
            app.packet_loss
                .map(|v| format!("{v:.0}%"))
                .unwrap_or_else(|| "—".into()),
        );
        let nat = app
            .snapshot
            .as_ref()
            .map(|s| nat_label(s.nat_behavior))
            .unwrap_or("—");
        metric(&mut columns[2], "NAT evidence", nat.to_owned());
        let (path, _) = app.path_label();
        metric(&mut columns[3], "Wybrana ścieżka", path.to_owned());
    });
}

fn metric(ui: &mut egui::Ui, label: &str, value: String) {
    egui::Frame::new()
        .fill(Color32::from_rgb(13, 22, 42))
        .corner_radius(10.0)
        .inner_margin(12.0)
        .show(ui, |ui| {
            ui.label(
                RichText::new(label)
                    .size(10.5)
                    .color(Color32::from_rgb(125, 144, 176)),
            );
            ui.label(
                RichText::new(value)
                    .size(17.0)
                    .color(Color32::WHITE)
                    .strong(),
            );
        });
}

fn technical_details(ui: &mut egui::Ui, app: &TesterApp) {
    egui::Grid::new("technical-grid")
        .striped(true)
        .show(ui, |ui| {
            detail(
                ui,
                "NodeID",
                if app.node_id.is_empty() {
                    "—"
                } else {
                    &app.node_id
                },
            );
            detail(
                ui,
                "Target NodeID",
                app.target_node_id.as_deref().unwrap_or("—"),
            );
            if let Some(snapshot) = &app.snapshot {
                detail(ui, "Local UDP", &snapshot.local_addr.to_string());
                detail(
                    ui,
                    "Endpoint evidence",
                    &snapshot
                        .observed_external_endpoint
                        .map(|e| e.to_string())
                        .unwrap_or_else(|| "brak".into()),
                );
                detail(ui, "NAT mapping", nat_label(snapshot.nat_behavior));
                detail(
                    ui,
                    "NAT filtering",
                    filtering_label(snapshot.filtering_evidence),
                );
                detail(
                    ui,
                    "Filter: contacted endpoint",
                    filter_cell_label(snapshot.filtering_matrix.contacted_endpoint),
                );
                detail(
                    ui,
                    "Filter: same address, different port",
                    filter_cell_label(snapshot.filtering_matrix.same_address_different_port),
                );
                detail(
                    ui,
                    "Filter: different address",
                    filter_cell_label(snapshot.filtering_matrix.different_address),
                );
                detail(
                    ui,
                    "Authenticated peers",
                    &snapshot.authenticated_peers.to_string(),
                );
                detail(ui, "DHT records", &snapshot.dht_records.to_string());
                detail(ui, "Pending punches", &snapshot.pending_punches.to_string());
                if let Some(path) = snapshot.active_paths.first() {
                    detail(ui, "Path endpoint", &path.endpoint.to_string());
                }
            }
        });
}

fn detail(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(RichText::new(label).color(Color32::from_rgb(125, 144, 176)));
    ui.label(
        RichText::new(value)
            .monospace()
            .color(Color32::from_rgb(210, 223, 244)),
    );
    ui.end_row();
}

fn card(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(Color32::from_rgb(13, 22, 42))
        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(31, 49, 79)))
        .corner_radius(12.0)
        .inner_margin(14.0)
        .show(ui, add_contents);
}

fn configure_style(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.visuals.dark_mode = true;
    style.visuals.override_text_color = Some(Color32::from_rgb(218, 229, 247));
    style.visuals.widgets.inactive.bg_fill = Color32::from_rgb(22, 35, 61);
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(31, 62, 100);
    style.visuals.widgets.active.bg_fill = Color32::from_rgb(25, 112, 183);
    style.text_styles.insert(
        egui::TextStyle::Body,
        FontId::new(13.0, FontFamily::Proportional),
    );
    ctx.set_style(style);
}

fn nat_label(behavior: NatMappingBehavior) -> &'static str {
    match behavior {
        NatMappingBehavior::Unknown => "Unknown",
        NatMappingBehavior::SingleObservation => "1 observation",
        NatMappingBehavior::StableEndpoint => "Stable endpoint",
        NatMappingBehavior::PortVariant => "Port variant",
        NatMappingBehavior::AddressVariant => "Address variant",
    }
}

fn filtering_label(evidence: NatFilteringEvidence) -> &'static str {
    match evidence {
        NatFilteringEvidence::Unknown => "Unknown / no evidence",
        NatFilteringEvidence::Inconclusive => "Inconclusive",
        NatFilteringEvidence::ContactedEndpointObserved => "Contacted endpoint observed",
        NatFilteringEvidence::SameAddressDifferentPortObserved => {
            "Same address, different port observed"
        }
        NatFilteringEvidence::EndpointIndependentObserved => "Endpoint-independent observed",
        NatFilteringEvidence::EndpointIndependentRepeated => "Endpoint-independent repeated",
    }
}

fn filter_cell_label(status: FilterCellStatus) -> &'static str {
    match status {
        FilterCellStatus::Unknown => "Unknown / no evidence",
        FilterCellStatus::Observed => "Observed",
        FilterCellStatus::InconclusiveTimedOut => "Inconclusive — timed out",
        FilterCellStatus::InconclusiveControlCorrelatedTimeout => {
            "Inconclusive — timed out (control observed)"
        }
        FilterCellStatus::InconclusiveUnavailable => "Inconclusive — helper unavailable",
        FilterCellStatus::InconclusiveSendFailed => "Inconclusive — send failed",
    }
}

fn spawn_worker(event_tx: Sender<WorkerEvent>) -> tokio_mpsc::UnboundedSender<Command> {
    let (command_tx, command_rx) = tokio_mpsc::unbounded_channel();
    std::thread::Builder::new()
        .name("kononexus-network-runtime".into())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build();
            match runtime {
                Ok(runtime) => {
                    if let Err(error) = runtime.block_on(worker(command_rx, event_tx.clone())) {
                        let _ = event_tx.send(WorkerEvent::Error(format!("{error:#}")));
                    }
                }
                Err(error) => {
                    let _ = event_tx.send(WorkerEvent::Error(format!(
                        "Nie można uruchomić runtime: {error}"
                    )));
                }
            }
        })
        .expect("failed to start network worker");
    command_tx
}

async fn worker(
    mut command_rx: tokio_mpsc::UnboundedReceiver<Command>,
    event_tx: Sender<WorkerEvent>,
) -> Result<()> {
    let state_dir = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("KonoNexus")
        .join("NetworkTester");
    std::fs::create_dir_all(&state_dir).context("nie można utworzyć katalogu danych testera")?;
    let identity_path = state_dir.join("identity.key");
    let identity = NodeIdentity::load_or_create(&identity_path)?;
    let node_id = identity.node_id();
    let endpoints = local_invite_endpoints(47000);
    let invite = InviteCode::signed(&identity, endpoints)?.encode()?;

    let config = KonofixSdkConfig::new(identity_path.clone())
        .with_bind("0.0.0.0:47000".parse().unwrap())
        .with_routing_cache(state_dir.join("routing-cache.json"))
        .with_event_capacity(256);
    let mut transport = KonofixTransport::spawn(config).await?;
    event_tx.send(WorkerEvent::Ready { node_id, invite }).ok();

    let mut target: Option<String> = None;
    let mut test: Option<ActiveTest> = None;
    let mut last_external: Option<SocketAddr> = None;
    let mut diagnostic_tick = time::interval(Duration::from_millis(250));
    diagnostic_tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            Some(command) = command_rx.recv() => {
                match command {
                    Command::Connect(invite) => {
                        invite.verify()?;
                        let peer = invite.node_id.clone();
                        let endpoints = invite.socket_endpoints();
                        transport.connect(peer.clone(), endpoints.clone()).await?;
                        target = Some(peer.clone());
                        event_tx.send(WorkerEvent::Target(peer.clone())).ok();
                        event_tx.send(WorkerEvent::Log(format!(
                            "Invite zweryfikowany. Próba DIRECT → HOLE PUNCH → RELAY do {peer} przez {} endpoint(y).",
                            endpoints.len()
                        ))).ok();
                    }
                    Command::StartTest => {
                        let peer = target.clone().context("brak docelowego NodeID")?;
                        test = Some(ActiveTest::new(peer));
                        event_tx.send(WorkerEvent::TestStarted).ok();
                    }
                }
            }
            event = transport.next_event() => {
                match event {
                    Some(RelayAppEvent::Message(message)) => {
                        if target.is_none() {
                            target = Some(message.peer_node_id.clone());
                            event_tx.send(WorkerEvent::Target(message.peer_node_id.clone())).ok();
                        }
                        event_tx.send(WorkerEvent::Log(format!(
                            "Odebrano zaszyfrowaną próbkę {} od {} ({} B).",
                            message.message_id, message.peer_node_id, message.data.len()
                        ))).ok();
                    }
                    Some(RelayAppEvent::Delivered(receipt)) => {
                        if let Some(active) = test.as_mut() {
                            if let Some(sent_at) = active.pending.remove(&receipt.message_id) {
                                active.delivered += 1;
                                active.rtts.push(sent_at.elapsed().as_secs_f32() * 1_000.0);
                                event_tx.send(WorkerEvent::TestProgress {
                                    delivered: active.delivered,
                                    sent: active.sent,
                                }).ok();
                            }
                        }
                    }
                    Some(RelayAppEvent::Failed(failure)) => {
                        if let Some(active) = test.as_mut() {
                            if active.pending.remove(&failure.message_id).is_some() {
                                active.failed += 1;
                            }
                        }
                        event_tx.send(WorkerEvent::Log(format!(
                            "Próbka {} nie została dostarczona: {:?}.", failure.message_id, failure.reason
                        ))).ok();
                    }
                    None => anyhow::bail!("runtime sieciowy zakończył pracę"),
                }
            }
            _ = diagnostic_tick.tick() => {
                let snapshot = transport.diagnostics();
                if target.is_none() {
                    if let Some(path) = snapshot.active_paths.first() {
                        target = Some(path.peer_node_id.clone());
                        event_tx.send(WorkerEvent::Target(path.peer_node_id.clone())).ok();
                    }
                }
                if snapshot.observed_external_endpoint != last_external {
                    last_external = snapshot.observed_external_endpoint;
                    if let Some(external) = last_external {
                        let identity = NodeIdentity::load_or_create(&identity_path)?;
                        let mut endpoints = local_invite_endpoints(snapshot.local_addr.port());
                        endpoints.push(external);
                        let invite = InviteCode::signed(&identity, endpoints)?.encode()?;
                        event_tx.send(WorkerEvent::InviteUpdated(invite)).ok();
                    }
                }
                event_tx.send(WorkerEvent::Snapshot(snapshot)).ok();

                if let Some(active) = test.as_mut() {
                    if active.sent < TEST_SAMPLE_COUNT && Instant::now() >= active.next_send {
                        let sequence = active.sent + 1;
                        let payload = format!("KONONEXUS_TEST_V1:{sequence}:{}", active.started.elapsed().as_nanos());
                        match transport.send(active.target.clone(), payload.into_bytes()).await {
                            Ok(message_id) => {
                                active.pending.insert(message_id, Instant::now());
                                active.sent += 1;
                                active.next_send = Instant::now() + Duration::from_millis(250);
                                event_tx.send(WorkerEvent::TestProgress {
                                    delivered: active.delivered,
                                    sent: active.sent,
                                }).ok();
                            }
                            Err(error) => {
                                event_tx.send(WorkerEvent::Error(format!("Nie można wysłać próbki: {error:#}"))).ok();
                                test = None;
                            }
                        }
                    }
                }

                let finished = test.as_ref().is_some_and(|active| {
                    (active.sent == TEST_SAMPLE_COUNT && active.pending.is_empty())
                        || active.started.elapsed() >= TEST_TIMEOUT
                });
                if finished {
                    let active = test.take().expect("test checked above");
                    let delivered = active.delivered;
                    let packet_loss = 100.0 * (TEST_SAMPLE_COUNT.saturating_sub(delivered)) as f32 / TEST_SAMPLE_COUNT as f32;
                    let rtt_ms = if active.rtts.is_empty() {
                        0.0
                    } else {
                        active.rtts.iter().sum::<f32>() / active.rtts.len() as f32
                    };
                    event_tx.send(WorkerEvent::TestFinished { rtt_ms, packet_loss }).ok();
                }
            }
        }
    }
}

fn local_invite_endpoints(port: u16) -> Vec<SocketAddr> {
    local_ip_hint()
        .map(|ip| vec![SocketAddr::new(ip, port)])
        .unwrap_or_else(|| vec!["127.0.0.1:47000".parse().expect("static endpoint is valid")])
}

fn local_ip_hint() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    Some(socket.local_addr().ok()?.ip())
}

fn app_icon() -> Option<egui::IconData> {
    let image = image::load_from_memory(include_bytes!("../../assets/kononexus-tester.png"))
        .ok()?
        .into_rgba8();
    let (width, height) = image.dimensions();
    Some(egui::IconData {
        rgba: image.into_raw(),
        width,
        height,
    })
}

fn main() -> eframe::Result<()> {
    let (event_tx, event_rx) = mpsc::channel();
    let command_tx = spawn_worker(event_tx);
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("KonoNexus Network Tester")
        .with_inner_size([980.0, 760.0])
        .with_min_inner_size([820.0, 650.0]);
    if let Some(icon) = app_icon() {
        viewport = viewport.with_icon(icon);
    }
    eframe::run_native(
        "KonoNexus Network Tester",
        eframe::NativeOptions {
            viewport,
            ..Default::default()
        },
        Box::new(move |cc| Ok(Box::new(TesterApp::new(cc, command_tx, event_rx)))),
    )
}

#[allow(dead_code)]
fn _state_path(base: &Path) -> PathBuf {
    base.join("KonoNexus").join("NetworkTester")
}
