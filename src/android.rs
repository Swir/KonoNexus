//! Android embedding boundary for KonoNexus.
//!
//! The core bridge is platform-neutral so lifecycle and real UDP delivery can be
//! tested on CI. The optional `android-jni` feature only adds the thin JNI ABI.

use crate::{
    KonofixSdkConfig, KonofixSdkEventEnvelope, KonofixSdkRequest, KonofixSdkResponse,
    KonofixTransport, MAX_SDK_REQUEST_ID_BYTES,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc as std_mpsc, Arc, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tokio::runtime::Builder;
use tokio::sync::{mpsc, oneshot};

pub const ANDROID_BRIDGE_DOMAIN: &str = "kononexus/android-transport";
pub const ANDROID_BRIDGE_VERSION: u8 = 1;
pub const MAX_ANDROID_EVENT_CAPACITY: usize = 1_024;
pub const MAX_ANDROID_POLL_TIMEOUT_MS: u64 = 60_000;
const ANDROID_COMMAND_CAPACITY: usize = 64;
const ANDROID_START_TIMEOUT: Duration = Duration::from_secs(30);
const ANDROID_STOP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AndroidTransportConfig {
    pub domain: String,
    pub version: u8,
    pub identity_path: String,
    #[serde(default)]
    pub routing_cache_path: Option<String>,
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default)]
    pub seed_peers: Vec<String>,
    #[serde(default = "default_hello_interval_ms")]
    pub hello_interval_ms: u64,
    #[serde(default = "default_event_capacity")]
    pub event_capacity: usize,
    #[serde(default)]
    pub local_test_mode: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AndroidTransportInfo {
    pub domain: String,
    pub version: u8,
    pub node_id: String,
    pub local_addr: String,
}

enum AndroidCommand {
    Request {
        request: KonofixSdkRequest,
        reply: oneshot::Sender<String>,
    },
    Shutdown {
        reply: oneshot::Sender<()>,
    },
}

pub struct AndroidTransportBridge {
    info: AndroidTransportInfo,
    command_tx: mpsc::Sender<AndroidCommand>,
    event_rx: Mutex<mpsc::Receiver<String>>,
    worker: Mutex<Option<JoinHandle<()>>>,
    stopped: AtomicBool,
}

impl AndroidTransportConfig {
    pub fn from_json_verified(json: &str) -> Result<Self> {
        let config: Self =
            serde_json::from_str(json).context("invalid Android transport config JSON")?;
        config.verify()?;
        Ok(config)
    }

    pub fn to_json(&self) -> Result<String> {
        self.verify()?;
        serde_json::to_string(self).context("unable to encode Android transport config")
    }

    pub fn verify(&self) -> Result<()> {
        if self.domain != ANDROID_BRIDGE_DOMAIN {
            bail!("unsupported Android bridge domain");
        }
        if self.version != ANDROID_BRIDGE_VERSION {
            bail!("unsupported Android bridge version {}", self.version);
        }
        verify_path(&self.identity_path, "identity_path")?;
        if let Some(path) = &self.routing_cache_path {
            verify_path(path, "routing_cache_path")?;
        }

        let bind: SocketAddr = self.bind.parse().context("invalid Android bind endpoint")?;
        if bind.ip().is_multicast() {
            bail!("Android bind endpoint must not be multicast");
        }
        if self.seed_peers.len() > 16 {
            bail!("Android seed peer list exceeds 16 entries");
        }
        for peer in &self.seed_peers {
            let endpoint: SocketAddr = peer
                .parse()
                .with_context(|| format!("invalid Android seed endpoint {peer}"))?;
            if endpoint.port() == 0 || unusable_seed_ip(endpoint.ip()) {
                bail!("unusable Android seed endpoint {peer}");
            }
        }
        if !(100..=60_000).contains(&self.hello_interval_ms) {
            bail!("hello_interval_ms must be between 100 and 60000");
        }
        if !(1..=MAX_ANDROID_EVENT_CAPACITY).contains(&self.event_capacity) {
            bail!("event_capacity must be between 1 and {MAX_ANDROID_EVENT_CAPACITY}");
        }
        Ok(())
    }

    fn sdk_config(&self) -> Result<KonofixSdkConfig> {
        self.verify()?;
        let mut config = KonofixSdkConfig::new(PathBuf::from(&self.identity_path))
            .with_bind(self.bind.parse()?)
            .with_seed_peers(
                self.seed_peers
                    .iter()
                    .map(|value| value.parse())
                    .collect::<std::result::Result<Vec<_>, _>>()?,
            )
            .with_hello_interval(Duration::from_millis(self.hello_interval_ms))
            .with_event_capacity(self.event_capacity)
            .with_local_test_mode(self.local_test_mode);
        if let Some(path) = &self.routing_cache_path {
            config = config.with_routing_cache(PathBuf::from(path));
        }
        Ok(config)
    }
}

impl AndroidTransportInfo {
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).context("unable to encode Android transport info")
    }
}

impl AndroidTransportBridge {
    pub fn start_json(json: &str) -> Result<Arc<Self>> {
        Self::start(AndroidTransportConfig::from_json_verified(json)?)
    }

    pub fn start(config: AndroidTransportConfig) -> Result<Arc<Self>> {
        let sdk_config = config.sdk_config()?;
        let event_capacity = config.event_capacity;
        let (command_tx, command_rx) = mpsc::channel(ANDROID_COMMAND_CAPACITY);
        let (event_tx, event_rx) = mpsc::channel(event_capacity);
        let (ready_tx, ready_rx) = std_mpsc::sync_channel(1);

        let worker = thread::Builder::new()
            .name("kononexus-android".to_owned())
            .spawn(move || {
                let runtime = match Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready_tx.send(Err(format!(
                            "unable to start Android Tokio runtime: {error}"
                        )));
                        return;
                    }
                };
                runtime.block_on(run_android_transport(
                    sdk_config, command_rx, event_tx, ready_tx,
                ));
            })
            .context("unable to spawn Android transport thread")?;

        let info = match ready_rx.recv_timeout(ANDROID_START_TIMEOUT) {
            Ok(Ok(info)) => info,
            Ok(Err(error)) => {
                let _ = worker.join();
                bail!("{error}");
            }
            Err(std_mpsc::RecvTimeoutError::Timeout) => {
                bail!("Android transport startup exceeded 30 seconds")
            }
            Err(std_mpsc::RecvTimeoutError::Disconnected) => {
                let _ = worker.join();
                bail!("Android transport worker stopped during startup")
            }
        };

        Ok(Arc::new(Self {
            info,
            command_tx,
            event_rx: Mutex::new(event_rx),
            worker: Mutex::new(Some(worker)),
            stopped: AtomicBool::new(false),
        }))
    }

    pub fn info(&self) -> &AndroidTransportInfo {
        &self.info
    }

    pub fn info_json(&self) -> Result<String> {
        self.info.to_json()
    }

    pub fn request_json(&self, json: &str) -> Result<String> {
        if self.stopped.load(Ordering::Acquire) {
            bail!("Android transport is stopped");
        }
        let request = match KonofixSdkRequest::from_json_verified(json) {
            Ok(request) => request,
            Err(error) => {
                return KonofixSdkResponse::rejected(
                    request_id_hint(json),
                    "invalid_request",
                    printable_error(&error),
                )
                .to_json()
            }
        };
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .blocking_send(AndroidCommand::Request {
                request,
                reply: reply_tx,
            })
            .map_err(|_| anyhow::anyhow!("Android transport command channel is closed"))?;
        reply_rx
            .blocking_recv()
            .context("Android transport request was interrupted")
    }

    pub fn poll_event_json(&self, timeout_ms: u64) -> Result<Option<String>> {
        if timeout_ms > MAX_ANDROID_POLL_TIMEOUT_MS {
            bail!("Android event poll exceeds {MAX_ANDROID_POLL_TIMEOUT_MS} ms");
        }
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let mut receiver = self
            .event_rx
            .lock()
            .map_err(|_| anyhow::anyhow!("Android event receiver lock poisoned"))?;
        loop {
            match receiver.try_recv() {
                Ok(event) => return Ok(Some(event)),
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    if self.stopped.load(Ordering::Acquire) {
                        return Ok(None);
                    }
                    bail!("Android transport event channel is closed");
                }
                Err(mpsc::error::TryRecvError::Empty) => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Ok(None);
                    }
                    thread::sleep((deadline - now).min(Duration::from_millis(5)));
                }
            }
        }
    }

    pub fn stop(&self) -> Result<()> {
        if !self.stopped.swap(true, Ordering::AcqRel) {
            let (reply_tx, reply_rx) = oneshot::channel();
            if self
                .command_tx
                .blocking_send(AndroidCommand::Shutdown { reply: reply_tx })
                .is_ok()
            {
                match reply_rx.blocking_recv() {
                    Ok(()) => {}
                    Err(_) => bail!("Android transport shutdown was interrupted"),
                }
            }
        }

        let worker = self
            .worker
            .lock()
            .map_err(|_| anyhow::anyhow!("Android worker lock poisoned"))?
            .take();
        if let Some(worker) = worker {
            let (joined_tx, joined_rx) = std_mpsc::sync_channel(1);
            thread::spawn(move || {
                let result = worker.join();
                let _ = joined_tx.send(result);
            });
            match joined_rx.recv_timeout(ANDROID_STOP_TIMEOUT) {
                Ok(Ok(())) => {}
                Ok(Err(_)) => bail!("Android transport worker panicked"),
                Err(std_mpsc::RecvTimeoutError::Timeout) => {
                    bail!("Android transport shutdown exceeded 10 seconds")
                }
                Err(std_mpsc::RecvTimeoutError::Disconnected) => {
                    bail!("Android transport join monitor stopped")
                }
            }
        }
        Ok(())
    }
}

impl Drop for AndroidTransportBridge {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

async fn run_android_transport(
    sdk_config: KonofixSdkConfig,
    mut commands: mpsc::Receiver<AndroidCommand>,
    events: mpsc::Sender<String>,
    ready: std_mpsc::SyncSender<std::result::Result<AndroidTransportInfo, String>>,
) {
    let mut transport = match KonofixTransport::spawn(sdk_config).await {
        Ok(transport) => transport,
        Err(error) => {
            let _ = ready.send(Err(format!(
                "KonoNexus Android transport startup failed: {error:#}"
            )));
            return;
        }
    };
    let info = AndroidTransportInfo {
        domain: ANDROID_BRIDGE_DOMAIN.to_owned(),
        version: ANDROID_BRIDGE_VERSION,
        node_id: transport.node_id().to_owned(),
        local_addr: transport.local_addr().to_string(),
    };
    if ready.send(Ok(info)).is_err() {
        transport.shutdown().await;
        return;
    }

    enum Wake<'a> {
        Event(Option<(mpsc::Permit<'a, String>, Option<crate::RelayAppEvent>)>),
        Command(Option<AndroidCommand>),
        ConsumerClosed,
    }

    loop {
        let wake = tokio::select! {
            event = async {
                let permit = events.reserve().await.ok()?;
                Some((permit, transport.next_event().await))
            } => Wake::Event(event),
            command = commands.recv() => Wake::Command(command),
            _ = events.closed() => Wake::ConsumerClosed,
        };
        match wake {
            Wake::Event(Some((permit, Some(event)))) => {
                match KonofixSdkEventEnvelope::from_relay_event(event).to_json() {
                    Ok(json) => permit.send(json),
                    Err(_) => break,
                }
            }
            Wake::Event(None) | Wake::Event(Some((_, None))) | Wake::ConsumerClosed => break,
            Wake::Command(Some(AndroidCommand::Request { request, reply })) => {
                let response = match request.execute(&transport).await {
                    Ok(response) => response,
                    Err(error) => KonofixSdkResponse::rejected(
                        request.request_id,
                        "bridge_error",
                        printable_error(&error),
                    ),
                };
                let json = response.to_json().unwrap_or_else(|_| {
                    KonofixSdkResponse::rejected(
                        "bridge-error",
                        "serialization_error",
                        "unable to encode SDK response",
                    )
                    .to_json()
                    .expect("static SDK rejection response is valid")
                });
                let _ = reply.send(json);
            }
            Wake::Command(Some(AndroidCommand::Shutdown { reply })) => {
                commands.close();
                transport.shutdown().await;
                let _ = reply.send(());
                return;
            }
            Wake::Command(None) => break,
        }
    }
    commands.close();
    transport.shutdown().await;
}

fn default_bind() -> String {
    "0.0.0.0:0".to_owned()
}

fn default_hello_interval_ms() -> u64 {
    2_000
}

fn default_event_capacity() -> usize {
    64
}

fn verify_path(path: &str, field: &str) -> Result<()> {
    if path.is_empty() || path.len() > 4_096 || path.chars().any(char::is_control) {
        bail!("{field} must be a non-empty printable path of at most 4096 bytes");
    }
    Ok(())
}

fn unusable_seed_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast(),
        IpAddr::V6(ip) => ip.is_unspecified() || ip.is_multicast(),
    }
}

fn request_id_hint(json: &str) -> String {
    serde_json::from_str::<Value>(json)
        .ok()
        .and_then(|value| value.get("request_id")?.as_str().map(str::to_owned))
        .filter(|value| {
            !value.is_empty()
                && value.len() <= MAX_SDK_REQUEST_ID_BYTES
                && !value.chars().any(char::is_control)
        })
        .unwrap_or_else(|| "invalid-request".to_owned())
}

fn printable_error(error: &anyhow::Error) -> String {
    error
        .to_string()
        .chars()
        .filter(|character| !character.is_control())
        .collect()
}

#[cfg(feature = "android-jni")]
mod jni_api {
    use super::*;
    use jni::objects::{JClass, JString};
    use jni::sys::{jboolean, jlong, jstring, JNI_FALSE, JNI_TRUE};
    use jni::JNIEnv;
    use std::collections::HashMap;
    use std::ptr;
    use std::sync::atomic::AtomicI64;
    use std::sync::OnceLock;

    static NEXT_HANDLE: AtomicI64 = AtomicI64::new(1);
    static BRIDGES: OnceLock<Mutex<HashMap<i64, Arc<AndroidTransportBridge>>>> = OnceLock::new();

    fn bridges() -> &'static Mutex<HashMap<i64, Arc<AndroidTransportBridge>>> {
        BRIDGES.get_or_init(|| Mutex::new(HashMap::new()))
    }

    fn read_string(env: &mut JNIEnv<'_>, value: &JString<'_>) -> Result<String> {
        env.get_string(value)
            .map(Into::into)
            .context("unable to read Java string")
    }

    fn write_string(env: &mut JNIEnv<'_>, value: String) -> jstring {
        env.new_string(value)
            .map(|value| value.into_raw())
            .unwrap_or(ptr::null_mut())
    }

    fn bridge(handle: jlong) -> Result<Arc<AndroidTransportBridge>> {
        bridges()
            .lock()
            .map_err(|_| anyhow::anyhow!("Android JNI bridge registry lock poisoned"))?
            .get(&handle)
            .cloned()
            .context("unknown Android transport handle")
    }

    fn throw(env: &mut JNIEnv<'_>, class: &str, error: impl std::fmt::Display) {
        let _ = env.throw_new(class, error.to_string());
    }

    #[no_mangle]
    pub extern "system" fn Java_com_swir_kononexus_KonoNexusNative_nativeStart(
        mut env: JNIEnv<'_>,
        _class: JClass<'_>,
        config_json: JString<'_>,
    ) -> jlong {
        let result = (|| -> Result<jlong> {
            let config = read_string(&mut env, &config_json)?;
            let bridge = AndroidTransportBridge::start_json(&config)?;
            let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
            if handle <= 0 {
                bail!("Android transport handle space exhausted");
            }
            bridges()
                .lock()
                .map_err(|_| anyhow::anyhow!("Android JNI bridge registry lock poisoned"))?
                .insert(handle, bridge);
            Ok(handle)
        })();
        match result {
            Ok(handle) => handle,
            Err(error) => {
                throw(&mut env, "java/lang/IllegalStateException", error);
                0
            }
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_com_swir_kononexus_KonoNexusNative_nativeInfo(
        mut env: JNIEnv<'_>,
        _class: JClass<'_>,
        handle: jlong,
    ) -> jstring {
        match bridge(handle).and_then(|bridge| bridge.info_json()) {
            Ok(json) => write_string(&mut env, json),
            Err(error) => {
                throw(&mut env, "java/lang/IllegalStateException", error);
                ptr::null_mut()
            }
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_com_swir_kononexus_KonoNexusNative_nativeRequest(
        mut env: JNIEnv<'_>,
        _class: JClass<'_>,
        handle: jlong,
        request_json: JString<'_>,
    ) -> jstring {
        let result = (|| -> Result<String> {
            let request = read_string(&mut env, &request_json)?;
            bridge(handle)?.request_json(&request)
        })();
        match result {
            Ok(json) => write_string(&mut env, json),
            Err(error) => {
                throw(&mut env, "java/lang/IllegalStateException", error);
                ptr::null_mut()
            }
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_com_swir_kononexus_KonoNexusNative_nativePollEvent(
        mut env: JNIEnv<'_>,
        _class: JClass<'_>,
        handle: jlong,
        timeout_ms: jlong,
    ) -> jstring {
        let result = (|| -> Result<Option<String>> {
            let timeout: u64 = timeout_ms
                .try_into()
                .context("Android poll timeout must not be negative")?;
            bridge(handle)?.poll_event_json(timeout)
        })();
        match result {
            Ok(Some(json)) => write_string(&mut env, json),
            Ok(None) => ptr::null_mut(),
            Err(error) => {
                throw(&mut env, "java/lang/IllegalStateException", error);
                ptr::null_mut()
            }
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_com_swir_kononexus_KonoNexusNative_nativeStop(
        mut env: JNIEnv<'_>,
        _class: JClass<'_>,
        handle: jlong,
    ) -> jboolean {
        let bridge = match bridges().lock() {
            Ok(mut bridges) => bridges.remove(&handle),
            Err(_) => {
                throw(
                    &mut env,
                    "java/lang/IllegalStateException",
                    "Android JNI bridge registry lock poisoned",
                );
                return JNI_FALSE;
            }
        };
        match bridge {
            Some(bridge) => match bridge.stop() {
                Ok(()) => JNI_TRUE,
                Err(error) => {
                    throw(&mut env, "java/lang/IllegalStateException", error);
                    JNI_FALSE
                }
            },
            None => JNI_FALSE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KonofixSdkEvent, KonofixSdkResult};
    use std::fs;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn config(root: &Path, name: &str) -> AndroidTransportConfig {
        AndroidTransportConfig {
            domain: ANDROID_BRIDGE_DOMAIN.to_owned(),
            version: ANDROID_BRIDGE_VERSION,
            identity_path: root.join(format!("{name}.key")).display().to_string(),
            routing_cache_path: Some(
                root.join(format!("{name}-routing.json"))
                    .display()
                    .to_string(),
            ),
            bind: "127.0.0.1:0".to_owned(),
            seed_peers: Vec::new(),
            hello_interval_ms: 100,
            event_capacity: 1,
            local_test_mode: true,
        }
    }

    fn test_root() -> PathBuf {
        let unique = format!(
            "kononexus-android-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock is before the Unix epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(unique);
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn android_config_is_strict_and_bounded() {
        let root = test_root();
        let valid = config(&root, "valid");
        let json = valid.to_json().unwrap();
        assert_eq!(
            AndroidTransportConfig::from_json_verified(&json).unwrap(),
            valid
        );

        let mut invalid = valid.clone();
        invalid.domain = "other/domain".to_owned();
        assert!(invalid.verify().is_err());
        invalid = valid.clone();
        invalid.event_capacity = MAX_ANDROID_EVENT_CAPACITY + 1;
        assert!(invalid.verify().is_err());
        invalid = valid;
        invalid.seed_peers = vec!["0.0.0.0:47000".to_owned()];
        assert!(invalid.verify().is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn two_android_bridges_exchange_message_and_receipt() {
        let root = test_root();
        let receiver = AndroidTransportBridge::start(config(&root, "receiver")).unwrap();
        let sender = AndroidTransportBridge::start(config(&root, "sender")).unwrap();

        let connect = KonofixSdkRequest::new_connect(
            "connect",
            receiver.info().node_id.clone(),
            [receiver.info().local_addr.parse().unwrap()],
        );
        let response = sender.request_json(&connect.to_json().unwrap()).unwrap();
        assert_eq!(
            KonofixSdkResponse::from_json_verified(&response)
                .unwrap()
                .result,
            KonofixSdkResult::Connected
        );

        let send = KonofixSdkRequest::new_send(
            "send",
            receiver.info().node_id.clone(),
            b"android-transport",
        );
        let response = KonofixSdkResponse::from_json_verified(
            &sender.request_json(&send.to_json().unwrap()).unwrap(),
        )
        .unwrap();
        let message_id = match response.result {
            KonofixSdkResult::Sent { message_id } => message_id,
            other => panic!("expected sent response, got {other:?}"),
        };

        let deadline = Instant::now() + Duration::from_secs(15);
        let mut received = false;
        let mut delivered = false;
        while Instant::now() < deadline && !(received && delivered) {
            if let Some(json) = receiver.poll_event_json(50).unwrap() {
                let event = crate::KonofixSdkEventEnvelope::from_json_verified(&json).unwrap();
                if let KonofixSdkEvent::Message {
                    message_id: incoming_id,
                    data_base64,
                    ..
                } = event.event
                {
                    received =
                        incoming_id == message_id && data_base64 == "YW5kcm9pZC10cmFuc3BvcnQ=";
                }
            }
            if let Some(json) = sender.poll_event_json(50).unwrap() {
                let event = crate::KonofixSdkEventEnvelope::from_json_verified(&json).unwrap();
                if let KonofixSdkEvent::Delivered {
                    message_id: delivered_id,
                    ..
                } = event.event
                {
                    delivered = delivered_id == message_id;
                }
            }
        }
        assert!(received, "Android receiver must observe the binary message");
        assert!(
            delivered,
            "Android sender must observe the authenticated receipt"
        );

        sender.stop().unwrap();
        receiver.stop().unwrap();
        let _ = fs::remove_dir_all(root);
    }
}
