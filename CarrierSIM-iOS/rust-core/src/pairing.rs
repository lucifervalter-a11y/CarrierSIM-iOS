//! Pairing module — RPPairing host, adapted from SideInstaller's pairing.rs.
//!
//! mDNS advertising is done in Swift via NetService (no iOS multicast entitlement
//! needed). The Rust side binds a TCP listener, passes the service ID, port, and
//! TXT records to Swift through `ready_cb`, then drives the handshake.

use std::ffi::{c_char, c_void, CString};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static HOST_ACTIVE: AtomicBool = AtomicBool::new(false);
static HOST_CANCELLED: AtomicBool = AtomicBool::new(false);

struct HostGuard;
impl Drop for HostGuard {
    fn drop(&mut self) { HOST_ACTIVE.store(false, Ordering::SeqCst); }
}

/// Cancels the one active pairing listener. It does not erase existing keys.
#[no_mangle]
pub extern "C" fn al_pairing_cancel_host() {
    HOST_CANCELLED.store(true, Ordering::SeqCst);
}

async fn wait_for_host_cancel() {
    while !HOST_CANCELLED.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

use idevice::remote_pairing::{
    PairableHost, PairableHostInfo, RpPairingFile, RpPairingSocket,
};
use tokio::net::TcpListener;

use crate::ffi_util::{cstr, opt_str};

// ---------------------------------------------------------------------------
// Types exposed to C / Swift

pub type ALPairReadyCb = Option<
    extern "C" fn(
        ctx: *mut c_void,
        service_id: *const c_char,
        port: u16,
        txt_keys: *const *const c_char,
        txt_vals: *const *const c_char,
        txt_count: usize,
    ),
>;

pub type ALPairPinCb = Option<extern "C" fn(pin: *const c_char, ctx: *mut c_void)>;

/// Heap-allocated result of one pairing run. Free with `al_pairing_result_free`.
#[repr(C)]
pub struct ALPairResult {
    pub error: *mut c_char,
    pub device_name: *mut c_char,
    pub device_model: *mut c_char,
    pub device_udid: *mut c_char,
    pub pairing_file_path: *mut c_char,
    pub host_alt_irk_hex: *mut c_char,
}

impl ALPairResult {
    fn empty() -> Self {
        Self {
            error: ptr::null_mut(),
            device_name: ptr::null_mut(),
            device_model: ptr::null_mut(),
            device_udid: ptr::null_mut(),
            pairing_file_path: ptr::null_mut(),
            host_alt_irk_hex: ptr::null_mut(),
        }
    }
}

// Callbacks carry raw pointers; the Swift side ensures they outlive the call.
struct Cbs {
    ready: ALPairReadyCb,
    pin: ALPairPinCb,
    ctx: *mut c_void,
}
unsafe impl Send for Cbs {}

// ---------------------------------------------------------------------------
// Public FFI entry point

/// # Safety
/// All `*const c_char` args must be null or valid C strings.
/// `out` must point to a writable `ALPairResult`.
#[allow(clippy::too_many_arguments)]
pub unsafe fn run_host(
    bind_addr: *const c_char,
    port: u16,
    name: *const c_char,
    model: *const c_char,
    out_path: *const c_char,
    host_alt_irk_hex: *const c_char,
    ready_cb: ALPairReadyCb,
    pin_cb: ALPairPinCb,
    ctx: *mut c_void,
    out: *mut ALPairResult,
) -> i32 {
    if out.is_null() {
        return 2;
    }
    *out = ALPairResult::empty();

    if HOST_ACTIVE.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        (*out).error = cstr("Сопряжение уже выполняется.");
        return 3;
    }
    let _guard = HostGuard;
    HOST_CANCELLED.store(false, Ordering::SeqCst);

    let bind_addr = opt_str(bind_addr, "0.0.0.0");
    let name = opt_str(name, "Airlift");
    let model = opt_str(model, "Mac17,7");
    let out_path = opt_str(out_path, "airlift_pairing.plist");
    let saved_alt_irk = parse_alt_irk(&opt_str(host_alt_irk_hex, ""));
    let cbs = Cbs { ready: ready_cb, pin: pin_cb, ctx };

    let res = crate::ffi_util::run_with_large_stack("al_pairing_run_host", move || {
        idevice_ffi::run_sync_local(async move {
            tokio::select! {
                result = tokio::time::timeout(Duration::from_secs(300), async_run_host(
                    bind_addr, port, name, model, out_path, saved_alt_irk, cbs,
                )) => result.unwrap_or_else(|_| Err("Время сопряжения истекло. Вернитесь в приложение и повторите подключение.".into())),
                _ = wait_for_host_cancel() => Err("Сопряжение остановлено.".into()),
            }
        })
    });

    match res {
        Ok(Ok((dev_name, dev_model, udid, path, irk_hex))) => {
            (*out).device_name = cstr(dev_name);
            (*out).device_model = cstr(dev_model);
            (*out).device_udid = cstr(udid);
            (*out).pairing_file_path = cstr(path);
            (*out).host_alt_irk_hex = cstr(irk_hex);
            0
        }
        Ok(Err(e)) => {
            (*out).error = cstr(e);
            1
        }
        Err(panic_msg) => {
            (*out).error = cstr(panic_msg);
            1
        }
    }
}

async fn async_run_host(
    bind_addr: String,
    port: u16,
    name: String,
    model: String,
    out_path: String,
    saved_alt_irk: Option<[u8; 16]>,
    cbs: Cbs,
) -> Result<(String, String, String, String, String), String> {
    tracing::info!("RPPairing: binding on {bind_addr}:{port}");
    let ip: IpAddr = bind_addr.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let listener = TcpListener::bind(SocketAddr::new(ip, port))
        .await
        .map_err(|e| format!("failed to bind {bind_addr}:{port}: {e}"))?;
    let bound_port = listener
        .local_addr()
        .map_err(|e| format!("no local addr: {e}"))?
        .port();
    tracing::info!("RPPairing: listening on port {bound_port}");

    let mut pairing_file = match RpPairingFile::read_from_file(&out_path).await {
        Ok(mut existing) => {
            existing.alt_irk = None;
            tracing::info!("RPPairing: reusing host key pair from {out_path}");
            existing
        }
        Err(_) => {
            tracing::info!("RPPairing: generating new host key pair");
            RpPairingFile::generate(&name)
        }
    };

    let mut host_info = PairableHostInfo::generate(&name, &model);
    if let Some(irk) = saved_alt_irk {
        host_info.alt_irk = irk;
        tracing::info!("RPPairing: reusing stored altIRK");
    }
    let host_alt_irk = host_info.alt_irk;
    let service_id = pairing_file.identifier.clone();

    // Advertise: hand the Bonjour details to Swift via the ready callback.
    emit_ready(&cbs, &service_id, bound_port, &host_info);

    tracing::info!("RPPairing: waiting for device on port {bound_port}…");
    let (stream, peer_addr) = listener
        .accept()
        .await
        .map_err(|e| format!("accept failed: {e}"))?;
    tracing::info!("RPPairing: device connected from {peer_addr}");

    let socket = RpPairingSocket::new_device(stream);
    let mut host = PairableHost::new(socket, host_info);

    // Clone ctx pointer so the closure can capture it.
    let pin_cb = cbs.pin;
    let pin_ctx = cbs.ctx;

    let peer_info = host
        .accept(&mut pairing_file, move |pin| {
            let pin_cb = pin_cb;
            let pin_ctx = pin_ctx;
            async move {
                tracing::info!("RPPairing: PIN issued");
                if let Some(cb) = pin_cb {
                    if let Ok(c) = CString::new(pin.as_str()) {
                        cb(c.as_ptr(), pin_ctx);
                    }
                }
            }
        })
        .await
        .map_err(|e| format!("pairing failed: {e}"))?;
    tracing::info!(
        "RPPairing: handshake complete — {} ({})",
        peer_info.name, peer_info.model
    );

    let temporary_path = format!("{out_path}.pending");
    pairing_file
        .write_to_file(&temporary_path)
        .await
        .map_err(|e| format!("failed to write pairing file: {e}"))?;

    // Preserve a previously working pairing file if the app is killed while writing.
    // The rename itself is synchronous so cancellation cannot interrupt publication.
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temporary_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("protect pairing file: {e}"))?;
        std::fs::File::open(&temporary_path).and_then(|f| f.sync_all())
            .map_err(|e| format!("flush pairing file: {e}"))?;
        std::fs::rename(&temporary_path, &out_path)
            .map_err(|e| format!("publish pairing file: {e}"))?;
        if let Some(parent) = std::path::Path::new(&out_path).parent() {
            std::fs::File::open(parent).and_then(|f| f.sync_all())
                .map_err(|e| format!("flush pairing directory: {e}"))?;
        }
    }

    let size = tokio::fs::metadata(&out_path)
        .await
        .map(|m| m.len())
        .unwrap_or(0);
    if size == 0 {
        return Err(format!(
            "handshake completed but pairing file {out_path} is empty"
        ));
    }
    tracing::info!("RPPairing: pairing file written to {out_path} ({size} bytes)");

    Ok((
        peer_info.name,
        peer_info.model,
        peer_info.remotepairing_udid,
        out_path,
        bytes_to_hex(&host_alt_irk),
    ))
}

// ---------------------------------------------------------------------------
// Free

/// # Safety
/// `r` must be null or a `ALPairResult` populated by `run_host`.
pub unsafe fn result_free(r: *mut ALPairResult) {
    if r.is_null() {
        return;
    }
    for p in [
        (*r).error,
        (*r).device_name,
        (*r).device_model,
        (*r).device_udid,
        (*r).pairing_file_path,
        (*r).host_alt_irk_hex,
    ] {
        if !p.is_null() {
            drop(CString::from_raw(p));
        }
    }
    *r = ALPairResult::empty();
}

// ---------------------------------------------------------------------------
// Helpers

fn emit_ready(cbs: &Cbs, service_id: &str, port: u16, host_info: &PairableHostInfo) {
    let Some(cb) = cbs.ready else { return };
    let records = host_info.mdns_txt_records(service_id);
    let keys: Vec<CString> = records
        .iter()
        .map(|(k, _)| CString::new(k.as_str()).unwrap_or_default())
        .collect();
    let vals: Vec<CString> = records
        .iter()
        .map(|(_, v)| CString::new(v.as_str()).unwrap_or_default())
        .collect();
    let key_ptrs: Vec<*const c_char> = keys.iter().map(|s| s.as_ptr()).collect();
    let val_ptrs: Vec<*const c_char> = vals.iter().map(|s| s.as_ptr()).collect();

    let Ok(id_c) = CString::new(service_id) else { return };
    cb(
        cbs.ctx,
        id_c.as_ptr(),
        port,
        key_ptrs.as_ptr(),
        val_ptrs.as_ptr(),
        records.len(),
    );
}

fn parse_alt_irk(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 { return None; }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn bytes_to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
