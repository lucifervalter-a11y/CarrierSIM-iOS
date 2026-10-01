//! Native IPCC trigger upload and installation.
//!
//! The desktop program deliberately uploads ZIP symlink entries as *regular
//! files containing their original bytes*.  Do the same here: AFC never creates
//! a symlink for an IPCC.  The only remote files this module removes are beneath
//! its own random PublicStaging directory.  Raw CommCenter output stays in memory
//! and is excluded from both the journal and serialized results.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

use idevice::afc::errors::AfcError;
use idevice::afc::opcode::AfcFopenMode;
use idevice::afc::AfcClient;
use idevice::services::installation_proxy::InstallationProxyClient;
use idevice::{IdeviceError, ReadWrite};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::time::{timeout, Instant};

use crate::carrier_data::{read_tree_zip_bytes, NodeKind, Tree, Trigger};
use crate::exploit::{AppDeviceTunnel, Logger};

const JOURNAL_NAME: &str = "trigger-staging.json";
const STAGING_PARENT: &str = "PublicStaging";
const STAGING_PREFIX: &str = "PublicStaging/carriersim-trigger-";
const MAX_TREE_ENTRIES: usize = 4096;
const MAX_FILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_TREE_BYTES: usize = 64 * 1024 * 1024;
const MAX_LOG_BYTES: usize = 16 * 1024 * 1024;
const MAX_LOG_LINE: usize = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(120);
const INSTALL_TIMEOUT: Duration = Duration::from_secs(90);
const OBSERVE_AFTER_INSTALL: Duration = Duration::from_secs(8);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Serialize, Deserialize)]
pub(crate) struct TriggerResult {
    pub(crate) ipcc_installation_completed: bool,
    /// Contains private device output. Only pass to the in-memory report parser.
    #[serde(skip)]
    pub(crate) commcenter_log: String,
    pub(crate) log_error: Option<String>,
}

impl std::fmt::Debug for TriggerResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TriggerResult")
            .field("ipcc_installation_completed", &self.ipcc_installation_completed)
            .field("commcenter_log", &"<private, not serialized>")
            .field("log_error", &self.log_error)
            .finish()
    }
}

/// Written before any AFC mutation and retained after cleanup. A started
/// installation with no Complete response has an unknown device-side outcome.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TriggerJournal {
    schema_version: u32,
    staging_path: String,
    trigger_sha256: String,
    phase: String,
    staging_creation_started: bool,
    installation_started: bool,
    ipcc_installation_completed: bool,
    cleanup_completed: bool,
    last_error: Option<String>,
    log_error: Option<String>,
}

/// Installs an already validated independent trigger carrier bundle.
///
/// `stage_path` is the caller's durable, device-bound run directory. Callers
/// must validate the trigger's SIM non-overlap before entering this function.
/// Every interruption leaves enough local metadata for `recover_trigger` to
/// remove this operation's temporary upload; recovery does not undo an IPCC
/// installation, which may already have changed the independent carrier bundle.
pub(crate) async fn install_trigger(
    tunnel: &mut AppDeviceTunnel,
    trigger: &Trigger,
    logger: &Logger,
    stage_path: &Path,
) -> Result<TriggerResult, String> {
    let directories = validate_tree(&trigger.tree)?;
    if trigger.sha256 != hex::encode(Sha256::digest(&trigger.bytes)) {
        return Err("Контрольная сумма IPCC не совпадает с проверенным архивом.".into());
    }
    if read_tree_zip_bytes(&trigger.bytes)? != trigger.tree {
        return Err("Файлы IPCC не совпадают с содержимым проверенного архива.".into());
    }
    check_local_run(stage_path)?;
    match fs::symlink_metadata(stage_path.join(JOURNAL_NAME)) {
        Ok(_) => return Err("Для этого запуска уже существует журнал IPCC. Сначала завершите восстановление и создайте новый запуск.".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("Не удалось проверить существующий журнал IPCC.".into()),
    }
    let mut journal = TriggerJournal {
        schema_version: 1,
        staging_path: format!("{STAGING_PREFIX}{}.ipcc", random_token()?),
        trigger_sha256: trigger.sha256.clone(),
        phase: "prepared".into(),
        staging_creation_started: false,
        installation_started: false,
        ipcc_installation_completed: false,
        cleanup_completed: false,
        last_error: None,
        log_error: None,
    };
    for relative in trigger.tree.keys() {
        validate_relative_path(&format!("{}/{relative}", journal.staging_path))?;
    }
    write_journal(stage_path, &journal)?;

    // Keep all remote work in one result scope so every ordinary error attempts
    // cleanup. Cancellation still leaves the already-fsynced journal pending.
    let operation = async {
        logger.log("CarrierSIM: загрузка независимого IPCC и проверка записанных данных…");
        timeout(UPLOAD_TIMEOUT, async {
            let mut afc = tunnel.connect_afc(logger).await?;
            upload_tree(&mut afc, &trigger.tree, &directories, &mut journal, stage_path).await
        })
        .await
        .map_err(|_| "Загрузка IPCC превысила 120 секунд; требуется уборка временных файлов.".to_string())??;
        journal.phase = "uploaded".into();
        write_journal(stage_path, &journal)?;

        let installer = timeout(CONNECT_TIMEOUT, tunnel.connect_installation_proxy(logger))
            .await
            .map_err(|_| "Служба установки IPCC не ответила за 15 секунд.".to_string())?
            .map_err(|_| "Не удалось открыть службу установки IPCC.".to_string())?;

        // A ready socket exists before Install is sent. An unavailable syslog
        // service must not be confused with a failed installation.
        let (stream, log_error) = match timeout(
            Duration::from_secs(10),
            tunnel.connect_service("com.apple.syslog_relay", logger),
        )
        .await
        {
            Ok(Ok(stream)) => (Some(stream), None),
            _ => (None, Some("Журнал CommCenter недоступен; результат применения настроек не подтверждён.".to_string())),
        };
        journal.log_error = log_error.clone();
        journal.installation_started = true;
        journal.phase = "installing".into();
        write_journal(stage_path, &journal)?;
        logger.log("CarrierSIM: установка IPCC и ожидание ответа CommCenter…");
        install_and_observe(installer, stream, log_error, &mut journal, stage_path).await
    }
    .await;

    if let Err(ref error) = operation {
        journal.last_error = Some(error.clone());
    }
    let cleanup = cleanup_journal(tunnel, logger, stage_path, &mut journal).await;
    match (operation, cleanup) {
        (Ok(result), Ok(())) => Ok(result),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(format!("IPCC установлен, но временные файлы не удалось полностью убрать. Требуется восстановление. {error}")),
        (Err(error), Err(cleanup_error)) => Err(format!("{error} Требуется восстановление временных файлов. {cleanup_error}")),
    }
}

/// Idempotent cleanup of this run's unique staging directory. The caller must
/// verify its enclosing run journal belongs to the connected device first.
pub(crate) async fn recover_trigger(
    tunnel: &mut AppDeviceTunnel,
    logger: &Logger,
    stage_path: &Path,
) -> Result<(), String> {
    let mut journal = read_journal(stage_path)?;
    if journal.cleanup_completed {
        return Ok(());
    }
    cleanup_journal(tunnel, logger, stage_path, &mut journal).await?;
    if journal.installation_started {
        logger.log("CarrierSIM: временная папка IPCC убрана. Ранее отправленная установка независимого профиля этим действием не откатывается.");
    }
    Ok(())
}

/// Used by the enclosing operation scanner even when its own journal says the
/// operation is closed. Corrupt/inconsistent trigger journals return an error,
/// so they cannot silently hide pending recovery.
pub(crate) fn trigger_needs_recovery(stage_path: &Path) -> Result<bool, String> {
    Ok(!read_journal(stage_path)?.cleanup_completed)
}

fn validate_relative_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.len() > 1024
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path.chars().any(char::is_control)
    {
        return Err("IPCC содержит недопустимый путь.".into());
    }
    let parts: Vec<_> = path.split('/').collect();
    if parts.len() > 32
        || parts.iter().any(|p| p.is_empty() || *p == "." || *p == ".." || p.len() > 255)
    {
        return Err("IPCC содержит выход за пределы временной папки или слишком длинный путь.".into());
    }
    Ok(())
}

/// Parent directories are made explicitly; file/directory collisions are
/// rejected. A symlink node is treated as a regular file, including collisions.
fn validate_tree(tree: &Tree) -> Result<BTreeSet<String>, String> {
    if tree.is_empty() || tree.len() > MAX_TREE_ENTRIES {
        return Err("Пустой или слишком большой список файлов IPCC.".into());
    }
    let mut directories = BTreeSet::new();
    let mut total = 0usize;
    let mut file_count = 0usize;
    for (path, node) in tree {
        validate_relative_path(path)?;
        if path != "Payload" && !path.starts_with("Payload/") {
            return Err("IPCC содержит файлы вне Payload.".into());
        }
        if matches!(node.kind, NodeKind::Directory) {
            if !node.data.is_empty() {
                return Err("Каталог IPCC неожиданно содержит данные.".into());
            }
            directories.insert(path.clone());
        } else {
            file_count += 1;
            if path == "Payload" || node.data.len() > MAX_FILE_BYTES {
                return Err("Недопустимый размер или расположение файла IPCC.".into());
            }
            total = total.checked_add(node.data.len()).ok_or("Переполнение размера IPCC.")?;
            if total > MAX_TREE_BYTES {
                return Err("Распакованный IPCC превышает 64 МБ.".into());
            }
        }
        let mut parent = path.as_str();
        while let Some((prefix, _)) = parent.rsplit_once('/') {
            directories.insert(prefix.to_string());
            parent = prefix;
        }
    }
    if file_count == 0 || directories.len() > MAX_TREE_ENTRIES {
        return Err("IPCC не содержит файлов или содержит слишком много каталогов.".into());
    }
    for directory in &directories {
        if let Some(node) = tree.get(directory) {
            if !matches!(node.kind, NodeKind::Directory) {
                return Err("Файл или символьная ссылка IPCC использованы как родительский каталог.".into());
            }
        }
    }
    Ok(directories)
}

fn not_found(error: &IdeviceError) -> bool {
    matches!(error, IdeviceError::Afc(AfcError::ObjectNotFound))
}

async fn require_absent(afc: &mut AfcClient, path: &str) -> Result<(), String> {
    match afc.get_file_info(path).await {
        Err(error) if not_found(&error) => Ok(()),
        Ok(_) => Err("Временный путь IPCC уже занят. Существующие данные не перезаписаны.".into()),
        Err(_) => Err("Не удалось надёжно проверить отсутствие временного пути IPCC.".into()),
    }
}

async fn require_directory(afc: &mut AfcClient, path: &str) -> Result<(), String> {
    match afc.get_file_info(path).await {
        Ok(info) if info.st_ifmt == "S_IFDIR" && info.st_link_target.is_none() => Ok(()),
        Ok(_) => Err("В пути временной папки обнаружен файл или ссылка. Операция остановлена.".into()),
        Err(_) => Err("Не удалось проверить каталог временной папки IPCC.".into()),
    }
}

async fn require_ancestors(afc: &mut AfcClient, path: &str) -> Result<(), String> {
    validate_relative_path(path)?;
    let mut prefix = String::new();
    let parts: Vec<_> = path.split('/').collect();
    for part in &parts[..parts.len() - 1] {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(part);
        require_directory(afc, &prefix).await?;
    }
    Ok(())
}

async fn upload_tree(
    afc: &mut AfcClient,
    tree: &Tree,
    directories: &BTreeSet<String>,
    journal: &mut TriggerJournal,
    stage_path: &Path,
) -> Result<(), String> {
    let root = journal.staging_path.clone();
    validate_staging_path(&root)?;
    let create_parent = match afc.get_file_info(STAGING_PARENT).await {
        Ok(info) if info.st_ifmt == "S_IFDIR" && info.st_link_target.is_none() => false,
        Err(error) if not_found(&error) => true,
        _ => return Err("PublicStaging недоступен или не является обычным каталогом.".into()),
    };
    // Establish absence before recording creation intent. In particular, a
    // collision/error before this point must never trigger cleanup of somebody
    // else's existing directory.
    if !create_parent {
        require_absent(afc, &root).await?;
    }
    journal.staging_creation_started = true;
    journal.phase = "uploading".into();
    write_journal(stage_path, journal)?;
    if create_parent {
        afc.mk_dir(STAGING_PARENT).await.map_err(|_| "Не удалось создать PublicStaging.".to_string())?;
        require_directory(afc, STAGING_PARENT).await?;
    }
    if let Err(error) = afc.mk_dir(&root).await {
        if matches!(error, IdeviceError::Afc(AfcError::ObjectExists)) {
            journal.staging_creation_started = false;
            write_journal(stage_path, journal)?;
        }
        return Err("Не удалось создать уникальную временную папку IPCC.".into());
    }
    require_directory(afc, &root).await?;
    for directory in directories {
        let path = format!("{root}/{directory}");
        require_ancestors(afc, &path).await?;
        require_absent(afc, &path).await?;
        afc.mk_dir(&path).await.map_err(|_| "Не удалось создать каталог внутри IPCC.".to_string())?;
        require_directory(afc, &path).await?;
    }
    for (relative, node) in tree {
        if matches!(node.kind, NodeKind::Directory) {
            continue;
        }
        let path = format!("{root}/{relative}");
        require_ancestors(afc, &path).await?;
        require_absent(afc, &path).await?;
        // In particular, NodeKind::Symlink is NOT passed to AFC make_link.
        let mut file = afc.open(&path, AfcFopenMode::WrOnly).await.map_err(|_| "Не удалось открыть файл IPCC для записи.".to_string())?;
        let written = file.write_entire(&node.data).await;
        let closed = file.close().await;
        written.map_err(|_| "Не удалось полностью записать файл IPCC.".to_string())?;
        closed.map_err(|_| "Не удалось закрыть записанный файл IPCC.".to_string())?;
        verify_uploaded_file(afc, &path, &node.data).await?;
    }
    Ok(())
}

async fn verify_uploaded_file(
    afc: &mut AfcClient,
    path: &str,
    expected: &[u8],
) -> Result<(), String> {
    require_ancestors(afc, path).await?;
    let before = afc.get_file_info(path).await.map_err(|_| "Не удалось проверить записанный файл IPCC.".to_string())?;
    if before.st_ifmt != "S_IFREG" || before.st_link_target.is_some() || before.size != expected.len() {
        return Err("Размер или тип записанного файла IPCC не совпадает с архивом.".into());
    }
    let mut file = afc.open(path, AfcFopenMode::RdOnly).await.map_err(|_| "Не удалось открыть файл IPCC для обратной проверки.".to_string())?;
    let mut readback = vec![0u8; expected.len()];
    // AFC returns EndOfData as an error, so a len+1/read_to_end probe would
    // reject a correct file. Read exactly the stat-checked size, never issue a
    // zero-byte/EOF read, and detect concurrent growth through the second stat.
    let read = if expected.is_empty() { Ok(0) } else { file.read_exact(&mut readback).await };
    let closed = file.close().await;
    read.map_err(|_| "Не удалось полностью прочитать записанный файл IPCC.".to_string())?;
    closed.map_err(|_| "Не удалось закрыть проверяемый файл IPCC.".to_string())?;
    require_ancestors(afc, path).await?;
    let after = afc.get_file_info(path).await.map_err(|_| "Не удалось повторно проверить записанный файл IPCC.".to_string())?;
    if after.st_ifmt != "S_IFREG"
        || after.st_link_target.is_some()
        || after.size != expected.len()
        || after.modified != before.modified
        || after.creation != before.creation
    {
        return Err("Файл IPCC изменился во время обратной проверки.".into());
    }
    if readback != expected {
        return Err("Обратная проверка IPCC не пройдена: байты на iPhone отличаются от архива.".into());
    }
    Ok(())
}

struct CommCenterCapture {
    accepted: String,
    line: Vec<u8>,
    dropping_line: bool,
    log_error: Option<String>,
}

impl CommCenterCapture {
    fn new(log_error: Option<String>) -> Self {
        Self { accepted: String::new(), line: Vec::new(), dropping_line: false, log_error }
    }

    fn note_error(&mut self, message: &str) {
        if self.log_error.is_none() {
            self.log_error = Some(message.to_string());
        }
    }

    /// Returns false once the bounded CommCenter capture is full.
    fn consume(&mut self, bytes: &[u8]) -> bool {
        for &byte in bytes {
            // Syslog relay records end in LF + NUL, as in the vendored
            // SyslogRelayClient::next. LF inside a record may be a multiline
            // CommCenter message; retain the entire record once its process
            // prefix matches, just like the desktop SyslogService watcher.
            if byte == 0 {
                if !self.dropping_line && self.line.windows(b"CommCenter".len()).any(|s| s == b"CommCenter") {
                    let line = String::from_utf8_lossy(&self.line);
                    let line = line.trim_end_matches('\n');
                    if self.accepted.len() + line.len() + 1 > MAX_LOG_BYTES {
                        self.note_error("Журнал CommCenter превысил 16 МБ; проверка результата неполная.");
                        self.line.clear();
                        return false;
                    }
                    self.accepted.push_str(line);
                    self.accepted.push('\n');
                }
                self.line.clear();
                self.dropping_line = false;
            } else if byte != b'\r' && !self.dropping_line {
                if self.line.len() >= MAX_LOG_LINE {
                    self.line.clear();
                    self.dropping_line = true;
                    self.note_error("Слишком длинная строка системного журнала пропущена; проверка результата неполная.");
                } else {
                    self.line.push(byte);
                }
            }
        }
        true
    }

    fn into_result(mut self) -> TriggerResult {
        if self.accepted.is_empty() {
            self.note_error("CommCenter не вернул строки для проверки; применение настроек не подтверждено.");
        }
        TriggerResult {
            ipcc_installation_completed: true,
            commcenter_log: self.accepted,
            log_error: self.log_error,
        }
    }
}

async fn read_syslog(
    stream: &mut Option<Box<dyn ReadWrite>>,
    buffer: &mut [u8],
) -> std::io::Result<usize> {
    match stream {
        Some(stream) => stream.read(buffer).await,
        None => std::future::pending().await,
    }
}

fn installation_error(error: &IdeviceError) -> String {
    // Do not put arbitrary service output in the persistent/UI log.
    if error.to_string().contains("InstallProhibited") {
        "iPhone запретил установку IPCC (InstallProhibited). Проверьте разрешение установки приложений в Экранном времени и ограничения MDM. Отправленная установка могла изменить состояние устройства.".into()
    } else {
        "Служба Installation Proxy вернула ошибку; завершение установки IPCC не подтверждено. Состояние независимого профиля могло измениться.".into()
    }
}

async fn install_and_observe(
    mut installer: InstallationProxyClient,
    mut stream: Option<Box<dyn ReadWrite>>,
    log_error: Option<String>,
    journal: &mut TriggerJournal,
    stage_path: &Path,
) -> Result<TriggerResult, String> {
    let mut options = plist::Dictionary::new();
    options.insert("PackageType".into(), plist::Value::String("CarrierBundle".into()));
    let installation = timeout(
        INSTALL_TIMEOUT,
        installer.install(journal.staging_path.clone(), Some(plist::Value::Dictionary(options))),
    );
    tokio::pin!(installation);
    let mut capture = CommCenterCapture::new(log_error);
    let mut buffer = [0u8; 8192];
    let mut installing = true;
    let mut observe_until = Instant::now() + INSTALL_TIMEOUT + OBSERVE_AFTER_INSTALL;
    loop {
        tokio::select! {
            // The installation future stays pinned across reads. read(), unlike
            // read_exact(), is cancellation-safe when another branch wins.
            biased;
            result = &mut installation, if installing => {
                match result {
                    Ok(Ok(())) => {
                        journal.ipcc_installation_completed = true;
                        journal.phase = "installed".into();
                        write_journal(stage_path, journal)?;
                        installing = false;
                        observe_until = Instant::now() + OBSERVE_AFTER_INSTALL;
                    }
                    Ok(Err(error)) => {
                        journal.log_error = capture.log_error;
                        return Err(installation_error(&error));
                    }
                    Err(_) => {
                        journal.log_error = capture.log_error;
                        return Err("Установка IPCC не ответила за 90 секунд. Она могла продолжиться на iPhone; повторная установка автоматически не выполняется.".into());
                    }
                }
            }
            _ = tokio::time::sleep_until(observe_until), if !installing => break,
            received = read_syslog(&mut stream, &mut buffer) => {
                match received {
                    Ok(0) => {
                        capture.note_error("Поток CommCenter закрылся до конца проверки; результат неполный.");
                        stream = None;
                    }
                    Ok(size) => {
                        if !capture.consume(&buffer[..size]) {
                            stream = None;
                        }
                    }
                    Err(_) => {
                        capture.note_error("Соединение с журналом CommCenter прервалось; результат неполный.");
                        stream = None;
                    }
                }
            }
        }
    }
    let result = capture.into_result();
    journal.log_error = result.log_error.clone();
    write_journal(stage_path, journal)?;
    Ok(result)
}

fn validate_staging_path(path: &str) -> Result<(), String> {
    let token = path.strip_prefix(STAGING_PREFIX).and_then(|s| s.strip_suffix(".ipcc"));
    match token {
        Some(token) if token.len() == 32 && token.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) => Ok(()),
        _ => Err("Журнал IPCC содержит недопустимый путь уборки. Ничего по этому пути не удалено.".into()),
    }
}

fn is_descendant(root: &str, path: &str) -> bool {
    path == root || path.strip_prefix(root).is_some_and(|s| s.starts_with('/'))
}

async fn cleanup_remote(afc: &mut AfcClient, root: &str) -> Result<(), String> {
    validate_staging_path(root)?;
    match afc.get_file_info(STAGING_PARENT).await {
        Err(error) if not_found(&error) => return Ok(()),
        Ok(info) if info.st_ifmt == "S_IFDIR" && info.st_link_target.is_none() => {}
        _ => return Err("Не удалось безопасно проверить PublicStaging перед уборкой.".into()),
    }
    // Iterative postorder traversal. Each path is checked with AFC file-info;
    // symbolic links are unlinked as leaves and are never enumerated/followed.
    let mut pending = vec![(root.to_string(), false)];
    let mut visited = 0usize;
    while let Some((path, leaving)) = pending.pop() {
        if !is_descendant(root, &path) {
            return Err("Путь уборки вышел за пределы временной папки IPCC.".into());
        }
        validate_relative_path(&path)?;
        require_ancestors(afc, &path).await?;
        let info = match afc.get_file_info(&path).await {
            Ok(info) => info,
            Err(error) if not_found(&error) => continue,
            Err(_) => return Err("Не удалось проверить временный файл IPCC перед удалением.".into()),
        };
        if leaving || info.st_ifmt != "S_IFDIR" || info.st_link_target.is_some() {
            if info.st_ifmt != "S_IFREG" && info.st_ifmt != "S_IFLNK" && info.st_ifmt != "S_IFDIR" {
                return Err("Во временной папке IPCC обнаружен неизвестный тип файла; уборка остановлена.".into());
            }
            afc.remove(&path).await.map_err(|_| "Не удалось удалить временный файл или пустой каталог IPCC.".to_string())?;
        } else {
            visited += 1;
            if visited > MAX_TREE_ENTRIES * 2 {
                return Err("Слишком много каталогов для безопасной уборки IPCC.".into());
            }
            let names = afc.list_dir(&path).await.map_err(|_| "Не удалось прочитать временную папку IPCC.".to_string())?;
            if names.len() > MAX_TREE_ENTRIES * 2 || pending.len() + names.len() > MAX_TREE_ENTRIES * 3 {
                return Err("Слишком много временных файлов IPCC для безопасной уборки.".into());
            }
            pending.push((path.clone(), true));
            for name in names {
                if name == "." || name == ".." {
                    continue;
                }
                validate_relative_path(&name)?;
                if name.contains('/') {
                    return Err("AFC вернул недопустимое имя временного файла IPCC.".into());
                }
                pending.push((format!("{path}/{name}"), false));
            }
        }
    }
    match afc.get_file_info(root).await {
        Err(error) if not_found(&error) => Ok(()),
        _ => Err("Не удалось подтвердить удаление временной папки IPCC.".into()),
    }
}

async fn cleanup_journal(
    tunnel: &mut AppDeviceTunnel,
    logger: &Logger,
    stage_path: &Path,
    journal: &mut TriggerJournal,
) -> Result<(), String> {
    validate_staging_path(&journal.staging_path)?;
    if !journal.staging_creation_started {
        journal.cleanup_completed = true;
        journal.phase = "complete".into();
        write_journal(stage_path, journal)?;
        return Ok(());
    }
    journal.phase = "cleaning".into();
    write_journal(stage_path, journal)?;
    // Always open a fresh AFC connection: a timed-out upload may have left its
    // previous protocol session in the middle of a packet.
    let cleanup = timeout(CLEANUP_TIMEOUT, async {
        let mut afc = tunnel.connect_afc(logger).await.map_err(|_| "Не удалось открыть AFC для уборки IPCC.".to_string())?;
        cleanup_remote(&mut afc, &journal.staging_path).await
    })
    .await
    .map_err(|_| "Уборка IPCC превысила 120 секунд.".to_string())
    .and_then(|r| r);
    if let Err(ref error) = cleanup {
        journal.phase = "cleanup_pending".into();
        let prior = journal.last_error.take();
        journal.last_error = Some(match prior {
            Some(prior) => format!("{prior} {error}"),
            None => error.clone(),
        });
        if write_journal(stage_path, journal).is_err() {
            return Err(format!("{error} Не удалось обновить журнал; исходная запись восстановления сохранена."));
        }
        return cleanup;
    }
    journal.cleanup_completed = true;
    journal.phase = "complete".into();
    write_journal(stage_path, journal)?;
    logger.log("CarrierSIM: временные файлы IPCC удалены, удаление проверено.");
    Ok(())
}

fn random_token() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|_| "Не удалось безопасно выбрать уникальное имя временной папки.".to_string())?;
    Ok(hex::encode(bytes))
}

fn check_local_run(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(info) if info.is_dir() && !info.file_type().is_symlink() => Ok(()),
        _ => Err("Каталог запуска IPCC отсутствует или является ссылкой.".into()),
    }
}

fn write_journal(stage_path: &Path, journal: &TriggerJournal) -> Result<(), String> {
    check_local_run(stage_path)?;
    validate_staging_path(&journal.staging_path)?;
    let destination = stage_path.join(JOURNAL_NAME);
    if let Ok(info) = fs::symlink_metadata(&destination) {
        if !info.is_file() || info.file_type().is_symlink() {
            return Err("Путь журнала IPCC занят ссылкой или каталогом.".into());
        }
    }
    let temporary = stage_path.join(format!(".trigger-staging-{}.tmp", random_token()?));
    let bytes = serde_json::to_vec_pretty(journal).map_err(|_| "Не удалось сформировать журнал IPCC.".to_string())?;
    let result = (|| -> std::io::Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, &destination)?;
        File::open(stage_path)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
        return Err("Не удалось надёжно сохранить журнал IPCC. Дальнейшие действия остановлены.".into());
    }
    Ok(())
}

fn read_journal(stage_path: &Path) -> Result<TriggerJournal, String> {
    check_local_run(stage_path)?;
    let path = stage_path.join(JOURNAL_NAME);
    let metadata = fs::symlink_metadata(&path).map_err(|_| "Не найден журнал восстановления IPCC.".to_string())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 64 * 1024 {
        return Err("Журнал восстановления IPCC имеет недопустимый тип или размер.".into());
    }
    let bytes = fs::read(path).map_err(|_| "Не удалось прочитать журнал восстановления IPCC.".to_string())?;
    let journal: TriggerJournal = serde_json::from_slice(&bytes).map_err(|_| "Журнал восстановления IPCC повреждён.".to_string())?;
    validate_staging_path(&journal.staging_path)?;
    if journal.schema_version != 1
        || journal.trigger_sha256.len() != 64
        || !journal.trigger_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        || !["prepared", "uploading", "uploaded", "installing", "installed", "cleaning", "cleanup_pending", "complete"].contains(&journal.phase.as_str())
        || (journal.ipcc_installation_completed && !journal.installation_started)
        || (journal.installation_started && !journal.staging_creation_started)
        || (journal.cleanup_completed && journal.phase != "complete")
    {
        return Err("Журнал восстановления IPCC содержит противоречивые данные.".into());
    }
    Ok(journal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_own_generated_staging_paths_are_accepted() {
        let root = format!("{STAGING_PREFIX}{}.ipcc", "a9".repeat(16));
        assert!(validate_staging_path(&root).is_ok());
        for bad in ["PublicStaging", "PublicStaging/other.ipcc", "../PublicStaging/x.ipcc", "/PublicStaging/carriersim-trigger-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.ipcc", "PublicStaging/carriersim-trigger-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.ipcc/../other"] {
            assert!(validate_staging_path(bad).is_err());
        }
        assert!(is_descendant(&root, &format!("{root}/Payload/a")));
        assert!(!is_descendant(&root, &format!("{root}-other/Payload")));
    }

    #[test]
    fn relative_path_rejects_traversal_and_protocol_delimiters() {
        for bad in ["", "../x", "/x", "Payload//x", "Payload/./x", "Payload/../x", "Payload/x/", "Payload\\x", "Payload/x\0y", "Payload/x\ny"] {
            assert!(validate_relative_path(bad).is_err());
        }
        assert!(validate_relative_path("Payload/O2_Germany.bundle/Info.plist").is_ok());
    }

    #[test]
    fn commcenter_capture_is_filtered_and_never_serialized() {
        let mut capture = CommCenterCapture::new(None);
        assert!(capture.consume(b"other daemon private=123456789012345\0Com"));
        assert!(capture.consume(b"mCenter result marker\n\0"));
        let result = capture.into_result();
        assert_eq!(result.commcenter_log, "CommCenter result marker\n");
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("marker"));
        assert!(!json.contains("123456789012345"));
        assert!(!json.contains("commcenter_log"));
        assert!(!format!("{result:?}").contains("marker"));
    }

    #[test]
    fn overlong_lines_do_not_leak_suffixes_or_grow_without_bound() {
        let mut capture = CommCenterCapture::new(None);
        let mut long = vec![b'x'; MAX_LOG_LINE + 20];
        long.extend_from_slice(b"CommCenter must be discarded\n\0CommCenter next\n\0");
        assert!(capture.consume(&long));
        let result = capture.into_result();
        assert_eq!(result.commcenter_log, "CommCenter next\n");
        assert!(result.log_error.is_some());
    }

    #[test]
    fn multiline_commcenter_record_keeps_continuation_fields() {
        let mut capture = CommCenterCapture::new(None);
        capture.consume(b"CommCenter selected profile:\n CFBundleIdentifier=test\n\0other daemon\n private data\n\0");
        assert_eq!(capture.into_result().commcenter_log, "CommCenter selected profile:\n CFBundleIdentifier=test\n");
    }

    /// A real AfcClient exchanges wire packets with a bounded fake AFC server.
    /// The server implements the device's EndOfData error when a reader probes
    /// past EOF; this catches the len+1/read_to_end regression in the client.
    async fn afc_readback_fixture(
        expected: &[u8],
        actual: &[u8],
        change_mtime: bool,
    ) -> (Result<(), String>, Vec<usize>) {
        use idevice::afc::opcode::AfcOpcode;
        use idevice::afc::packet::{AfcPacket, AfcPacketHeader};
        use tokio::io::AsyncWriteExt;

        let (client_socket, mut server) = tokio::io::duplex(8192);
        let mut afc = AfcClient::new(idevice::Idevice::new(Box::new(client_socket), "trigger-test"));
        let client = async {
            let result = verify_uploaded_file(&mut afc, "fixture", expected).await;
            drop(afc);
            result
        };
        let device = async {
            let mut reads = Vec::new();
            let mut cursor = 0usize;
            let mut stats = 0usize;
            loop {
                let mut raw = [0u8; 40];
                if server.read_exact(&mut raw).await.is_err() {
                    break;
                }
                let total = u64::from_le_bytes(raw[8..16].try_into().unwrap()) as usize;
                let header_size = u64::from_le_bytes(raw[16..24].try_into().unwrap()) as usize;
                let number = u64::from_le_bytes(raw[24..32].try_into().unwrap());
                let operation = AfcOpcode::try_from(u64::from_le_bytes(raw[32..40].try_into().unwrap())).unwrap();
                assert!((40..=8192).contains(&total));
                assert!((40..=total).contains(&header_size));
                let mut request = vec![0u8; total - 40];
                server.read_exact(&mut request).await.unwrap();
                let (opcode, head, payload) = match operation {
                    AfcOpcode::GetFileInfo => {
                        stats += 1;
                        let mtime = if change_mtime && stats > 1 { 2 } else { 1 };
                        let info = format!("st_size\0{}\0st_blocks\01\0st_birthtime\01\0st_mtime\0{mtime}\0st_nlink\01\0st_ifmt\0S_IFREG\0", expected.len());
                        (AfcOpcode::Data, Vec::new(), info.into_bytes())
                    }
                    AfcOpcode::FileOpen => (AfcOpcode::FileOpenRes, 7u64.to_le_bytes().to_vec(), Vec::new()),
                    AfcOpcode::Read => {
                        let amount = u64::from_le_bytes(request[8..16].try_into().unwrap()) as usize;
                        reads.push(amount);
                        if cursor == actual.len() {
                            (AfcOpcode::Status, (AfcError::EndOfData as u64).to_le_bytes().to_vec(), Vec::new())
                        } else {
                            let end = (cursor + amount).min(actual.len());
                            let bytes = actual[cursor..end].to_vec();
                            cursor = end;
                            (AfcOpcode::Data, Vec::new(), bytes)
                        }
                    }
                    AfcOpcode::FileClose => (AfcOpcode::Status, 0u64.to_le_bytes().to_vec(), Vec::new()),
                    _ => panic!("unexpected AFC operation in readback fixture: {operation:?}"),
                };
                let reply = AfcPacket {
                    header: AfcPacketHeader {
                        magic: idevice::afc::MAGIC,
                        entire_len: (40 + head.len() + payload.len()) as u64,
                        header_payload_len: (40 + head.len()) as u64,
                        packet_num: number,
                        operation: opcode,
                    },
                    header_payload: head,
                    payload,
                };
                server.write_all(&reply.serialize()).await.unwrap();
            }
            reads
        };
        timeout(Duration::from_secs(2), async { tokio::join!(client, device) }).await.unwrap()
    }

    #[tokio::test]
    async fn readback_does_not_probe_past_afc_eof_or_read_empty_files() {
        let (normal, reads) = afc_readback_fixture(b"abc123", b"abc123", false).await;
        assert!(normal.is_ok(), "{normal:?}");
        assert_eq!(reads, vec![6]);
        let (empty, reads) = afc_readback_fixture(b"", b"", false).await;
        assert!(empty.is_ok(), "{empty:?}");
        assert!(reads.is_empty());
    }

    #[tokio::test]
    async fn readback_rejects_shrink_and_concurrent_modification() {
        let (short, _) = afc_readback_fixture(b"abc123", b"abc", false).await;
        assert!(short.is_err());
        let (changed, _) = afc_readback_fixture(b"abc123", b"abc123", true).await;
        assert!(changed.is_err());
    }
}
