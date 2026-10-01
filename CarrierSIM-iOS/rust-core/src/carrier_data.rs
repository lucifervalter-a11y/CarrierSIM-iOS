//! Bounded, side-effect-free CarrierSIM data handling.
//!
//! A tree stores symlink contents as bytes. It is never extracted into the app's
//! filesystem, so inspecting a backup cannot follow a link outside that backup.
//! The AirTraffic transaction is implemented separately in the carrier module.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::path::Path;

use plist::Value;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PARENT: &str = "/var/mobile/Library/Carrier Bundles";
pub const TARGET: &str = "/var/mobile/Library/Carrier Bundles/iPhone";
pub const PAYLOAD_PATH: &str = "q0/q1/q2/q3/q4/payload";
pub const SYSTEM_PREFIX: &str = "../../../../../../System/Library/Carrier Bundles/iPhone/";
pub const DEFAULT_BUNDLE: &str = "Vodafone_hu.bundle";
pub const MAX_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_NODES: usize = 4_000;
pub const MAX_DEPTH: usize = 31;
pub const ASSET_SHA256: &str = "6de1ea0be81a29c145ef414f24bc21d1dcb8a4eb737b22b1f956e9a6f0c2098b";

pub const TRIGGER_FILES: [(&str, &str); 3] = [
    ("AVEA_tr.ipcc", "bb6bf489f93da2d3ef9f8a69ce819d6b90588af8177116b7ff2c8233811c7cac"),
    ("Swisscom_ch.ipcc", "2fe320c72e85853942ba1073d80f219cdee211a0423f5d980978a492662a999f"),
    ("O2_Germany.ipcc", "5f8166b3e33d14230273b85320795f1eb1f29214d2c0594056d0b0e448c029f1"),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeKind {
    Directory,
    File,
    Symlink,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    pub kind: NodeKind,
    pub data: Vec<u8>,
}

impl Node {
    pub fn directory() -> Self {
        Self { kind: NodeKind::Directory, data: Vec::new() }
    }

    pub fn file(data: Vec<u8>) -> Self {
        Self { kind: NodeKind::File, data }
    }

    pub fn symlink(data: Vec<u8>) -> Self {
        Self { kind: NodeKind::Symlink, data }
    }
}

pub type Tree = BTreeMap<String, Node>;
pub type BundleConfig = BTreeMap<String, String>;

pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Reject any path which could change the interpretation of a tree entry.
pub fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.starts_with('/') || name.contains('\\') || name.contains('\0') {
        return Err("Недопустимый путь в каталоге или архиве".into());
    }
    let parts: Vec<&str> = name.split('/').collect();
    if parts.len() > MAX_DEPTH
        || parts.iter().any(|p| p.is_empty() || *p == "." || *p == "..")
    {
        return Err("Небезопасный или слишком глубокий путь в каталоге".into());
    }
    // ZIP filename lengths are 16-bit; this is also a useful allocation bound.
    if name.len() >= u16::MAX as usize {
        return Err("Слишком длинный путь в каталоге".into());
    }
    Ok(())
}

pub fn validate_tree(tree: &Tree) -> Result<(), String> {
    if tree.len() > MAX_NODES {
        return Err(format!("В каталоге больше {MAX_NODES} объектов"));
    }
    let mut size: usize = 0;
    for (name, node) in tree {
        validate_name(name)?;
        size = size.checked_add(node.data.len()).ok_or("Переполнение размера каталога")?;
        if size > MAX_BYTES {
            return Err("Размер каталога превышает 64 МБ".into());
        }
        match node.kind {
            NodeKind::Directory if !node.data.is_empty() => {
                return Err("У записи каталога обнаружены неожиданные данные".into());
            }
            NodeKind::Symlink if node.data.contains(&0) || node.data.len() > 4096 => {
                return Err("Повреждённая символьная ссылка".into());
            }
            _ => {}
        }
        let mut parent = name.as_str();
        while let Some((next, _)) = parent.rsplit_once('/') {
            if !matches!(tree.get(next), Some(Node { kind: NodeKind::Directory, .. })) {
                return Err("Родительский каталог отсутствует или является ссылкой".into());
            }
            parent = next;
        }
    }
    Ok(())
}

// Python json.dumps(..., sort_keys=True) uses ASCII escaping and spaces after
// separators. Keep its exact representation so native backups can be compared
// against hashes recorded by the supplied desktop program.
fn python_json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < '\u{20}' || !c.is_ascii() => {
                for unit in c.encode_utf16(&mut [0u16; 2]).iter() {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn tree_hash(tree: &Tree) -> String {
    let items: Vec<String> = tree.iter().map(|(name, node)| {
        let kind = match node.kind {
            NodeKind::Directory => "d",
            NodeKind::File => "f",
            NodeKind::Symlink => "l",
        };
        format!("{}: [\"{}\", \"{}\"]", python_json_string(name), kind, digest(&node.data))
    }).collect();
    digest(format!("{{{}}}", items.join(", ")).as_bytes())
}

fn zip_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let part = bytes.get(offset..offset.checked_add(2).ok_or("Слишком большой ZIP")?)
        .ok_or("Обрезанный заголовок ZIP")?;
    Ok(u16::from_le_bytes([part[0], part[1]]))
}

fn zip_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let part = bytes.get(offset..offset.checked_add(4).ok_or("Слишком большой ZIP")?)
        .ok_or("Обрезанный заголовок ZIP")?;
    Ok(u32::from_le_bytes([part[0], part[1], part[2], part[3]]))
}

/// zip 2.x stores parsed entries in an IndexMap keyed by filename and silently
/// coalesces duplicate names. Inspect the bounded central directory first so
/// malformed input cannot hide duplicate entries or oversized declarations.
fn preflight_zip(bytes: &[u8]) -> Result<usize, String> {
    if bytes.len() < 22 { return Err("Обрезанный ZIP".into()); }
    let search_start = bytes.len().saturating_sub(22 + u16::MAX as usize);
    let eocd = (search_start..=bytes.len() - 22).rev().find(|&i| {
        bytes[i..i + 4] == [0x50, 0x4b, 0x05, 0x06]
            && i + 22 + u16::from_le_bytes([bytes[i + 20], bytes[i + 21]]) as usize == bytes.len()
    }).ok_or("Не найден конец ZIP")?;
    let count = zip_u16(bytes, eocd + 10)? as usize;
    if zip_u16(bytes, eocd + 4)? != 0 || zip_u16(bytes, eocd + 6)? != 0
        || zip_u16(bytes, eocd + 8)? as usize != count || count > MAX_NODES
    {
        return Err("Многотомный или слишком большой ZIP не поддерживается".into());
    }
    let central_size = zip_u32(bytes, eocd + 12)? as usize;
    let central_start = zip_u32(bytes, eocd + 16)? as usize;
    if central_start.checked_add(central_size) != Some(eocd) {
        return Err("Некорректные границы центрального каталога ZIP".into());
    }
    let mut cursor = central_start;
    let mut names = BTreeSet::new();
    let mut regions = Vec::new();
    let mut total: u64 = 0;
    for _ in 0..count {
        if zip_u32(bytes, cursor)? != 0x0201_4b50 { return Err("Повреждён каталог ZIP".into()); }
        let flags = zip_u16(bytes, cursor + 8)?;
        let method = zip_u16(bytes, cursor + 10)?;
        let compressed = zip_u32(bytes, cursor + 20)? as usize;
        let declared = zip_u32(bytes, cursor + 24)? as u64;
        let name_len = zip_u16(bytes, cursor + 28)? as usize;
        let extra_len = zip_u16(bytes, cursor + 30)? as usize;
        let comment_len = zip_u16(bytes, cursor + 32)? as usize;
        if zip_u16(bytes, cursor + 34)? != 0 || flags & 1 != 0 || !matches!(method, 0 | 8) {
            return Err("Шифрованный или неподдерживаемый ZIP".into());
        }
        total = total.checked_add(declared).ok_or("Переполнение размера ZIP")?;
        if total > MAX_BYTES as u64 { return Err("Распакованный ZIP превышает 64 МБ".into()); }
        let name_start = cursor.checked_add(46).ok_or("Переполнение заголовка ZIP")?;
        let next = name_start.checked_add(name_len).and_then(|n| n.checked_add(extra_len))
            .and_then(|n| n.checked_add(comment_len)).ok_or("Переполнение заголовка ZIP")?;
        if next > eocd { return Err("Обрезанное имя ZIP".into()); }
        let name = bytes.get(name_start..name_start + name_len).ok_or("Обрезанное имя ZIP")?;
        if !names.insert(name.to_vec()) { return Err("Повторяющийся путь в ZIP".into()); }
        if flags & 0x0800 != 0 && std::str::from_utf8(name).is_err() {
            return Err("Повреждённое UTF-8 имя ZIP".into());
        }
        let local = zip_u32(bytes, cursor + 42)? as usize;
        if local >= central_start || zip_u32(bytes, local)? != 0x0403_4b50
            || zip_u16(bytes, local + 6)? != flags || zip_u16(bytes, local + 8)? != method
            || zip_u16(bytes, local + 26)? as usize != name_len
        {
            return Err("Локальный заголовок ZIP не совпал с каталогом".into());
        }
        let local_name_start = local.checked_add(30).ok_or("Переполнение заголовка ZIP")?;
        let data_start = local_name_start.checked_add(name_len)
            .and_then(|n| n.checked_add(zip_u16(bytes, local + 28).ok()? as usize))
            .ok_or("Обрезанный локальный заголовок ZIP")?;
        let data_end = data_start.checked_add(compressed).ok_or("Переполнение данных ZIP")?;
        if data_end > central_start || bytes.get(local_name_start..local_name_start + name_len) != Some(name) {
            return Err("Некорректные границы файла ZIP".into());
        }
        regions.push((local, data_end));
        cursor = next;
    }
    if cursor != eocd { return Err("Число записей ZIP не совпало с каталогом".into()); }
    regions.sort_unstable();
    if regions.windows(2).any(|w| w[0].1 > w[1].0) {
        return Err("Пересекающиеся области файлов ZIP".into());
    }
    Ok(count)
}

pub fn read_tree_zip_bytes(bytes: &[u8]) -> Result<Tree, String> {
    // A stored archive includes some path/header overhead in addition to data.
    // Larger archives cannot describe a bounded tree and need not be parsed.
    if bytes.len() > MAX_BYTES + 16 * 1024 * 1024 {
        return Err("Архив превышает допустимый размер".into());
    }
    let expected_entries = preflight_zip(bytes)?;
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| format!("Не удалось прочитать ZIP: {e}"))?;
    if zip.len() != expected_entries {
        return Err("Повторяющиеся или неоднозначные имена файлов в ZIP".into());
    }
    let mut declared: u64 = 0;
    for i in 0..zip.len() {
        let entry = zip.by_index(i).map_err(|e| format!("Повреждена запись ZIP: {e}"))?;
        declared = declared.checked_add(entry.size()).ok_or("Переполнение размера ZIP")?;
        if declared > MAX_BYTES as u64 {
            return Err("Распакованный ZIP превышает 64 МБ".into());
        }
    }
    let mut tree = Tree::new();
    let mut actual: usize = 0;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).map_err(|e| format!("Повреждена запись ZIP: {e}"))?;
        let raw_name = entry.name().to_owned();
        let name = raw_name.strip_suffix('/').unwrap_or(&raw_name).to_owned();
        validate_name(&name)?;
        if tree.contains_key(&name) {
            return Err("Повторяющийся путь в ZIP".into());
        }
        let mode = entry.unix_mode().unwrap_or(0) & 0o170000;
        let kind = match mode {
            0 if entry.is_dir() => NodeKind::Directory,
            0 | 0o100000 => NodeKind::File,
            0o040000 => NodeKind::Directory,
            0o120000 => NodeKind::Symlink,
            _ => return Err("Неподдерживаемый тип файла в ZIP".into()),
        };
        if (kind == NodeKind::Directory) != entry.is_dir() {
            return Err("Противоречивый тип каталога в ZIP".into());
        }
        let expected = entry.size();
        let budget = MAX_BYTES - actual;
        let mut data = Vec::new();
        (&mut entry).take(budget as u64 + 1).read_to_end(&mut data)
            .map_err(|e| format!("Не удалось проверить содержимое ZIP: {e}"))?;
        if data.len() > budget || data.len() as u64 != expected {
            return Err("Фактический размер ZIP не совпал с заголовком".into());
        }
        actual += data.len();
        tree.insert(name, Node { kind, data });
    }
    validate_tree(&tree)?;
    Ok(tree)
}

pub fn read_tree_zip(path: &Path) -> Result<Tree, String> {
    let file = File::open(path).map_err(|e| format!("Не удалось открыть копию: {e}"))?;
    let mut bytes = Vec::new();
    file.take((MAX_BYTES + 16 * 1024 * 1024 + 1) as u64).read_to_end(&mut bytes)
        .map_err(|e| format!("Не удалось прочитать копию: {e}"))?;
    read_tree_zip_bytes(&bytes)
}

fn le16(out: &mut Vec<u8>, value: u16) { out.extend_from_slice(&value.to_le_bytes()); }
fn le32(out: &mut Vec<u8>, value: u32) { out.extend_from_slice(&value.to_le_bytes()); }

fn crc32(bytes: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, slot) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 { c = if c & 1 != 0 { 0xedb8_8320 ^ (c >> 1) } else { c >> 1 }; }
        *slot = c;
    }
    let mut crc = 0xffff_ffffu32;
    for &byte in bytes { crc = table[((crc ^ byte as u32) & 255) as usize] ^ (crc >> 8); }
    !crc
}

/// Write the small, stored ZIP subset used by the desktop program. Writing the
/// headers explicitly preserves arbitrary symlink bytes and UNIX file types;
/// ordinary archive extraction and follow-link filesystem APIs are not used.
fn zip_bytes(tree: &Tree, streaming: bool) -> Result<Vec<u8>, String> {
    validate_tree(tree)?;
    let mut out = Vec::new();
    let mut central = Vec::new();
    const DOS_DATE: u16 = ((2026 - 1980) << 9) | (9 << 5) | 24;
    for (name, node) in tree {
        let encoded_name = if node.kind == NodeKind::Directory { format!("{name}/") } else { name.clone() };
        let filename = encoded_name.as_bytes();
        let filename_len = u16::try_from(filename.len()).map_err(|_| "Слишком длинное имя ZIP")?;
        let flags: u16 = if filename.is_ascii() { 0 } else { 0x0800 };
        let mode: u32 = match node.kind {
            NodeKind::Directory => 0o040755,
            NodeKind::File => 0o100644,
            NodeKind::Symlink => 0o120777,
        };
        let mut extra = Vec::new();
        if streaming { le16(&mut extra, 0x5a53); le16(&mut extra, 2); le16(&mut extra, mode as u16); }
        let offset = u32::try_from(out.len()).map_err(|_| "Слишком большой ZIP")?;
        let size = u32::try_from(node.data.len()).map_err(|_| "Слишком большой файл ZIP")?;
        let crc = crc32(&node.data);

        le32(&mut out, 0x0403_4b50);
        le16(&mut out, 20); le16(&mut out, flags); le16(&mut out, 0);
        le16(&mut out, 0); le16(&mut out, DOS_DATE);
        le32(&mut out, crc); le32(&mut out, size); le32(&mut out, size);
        le16(&mut out, filename_len); le16(&mut out, extra.len() as u16);
        out.extend_from_slice(filename); out.extend_from_slice(&extra); out.extend_from_slice(&node.data);

        le32(&mut central, 0x0201_4b50);
        le16(&mut central, (3 << 8) | 20); le16(&mut central, 20);
        le16(&mut central, flags); le16(&mut central, 0); le16(&mut central, 0); le16(&mut central, DOS_DATE);
        le32(&mut central, crc); le32(&mut central, size); le32(&mut central, size);
        le16(&mut central, filename_len); le16(&mut central, extra.len() as u16); le16(&mut central, 0);
        le16(&mut central, 0); le16(&mut central, 0); le32(&mut central, mode << 16); le32(&mut central, offset);
        central.extend_from_slice(filename); central.extend_from_slice(&extra);
    }
    let offset = u32::try_from(out.len()).map_err(|_| "Слишком большой ZIP")?;
    let central_size = u32::try_from(central.len()).map_err(|_| "Слишком большой каталог ZIP")?;
    out.extend_from_slice(&central);
    le32(&mut out, 0x0605_4b50); le16(&mut out, 0); le16(&mut out, 0);
    le16(&mut out, tree.len() as u16); le16(&mut out, tree.len() as u16);
    le32(&mut out, central_size); le32(&mut out, offset); le16(&mut out, 0);
    Ok(out)
}

pub fn tree_zip_bytes(tree: &Tree) -> Result<Vec<u8>, String> {
    zip_bytes(tree, false)
}

/// A backup is created exclusively and synced before returning. An existing
/// backup is never silently replaced by a later attempt.
pub fn write_tree_zip(path: &Path, tree: &Tree) -> Result<(), String> {
    let bytes = tree_zip_bytes(tree)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| format!("Не удалось создать резервную копию: {e}"))?;
    file.write_all(&bytes).and_then(|_| file.sync_all())
        .map_err(|e| format!("Не удалось сохранить резервную копию: {e}"))
}

fn directories(tree: &mut Tree, path: &str) -> Result<(), String> {
    validate_name(path)?;
    let mut cursor = String::new();
    for part in path.split('/') {
        if !cursor.is_empty() { cursor.push('/'); }
        cursor.push_str(part);
        match tree.get(&cursor) {
            Some(Node { kind: NodeKind::Directory, .. }) => {}
            Some(_) => return Err("Путь каталога пересекается с файлом или ссылкой".into()),
            None => { tree.insert(cursor.clone(), Node::directory()); }
        }
    }
    Ok(())
}

pub fn staging_archive(payload: Option<&Tree>) -> Result<Vec<u8>, String> {
    let mut tree = Tree::new();
    directories(&mut tree, "META-INF")?;
    let mut metadata = plist::Dictionary::new();
    metadata.insert("Version".into(), Value::Integer(2.into()));
    let mut metadata_bytes = Vec::new();
    Value::Dictionary(metadata).to_writer_binary(&mut metadata_bytes)
        .map_err(|e| format!("Не удалось подготовить метаданные: {e}"))?;
    tree.insert("META-INF/com.apple.ZipMetadata.plist".into(), Node::file(metadata_bytes));
    directories(&mut tree, "p0/p1/p2")?;
    tree.insert("p0/p1/p2/link".into(), Node::symlink(format!("../../../{}", PARENT.trim_start_matches('/')).into_bytes()));
    directories(&mut tree, PARENT.trim_start_matches('/'))?;
    if let Some(payload) = payload {
        validate_tree(payload)?;
        directories(&mut tree, PAYLOAD_PATH)?;
        let mut system_names = BTreeSet::from([DEFAULT_BUNDLE.to_owned()]);
        for node in payload.values().filter(|n| n.kind == NodeKind::Symlink) {
            if node.data.starts_with(SYSTEM_PREFIX.as_bytes()) {
                let tail = std::str::from_utf8(&node.data[SYSTEM_PREFIX.len()..])
                    .map_err(|_| "Неожиданное имя системной ссылки")?;
                if normalize_bundle(tail)? != tail {
                    return Err("Неожиданная системная ссылка".into());
                }
                system_names.insert(tail.to_owned());
            }
        }
        for name in system_names {
            directories(&mut tree, &format!("System/Library/Carrier Bundles/iPhone/{name}"))?;
        }
        for (name, node) in payload {
            tree.insert(format!("{PAYLOAD_PATH}/{name}"), node.clone());
        }
    }
    // Staging adds a small fixed scaffold. A maximum-sized original tree must
    // still be representable; never silently drop nodes to satisfy the limit.
    if tree.len() > MAX_NODES {
        return Err("Каталог слишком велик для безопасного промежуточного архива".into());
    }
    zip_bytes(&tree, true)
}

fn ascii_digits(value: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_digit())
}

pub fn normalize_bundle(input: &str) -> Result<String, String> {
    let input = input.trim();
    let name = input.strip_suffix(".bundle").unwrap_or(input);
    if name.is_empty() || name.len() > 120 || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Err("Имя профиля должно содержать только латинские буквы, цифры и знак _".into());
    }
    Ok(format!("{name}.bundle"))
}

fn unquote(value: &str) -> Result<&str, String> {
    if let Some(first) = value.chars().next() {
        if first == '\'' || first == '"' {
            if value.len() < 2 || !value.ends_with(first) {
                return Err("Незакрытые кавычки в настройках профиля".into());
            }
            return Ok(&value[1..value.len() - 1]);
        }
    }
    if value.ends_with('\'') || value.ends_with('"') {
        return Err("Лишняя кавычка в настройках профиля".into());
    }
    Ok(value)
}

/// The same deliberately small YAML subset as the original bundle.yaml.
pub fn parse_bundle_config(text: &str) -> Result<BundleConfig, String> {
    if text.len() > 64 * 1024 { return Err("Слишком большой файл настроек".into()); }
    let mut result = BundleConfig::new();
    for (i, line) in text.trim_start_matches('\u{feff}').lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() { continue; }
        let (key, value) = line.split_once(':').ok_or_else(|| format!("Строка {}: ожидается ключ: профиль", i + 1))?;
        let key = unquote(key.trim())?;
        if key != "default" && !ascii_digits(key, 5, 6) {
            return Err(format!("Строка {}: неверный MCCMNC", i + 1));
        }
        let bundle = normalize_bundle(unquote(value.trim())?)?;
        if result.insert(key.to_owned(), bundle).is_some() {
            return Err(format!("Строка {}: ключ указан дважды", i + 1));
        }
    }
    result.entry("default".into()).or_insert_with(|| DEFAULT_BUNDLE.into());
    Ok(result)
}

/// Full identities stay inside the transaction code; only PublicSim is
/// serializable, so a status response cannot accidentally expose the full IMSI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sim {
    pub slot: String,
    pub mcc: String,
    pub mnc: String,
    pub imsi: String,
    pub bundle: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicSim {
    pub slot: String,
    pub mcc: String,
    pub mnc: String,
    pub plmn: String,
    pub imsi_tail: String,
    pub bundle: String,
}

impl Sim {
    pub fn plmn(&self) -> String { format!("{}{}", self.mcc, self.mnc) }

    pub fn public(&self) -> PublicSim {
        let tail = if self.imsi.len() >= 4 && self.imsi.is_ascii() {
            self.imsi[self.imsi.len() - 4..].to_owned()
        } else { String::new() };
        PublicSim {
            slot: self.slot.clone(), mcc: self.mcc.clone(), mnc: self.mnc.clone(),
            plmn: self.plmn(), imsi_tail: tail, bundle: self.bundle.clone(),
        }
    }
}

fn row_text(row: &plist::Dictionary, key: &str) -> String {
    match row.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Integer(n)) => n.as_unsigned().map(|n| n.to_string()).unwrap_or_default(),
        _ => String::new(),
    }
}

fn validate_sim(sim: &Sim) -> Result<(), String> {
    if !matches!(sim.slot.as_str(), "kOne" | "kTwo") {
        return Err("Неизвестный слот SIM".into());
    }
    if !ascii_digits(&sim.mcc, 3, 3) || !ascii_digits(&sim.mnc, 2, 3)
        || !ascii_digits(&sim.imsi, 15, 15) || !sim.imsi.starts_with(&sim.plmn())
    {
        return Err("iPhone не сообщил корректный полный IMSI. Включите линию и разблокируйте телефон".into());
    }
    if normalize_bundle(&sim.bundle)? != sim.bundle {
        return Err("Неоднозначное имя профиля".into());
    }
    Ok(())
}

pub fn select_sims(rows: &Value, slots: &[&str], config: &BundleConfig) -> Result<Vec<Sim>, String> {
    if slots.is_empty() || slots.len() > 2
        || slots.iter().any(|s| !matches!(*s, "kOne" | "kTwo"))
        || slots.iter().copied().collect::<BTreeSet<_>>().len() != slots.len()
    {
        return Err("Неверный выбор слотов SIM".into());
    }
    let rows = rows.as_array().ok_or("iPhone не сообщил список SIM")?;
    let mut seen_slots = BTreeSet::new();
    let mut seen_imsi = BTreeSet::new();
    let mut selected = Vec::new();
    for row in rows {
        let row = row.as_dictionary().ok_or("Неожиданный формат сведений о SIM")?;
        let slot = row_text(row, "Slot");
        if !matches!(slot.as_str(), "kOne" | "kTwo") || !seen_slots.insert(slot.clone()) {
            return Err("Неоднозначные слоты SIM; запись отменена".into());
        }
        if !slots.contains(&slot.as_str()) { continue; }
        let mcc = row_text(row, "MCC");
        let mnc = row_text(row, "MNC");
        // IMSI is deliberately not coerced from a number: leading zeros matter.
        let imsi = row.get("InternationalMobileSubscriberIdentity").and_then(Value::as_string)
            .ok_or("iPhone не сообщил полный IMSI выбранной SIM")?.to_owned();
        let plmn = format!("{mcc}{mnc}");
        let bundle = normalize_bundle(config.get(&plmn).or_else(|| config.get("default"))
            .map(String::as_str).unwrap_or(DEFAULT_BUNDLE))?;
        let sim = Sim { slot, mcc, mnc, imsi, bundle };
        validate_sim(&sim)?;
        if !seen_imsi.insert(sim.imsi.clone()) {
            return Err("Один IMSI указан в двух слотах; запись отменена".into());
        }
        selected.push(sim);
    }
    if selected.is_empty() || (slots.len() == 1 && !seen_slots.contains(slots[0])) {
        return Err("Выбранная SIM не найдена или недоступна".into());
    }
    // A stable slot order makes comparison independent of response ordering.
    selected.sort_by(|a, b| a.slot.cmp(&b.slot));
    Ok(selected)
}

pub fn make_plan(original: &Tree, sims: &[Sim]) -> Result<Tree, String> {
    validate_tree(original)?;
    if sims.is_empty() { return Err("Не выбрана SIM для изменения профиля".into()); }
    let mut desired = original.clone();
    let mut slots = BTreeSet::new();
    let mut imsis = BTreeSet::new();
    for sim in sims {
        validate_sim(sim)?;
        if !slots.insert(&sim.slot) || !imsis.insert(&sim.imsi) {
            return Err("Повторяющийся слот или IMSI в плане".into());
        }
        if matches!(original.get(&sim.imsi), Some(n) if n.kind != NodeKind::Symlink) {
            return Err("Вместо ссылки IMSI обнаружен файл или каталог; запись отменена".into());
        }
        desired.insert(sim.imsi.clone(), Node::symlink(format!("{SYSTEM_PREFIX}{}", sim.bundle).into_bytes()));
    }
    validate_tree(&desired)?;
    Ok(desired)
}

pub fn remove_imsi_links(original: &Tree) -> Result<Tree, String> {
    validate_tree(original)?;
    let result = original.iter().filter(|(name, node)| !(node.kind == NodeKind::Symlink && ascii_digits(name, 15, 15)))
        .map(|(name, node)| (name.clone(), node.clone())).collect();
    validate_tree(&result)?;
    Ok(result)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub product_type: String,
    pub hardware_model: String,
    pub product_version: String,
    pub build_version: String,
    pub activation_state: String,
    /// Only the original desktop source reports physical testing on these builds.
    pub original_tested_build: bool,
}

pub fn validate_device_info(info: &plist::Dictionary) -> Result<DeviceInfo, String> {
    let get = |key: &str| -> Result<String, String> {
        let text = info.get(key).and_then(Value::as_string).ok_or_else(|| format!("iPhone не сообщил {key}"))?;
        if text.is_empty() || text.len() > 128 || text.contains('\0') {
            return Err(format!("Некорректное значение {key}"));
        }
        Ok(text.to_owned())
    };
    let mut result = DeviceInfo {
        product_type: get("ProductType")?, hardware_model: get("HardwareModel")?,
        product_version: get("ProductVersion")?, build_version: get("BuildVersion")?,
        activation_state: get("ActivationState")?, original_tested_build: false,
    };
    if !result.product_type.starts_with("iPhone") { return Err("Поддерживается только iPhone".into()); }
    if result.activation_state != "Activated" { return Err("iPhone не активирован".into()); }
    result.original_tested_build = result.product_version == "27.0"
        && matches!(result.build_version.as_str(), "24A435" | "24A437");
    Ok(result)
}

pub fn validate_target(target: &str) -> Result<(), String> {
    if target != TARGET { return Err("Копия относится к другому системному каталогу".into()); }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct Trigger {
    pub filename: String,
    pub bundle: String,
    pub version: String,
    pub sha256: String,
    pub bytes: Vec<u8>,
    pub tree: Tree,
    pub supported_sims: Vec<String>,
    pub hardware_supported: bool,
}

pub fn load_assets_bytes(bytes: &[u8]) -> Result<Tree, String> {
    if digest(bytes) != ASSET_SHA256 {
        return Err("Встроенный архив assets.zip повреждён или заменён".into());
    }
    let assets = read_tree_zip_bytes(bytes)?;
    for (filename, expected) in TRIGGER_FILES {
        let node = assets.get(&format!("triggers/{filename}"))
            .ok_or("В архиве нет необходимого IPCC")?;
        if node.kind != NodeKind::File || digest(&node.data) != expected {
            return Err("Встроенный IPCC повреждён или заменён".into());
        }
    }
    Ok(assets)
}

pub fn load_assets(path: &Path) -> Result<Tree, String> {
    let file = File::open(path).map_err(|e| format!("Не удалось открыть встроенные профили: {e}"))?;
    let mut bytes = Vec::new();
    file.take(2 * 1024 * 1024).read_to_end(&mut bytes).map_err(|e| format!("Не удалось прочитать профили: {e}"))?;
    load_assets_bytes(&bytes)
}

fn plist_dictionary_file(tree: &Tree, path: &str) -> Result<plist::Dictionary, String> {
    let node = tree.get(path).ok_or_else(|| format!("В IPCC отсутствует {path}"))?;
    if node.kind != NodeKind::File { return Err("Вместо файла метаданных IPCC обнаружена ссылка".into()); }
    Value::from_reader(Cursor::new(&node.data)).map_err(|e| format!("Повреждён plist IPCC: {e}"))?
        .into_dictionary().ok_or_else(|| "Неверный формат plist IPCC".into())
}

fn supported_sim_identifier(identifier: &str) -> bool {
    let base = identifier.split_once('_').map(|(base, _)| base).unwrap_or(identifier);
    ascii_digits(base, 5, 6)
}

pub fn check_trigger(bytes: &[u8], plmns: &[String], targets: &[String], hardware: &str) -> Result<Trigger, String> {
    let tree = read_tree_zip_bytes(bytes)?;
    let bundles: BTreeSet<&str> = tree.keys().filter_map(|name| {
        let mut parts = name.split('/');
        if parts.next() != Some("Payload") { return None; }
        parts.next().filter(|n| n.ends_with(".bundle"))
    }).collect();
    if bundles.len() != 1 { return Err("IPCC должен содержать ровно один пакет оператора".into()); }
    let bundle = bundles.iter().next().ok_or("В IPCC нет пакета")?.to_string();
    if normalize_bundle(&bundle)? != bundle { return Err("Неверное имя пакета IPCC".into()); }
    if targets.iter().any(|target| target.eq_ignore_ascii_case(&bundle)) {
        return Err("Триггер совпадает с выбранным профилем".into());
    }
    let prefix = format!("Payload/{bundle}");
    let info = plist_dictionary_file(&tree, &format!("{prefix}/Info.plist"))?;
    let carrier = plist_dictionary_file(&tree, &format!("{prefix}/carrier.plist"))?;
    if info.get("CFBundleIdentifier").and_then(Value::as_string) == Some("com.apple.Viva_kw") {
        return Err("Viva не является независимым триггером".into());
    }
    // Presence only. Cryptographic carrier signature verification is performed
    // by iOS; only its observed CommCenter result can confirm acceptance.
    if !tree.iter().any(|(name, node)| name.starts_with(&format!("{prefix}/signatures/")) && node.kind == NodeKind::File) {
        return Err("В IPCC отсутствуют файлы подписей".into());
    }
    let sims = carrier.get("SupportedSIMs").and_then(Value::as_array)
        .filter(|a| !a.is_empty()).ok_or("В IPCC нет корректного SupportedSIMs")?;
    let mut affected = BTreeSet::new();
    for sim in sims {
        let sim = sim.as_string().filter(|s| supported_sim_identifier(s)).ok_or("Неожиданный формат SupportedSIMs")?;
        affected.insert(sim.to_owned());
    }
    for (name, node) in &tree {
        if node.kind == NodeKind::Symlink {
            let leaf = name.rsplit('/').next().ok_or("Неверная ссылка IPCC")?;
            if !supported_sim_identifier(leaf) { return Err("Неожиданная ссылка в IPCC".into()); }
            affected.insert(leaf.to_owned());
        }
    }
    if plmns.iter().any(|p| !ascii_digits(p, 5, 6)) {
        return Err("Не удалось проверить пересечение триггера со всеми SIM".into());
    }
    if affected.iter().any(|a| plmns.iter().any(|p| a == p || a.starts_with(&format!("{p}_")))) {
        return Err("Триггер пересекается с активной SIM".into());
    }
    let board = hardware.to_ascii_uppercase();
    let board = board.strip_suffix("AP").unwrap_or(&board);
    let hardware_supported = !board.is_empty() && tree.iter().any(|(name, node)| {
        if node.kind != NodeKind::File || name.contains("/signatures/") { return false; }
        let Some((directory, leaf)) = name.rsplit_once('/') else { return false; };
        let Some(boards) = leaf.strip_prefix("overrides_").and_then(|s| s.strip_suffix(".plist")) else { return false; };
        boards.split('_').any(|b| b.eq_ignore_ascii_case(board))
            && matches!(tree.get(&format!("{directory}/signatures/{leaf}")), Some(Node { kind: NodeKind::File, .. }))
    });
    let version = info.get("CFBundleVersion").and_then(Value::as_string)
        .ok_or("В IPCC нет версии пакета")?.to_owned();
    Ok(Trigger {
        filename: String::new(), bundle, version, sha256: digest(bytes), bytes: bytes.to_vec(),
        tree, supported_sims: affected.into_iter().collect(), hardware_supported,
    })
}

pub fn choose_trigger(assets: &Tree, plmns: &[String], targets: &[String], hardware: &str) -> Result<Trigger, String> {
    validate_tree(assets)?;
    for (filename, expected) in TRIGGER_FILES {
        let node = assets.get(&format!("triggers/{filename}")).ok_or("Нет встроенного IPCC")?;
        if node.kind != NodeKind::File || digest(&node.data) != expected {
            return Err("Встроенный IPCC повреждён или заменён".into());
        }
        if let Ok(mut trigger) = check_trigger(&node.data, plmns, targets, hardware) {
            trigger.filename = filename.to_owned();
            return Ok(trigger);
        }
    }
    Err("Не найден независимый триггер для этих SIM и выбранных профилей".into())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CarrierResult {
    pub slot: String,
    pub plmn: String,
    pub expected: String,
    pub selected: Option<String>,
    pub verified: bool,
}

fn log_field<'a>(block: &'a str, field: &str) -> Vec<&'a str> {
    block.lines().filter_map(|line| {
        let (_, remainder) = line.split_once(field)?;
        remainder.trim_start().strip_prefix(':').map(str::trim)
    }).collect()
}

/// Parse only complete, unambiguous CommCenter records. Missing logs or an
/// observed profile without an explicit Success stay unconfirmed.
pub fn report_log(text: &str, sims: &[Sim]) -> Vec<CarrierResult> {
    let mut result: Vec<CarrierResult> = sims.iter().map(|sim| CarrierResult {
        slot: sim.slot.clone(), plmn: sim.plmn(), expected: sim.bundle.clone(), selected: None, verified: false,
    }).collect();
    for block in text.split("----------Bundle File----------") {
        let resolved = log_field(block, "Resolved path");
        let linked = log_field(block, "Linking Path");
        let verified = log_field(block, "Verification Result");
        if resolved.len() != 1 || linked.len() != 1 { continue; }
        for row in &mut result {
            let leaf = match row.slot.as_str() { "kOne" => "/Carrier1Bundle.bundle", "kTwo" => "/Carrier2Bundle.bundle", _ => continue };
            if linked[0].ends_with(leaf) {
                row.selected = resolved[0].rsplit('/').next().filter(|s| !s.is_empty()).map(str::to_owned);
                row.verified = verified == ["Success"];
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tree() -> Tree {
        Tree::from([
            ("a".into(), Node::directory()),
            ("a/file".into(), Node::file(b"preserve me".to_vec())),
            ("a/.hidden".into(), Node::file(vec![0, 255, 1])),
            ("25001".into(), Node::symlink(b"/System/Library/Carrier Bundles/iPhone/Original.bundle".to_vec())),
        ])
    }

    fn sim() -> Sim {
        Sim { slot: "kOne".into(), mcc: "250".into(), mnc: "01".into(), imsi: "250011234567890".into(), bundle: DEFAULT_BUNDLE.into() }
    }

    fn rows(sims: &[Sim]) -> Value {
        Value::Array(sims.iter().map(|s| {
            Value::Dictionary(plist::Dictionary::from_iter([
                ("Slot", Value::String(s.slot.clone())),
                ("MCC", Value::String(s.mcc.clone())),
                ("MNC", Value::String(s.mnc.clone())),
                ("InternationalMobileSubscriberIdentity", Value::String(s.imsi.clone())),
            ]))
        }).collect())
    }

    #[test]
    fn backup_roundtrip_preserves_types_links_hidden_files_and_non_ascii() {
        let mut tree = sample_tree();
        tree.insert("a/имя😀".into(), Node::file(vec![1, 2, 3]));
        tree.insert("bytes-link".into(), Node::symlink(vec![b'.', b'/', 0xff]));
        assert_eq!(read_tree_zip_bytes(&tree_zip_bytes(&tree).unwrap()).unwrap(), tree);
    }

    #[test]
    fn paths_cannot_escape_or_traverse_links() {
        for path in ["", "/abs", "a//b", "a/../b", "a/./b", "a\\b", "x\0y"] {
            assert!(validate_name(path).is_err(), "{path:?}");
        }
        let tree = Tree::from([("parent".into(), Node::symlink(b"/tmp".to_vec())), ("parent/child".into(), Node::file(vec![]))]);
        assert!(validate_tree(&tree).is_err());
    }

    #[test]
    fn missing_parent_and_invalid_symlink_are_rejected() {
        assert!(validate_tree(&Tree::from([("a/file".into(), Node::file(vec![]))])).is_err());
        assert!(validate_tree(&Tree::from([("link".into(), Node::symlink(vec![0]))])).is_err());
        assert!(validate_tree(&Tree::from([("link".into(), Node::symlink(vec![b'x'; 4097]))])).is_err());
    }

    #[test]
    fn limits_reject_large_counts_depth_and_data() {
        let tree: Tree = (0..=MAX_NODES).map(|i| (format!("f{i}"), Node::file(Vec::new()))).collect();
        assert!(validate_tree(&tree).is_err());
        assert!(validate_name(&vec!["x"; MAX_DEPTH + 1].join("/")).is_err());
        assert!(validate_tree(&Tree::from([("huge".into(), Node::file(vec![0; MAX_BYTES + 1]))])).is_err());
    }

    #[test]
    fn duplicate_zip_entries_are_rejected() {
        let mut bytes = tree_zip_bytes(&Tree::from([("first".into(), Node::file(vec![])), ("other".into(), Node::file(vec![]))])).unwrap();
        // Both names have equal lengths; rewrite local and central names to
        // produce a real duplicate archive independently of the ZIP writer.
        for i in 0..=bytes.len() - 5 {
            if &bytes[i..i + 5] == b"other" { bytes[i..i + 5].copy_from_slice(b"first"); }
        }
        assert!(read_tree_zip_bytes(&bytes).is_err());
    }

    #[test]
    fn corrupt_zip_crc_is_rejected() {
        let mut bytes = tree_zip_bytes(&Tree::from([("file".into(), Node::file(b"unique payload".to_vec()))])).unwrap();
        let offset = bytes.windows(14).position(|w| w == b"unique payload").unwrap();
        bytes[offset] ^= 1;
        assert!(read_tree_zip_bytes(&bytes).is_err());
    }

    #[test]
    fn crc_uses_standard_zip_polynomial() { assert_eq!(crc32(b"123456789"), 0xcbf4_3926); }

    #[test]
    fn tree_hash_matches_desktop_python_and_unicode_escaping() {
        assert_eq!(tree_hash(&Tree::new()), "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a");
        let tree = Tree::from([
            ("a".into(), Node::directory()),
            ("a/имя😀".into(), Node::file(b"hello".to_vec())),
            ("25001".into(), Node::symlink(b"../../System".to_vec())),
        ]);
        assert_eq!(tree_hash(&tree), "2b5b456b471b4cdf3a5c0ca356fb4a9a48f8cb2d7a5bdecba11ab4fd5d75c6bc");
    }

    #[test]
    fn staging_preserves_payload_and_contains_safe_resolution_scaffold() {
        let payload = make_plan(&sample_tree(), &[sim()]).unwrap();
        let raw = staging_archive(Some(&payload)).unwrap();
        // Produced independently with the supplied Python program's documented
        // ZIP geometry, modes, timestamps and binary plist serialization.
        assert_eq!(digest(&tree_zip_bytes(&payload).unwrap()), "c6415b42bf7ace5516a2df37981244b45de0e40b741160757f9b325e1a7c6604");
        assert_eq!(digest(&raw), "680caa2219bca320625af8883054ab721571d96998b7ff4ab1995ee37a84e75d");
        let tree = read_tree_zip_bytes(&raw).unwrap();
        assert_eq!(tree["p0/p1/p2/link"], Node::symlink(format!("../../../{}", PARENT.trim_start_matches('/')).into_bytes()));
        assert_eq!(tree["System/Library/Carrier Bundles/iPhone/Vodafone_hu.bundle"].kind, NodeKind::Directory);
        for (name, node) in &payload { assert_eq!(&tree[&format!("{PAYLOAD_PATH}/{name}")], node); }
        let mut zip = zip::ZipArchive::new(Cursor::new(&raw)).unwrap();
        let link = zip.by_name(&format!("{PAYLOAD_PATH}/{}", sim().imsi)).unwrap();
        assert_eq!(link.unix_mode().unwrap() & 0o170000, 0o120000);
        assert!(link.extra_data().unwrap().windows(4).any(|w| w == [0x53, 0x5a, 2, 0]));
    }

    #[test]
    fn staged_system_links_must_name_one_bundle() {
        let payload = Tree::from([("x".into(), Node::symlink(format!("{SYSTEM_PREFIX}../escape").into_bytes()))]);
        assert!(staging_archive(Some(&payload)).is_err());
    }

    #[test]
    fn plan_changes_only_selected_imsi_and_refuses_file_collision() {
        let before = sample_tree();
        let after = make_plan(&before, &[sim()]).unwrap();
        for (name, node) in &before { assert_eq!(&after[name], node); }
        assert_eq!(after.len(), before.len() + 1);
        let mut before = before;
        before.insert(sim().imsi, Node::file(b"must not overwrite".to_vec()));
        assert!(make_plan(&before, &[sim()]).is_err());
    }

    #[test]
    fn restore_removes_only_root_imsi_symlinks() {
        let mut original = sample_tree();
        original.insert(sim().imsi.clone(), Node::symlink(b"target".to_vec()));
        original.insert(format!("a/{}", sim().imsi), Node::symlink(b"nested".to_vec()));
        original.insert("999999999999999".into(), Node::file(b"keep".to_vec()));
        let restored = remove_imsi_links(&original).unwrap();
        assert!(!restored.contains_key(&sim().imsi));
        assert!(restored.contains_key("25001"));
        assert!(restored.contains_key("999999999999999"));
        assert!(restored.contains_key(&format!("a/{}", sim().imsi)));
    }

    #[test]
    fn sims_require_complete_identifiers_and_correct_prefix() {
        for imsi in ["", "25001123456789", "2500112345678901", "25001123456789x", "999991234567890"] {
            let mut bad = sim(); bad.imsi = imsi.into();
            assert!(select_sims(&rows(&[bad]), &["kOne"], &BundleConfig::new()).is_err());
        }
        assert_eq!(select_sims(&rows(&[sim()]), &["kOne", "kTwo"], &BundleConfig::new()).unwrap(), vec![sim()]);
        assert!(select_sims(&rows(&[sim()]), &["kTwo"], &BundleConfig::new()).is_err());
    }

    #[test]
    fn duplicate_slot_and_imsi_and_invalid_selection_are_rejected() {
        assert!(select_sims(&rows(&[sim(), sim()]), &["kOne"], &BundleConfig::new()).is_err());
        let mut second = sim(); second.slot = "kTwo".into();
        assert!(select_sims(&rows(&[sim(), second]), &["kOne", "kTwo"], &BundleConfig::new()).is_err());
        assert!(select_sims(&rows(&[sim()]), &["kOne", "kOne"], &BundleConfig::new()).is_err());
    }

    #[test]
    fn profile_names_cannot_escape_fixed_system_directory() {
        for name in ["", "../x", "x/y", "x\\y", "/tmp/a", "x.bundle/../b", "x.bundle.bundle", "привет", "x;cmd"] {
            assert!(normalize_bundle(name).is_err(), "{name}");
        }
        assert_eq!(normalize_bundle("O2_Germany").unwrap(), "O2_Germany.bundle");
        assert!(validate_target("/var/mobile/Library").is_err());
        assert!(validate_target("/var/mobile/Library/Carrier Bundles/iPhone/../iPhone").is_err());
        assert!(validate_target(TARGET).is_ok());
    }

    #[test]
    fn yaml_subset_preserves_leading_zero_network_and_rejects_duplicates() {
        let config = parse_bundle_config("\u{feff}# comment\ndefault: Vodafone_hu\n'00101': 'O2_Germany.bundle' # x\n").unwrap();
        assert_eq!(config["00101"], "O2_Germany.bundle");
        assert!(parse_bundle_config("default: A\ndefault: B").is_err());
        assert!(parse_bundle_config("default: '../bad'").is_err());
        assert!(parse_bundle_config("'default: A").is_err());
    }

    #[test]
    fn public_sim_does_not_serialize_complete_imsi() {
        let json = serde_json::to_string(&sim().public()).unwrap();
        assert!(!json.contains(&sim().imsi));
        assert!(json.contains("7890"));
    }

    #[test]
    fn bundled_assets_and_trigger_exclusions_match_original() {
        let raw = include_bytes!("../../Resources/assets.zip");
        let assets = load_assets_bytes(raw).unwrap();
        let first = choose_trigger(&assets, &["25001".into()], &[DEFAULT_BUNDLE.into()], "V57AP").unwrap();
        assert_eq!(first.filename, "AVEA_tr.ipcc");
        let second = choose_trigger(&assets, &["28603".into()], &[DEFAULT_BUNDLE.into()], "V57AP").unwrap();
        assert_eq!(second.filename, "Swisscom_ch.ipcc");
        let third = choose_trigger(&assets, &["28604".into(), "22801".into()], &[DEFAULT_BUNDLE.into()], "V57AP").unwrap();
        assert_eq!(third.filename, "O2_Germany.ipcc");
        assert!(choose_trigger(&assets, &["28603".into(), "22801".into()], &["O2_Germany.bundle".into()], "V57AP").is_err());
        let mut corrupted = raw.to_vec(); corrupted[10] ^= 1;
        assert!(load_assets_bytes(&corrupted).is_err());
    }

    #[test]
    fn missing_or_ambiguous_logs_do_not_confirm_signature() {
        assert_eq!(report_log("", &[sim()])[0].verified, false);
        let good = "----------Bundle File----------\nResolved path : /System/Library/Carrier Bundles/iPhone/Vodafone_hu.bundle\nLinking Path : /var/mobile/Library/Carrier1Bundle.bundle\nVerification Result : Success\n";
        let result = report_log(good, &[sim()]);
        assert_eq!(result[0].selected.as_deref(), Some(DEFAULT_BUNDLE));
        assert!(result[0].verified);
        assert!(!report_log(&good.replace("Success", "Failure"), &[sim()])[0].verified);
        let ambiguous = format!("{good}Resolved path : /different.bundle\n");
        assert!(!report_log(&ambiguous, &[sim()])[0].verified);
    }
}
