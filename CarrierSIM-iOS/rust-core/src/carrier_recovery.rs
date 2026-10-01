//! Reconcile an interrupted operation's Books metadata with the CURRENT state.
//!
//! Recovery must not blindly put an old Books database over later user changes.
//! This module removes only the three exact asset identifiers belonging to one
//! journal. The caller preserves and rechecks the current snapshot before
//! applying this plan, and durably records the plan before its first write.

use std::collections::BTreeSet;
use std::ffi::{CStr, CString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use plist::Value;

use crate::carrier_data::{self as data, Node, NodeKind, Tree, MAX_BYTES};

const DB: &str = "Sync/Database/OutstandingAssets_4.sqlite";
const WAL: &str = "Sync/Database/OutstandingAssets_4.sqlite-wal";
const SHM: &str = "Sync/Database/OutstandingAssets_4.sqlite-shm";
const MANIFEST: &str = "Sync/Books.plist";
const PLISTS: [&str; 4] = ["Books.plist", "Backup-Books.plist", MANIFEST, "Sync/Upload.plist"];
const LOCKS: [&str; 2] = ["Managed/.Managed.plist.lock", "Sync/.bookSync.lock"];
const DIRECTORIES: [&str; 3] = ["Managed", "Sync", "Sync/Database"];
const OWNER_KEYS: [&str; 4] = ["Persistent ID", "PersistentID", "AssetID", "ZPERSISTENTID"];

fn owned_ids(ids: &[String]) -> Result<BTreeSet<String>, String> {
    if ids.len() != 3 { return Err("Неверное число объектов Books в журнале восстановления".into()); }
    let first = ids[0].strip_prefix("../../airlift-src-")
        .and_then(|s| s.strip_suffix("/p0/p1/p2/link"))
        .ok_or("Неверный первый объект Books в журнале")?;
    if first.len() != 20 || !first.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("Неверный идентификатор операции Books".into());
    }
    let second = format!("../../airlift-src-{first}/../../Library/Carrier Bundles/iPhone");
    let third_payload = format!("../../airlift-src-{first}/{}", data::PAYLOAD_PATH);
    let third_saved = format!("../../airlift-saved-{first}");
    if ids[1] != second || (ids[2] != third_payload && ids[2] != third_saved) {
        return Err("Объекты Books относятся к разным операциям или каталогам".into());
    }
    Ok(ids.iter().cloned().collect())
}

fn validate_books_tree(tree: &Tree) -> Result<(), String> {
    data::validate_tree(tree)?;
    for (name, node) in tree {
        let directory = DIRECTORIES.contains(&name.as_str());
        let file = PLISTS.contains(&name.as_str()) || LOCKS.contains(&name.as_str())
            || [DB, WAL, SHM].contains(&name.as_str());
        if (!directory && !file)
            || (directory && node.kind != NodeKind::Directory)
            || (file && node.kind != NodeKind::File)
        {
            return Err("В копии служебных файлов Books обнаружен посторонний путь или тип".into());
        }
    }
    Ok(())
}

fn parse_plist(node: &Node) -> Result<Value, String> {
    Value::from_reader(std::io::Cursor::new(&node.data))
        .map_err(|_| "Не удалось безопасно разобрать изменённый служебный plist Books. Копии сохранены.".into())
}

fn references_owned(value: &Value, ids: &BTreeSet<String>) -> bool {
    match value {
        Value::String(s) => ids.contains(s),
        Value::Array(values) => values.iter().any(|v| references_owned(v, ids)),
        Value::Dictionary(values) => values.iter().any(|(key, v)| ids.contains(key) || references_owned(v, ids)),
        _ => false,
    }
}

fn owner_id<'a>(value: &'a Value) -> Option<&'a str> {
    value.as_dictionary().and_then(|d| OWNER_KEYS.iter().find_map(|key| d.get(*key).and_then(Value::as_string)))
}

/// Remove entire records only when an explicit identity or dictionary key
/// exactly matches this operation. An ambiguous reference is a conflict.
fn prune(value: &Value, ids: &BTreeSet<String>, array_item: bool) -> Result<Option<Value>, String> {
    if owner_id(value).map(|id| ids.contains(id)).unwrap_or(false) { return Ok(None); }
    match value {
        Value::String(s) if ids.contains(s) => {
            if array_item { Ok(None) } else {
                Err("Неизвестная структура ссылки на объект Books; автоматическая перезапись остановлена".into())
            }
        }
        Value::Array(items) => {
            let mut result = Vec::new();
            for item in items { if let Some(item) = prune(item, ids, true)? { result.push(item); } }
            Ok(Some(Value::Array(result)))
        }
        Value::Dictionary(dict) => {
            let mut result = plist::Dictionary::new();
            for (key, value) in dict {
                if ids.contains(key) { continue; }
                if let Some(value) = prune(value, ids, false)? { result.insert(key.clone(), value); }
            }
            Ok(Some(Value::Dictionary(result)))
        }
        _ => Ok(Some(value.clone())),
    }
}

fn empty_manifest(value: &Value) -> bool {
    match value.as_dictionary() {
        Some(d) if d.len() == 1 => d.get("Books").and_then(Value::as_array).map(Vec::is_empty).unwrap_or(false),
        _ => false,
    }
}

fn encode_plist(value: &Value, binary: bool) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let result = if binary { value.to_writer_binary(&mut bytes) } else { value.to_writer_xml(&mut bytes) };
    result.map_err(|_| "Не удалось сохранить очищенный plist Books".to_string())?;
    Ok(bytes)
}

fn merge_manifest(original: Option<&Node>, current: &Node, clean: Value) -> Result<Option<Node>, String> {
    // This is the only file that CarrierSIM deliberately overwrites with a
    // synthetic manifest. If it still contains only our own records, restore
    // the original bytes exactly. Other Books files always keep current data.
    if empty_manifest(&clean) { return Ok(original.cloned()); }
    let Some(original) = original else {
        return Ok(Some(Node::file(encode_plist(&clean, current.data.starts_with(b"bplist"))?)));
    };
    let old = parse_plist(original)?;
    let old_dict = old.as_dictionary().ok_or("Исходный манифест Books имеет неизвестную структуру")?;
    let mut new_dict = clean.into_dictionary().ok_or("Новый манифест Books имеет неизвестную структуру")?;
    let old_rows = old_dict.get("Books").and_then(Value::as_array)
        .ok_or("Исходный манифест Books не содержит список Books")?;
    let new_rows = new_dict.get("Books").and_then(Value::as_array)
        .ok_or("Новый манифест Books не содержит список Books")?;
    // Keep all current records first. A newer record with the same identity
    // wins over its older version; old records lost to our overwrite return.
    let mut merged = new_rows.clone();
    let known_ids: BTreeSet<&str> = new_rows.iter().filter_map(owner_id).collect();
    for row in old_rows {
        if let Some(id) = owner_id(row) {
            if !known_ids.contains(id) { merged.push(row.clone()); }
        } else if !merged.contains(row) { merged.push(row.clone()); }
    }
    for (key, value) in old_dict {
        if key != "Books" && !new_dict.contains_key(key) { new_dict.insert(key.clone(), value.clone()); }
    }
    new_dict.insert("Books".into(), Value::Array(merged));
    Ok(Some(Node::file(encode_plist(&Value::Dictionary(new_dict), current.data.starts_with(b"bplist"))?)))
}

/// The returned tree is a recovery plan, not a claim of byte equality with the
/// old snapshot. Current unrelated user additions, deletions and metadata are
/// retained. The caller must journal this complete plan before applying it.
pub fn reconcile_books(original: &Tree, current: &Tree, asset_ids: &[String], workspace: &Path) -> Result<Tree, String> {
    validate_books_tree(original)?;
    validate_books_tree(current)?;
    let ids = owned_ids(asset_ids)?;
    let mut result = current.clone();
    for path in PLISTS {
        let Some(now) = current.get(path) else { continue; };
        if original.get(path) == Some(now) { continue; }
        let value = parse_plist(now)?;
        if !references_owned(&value, &ids) { continue; }
        let clean = prune(&value, &ids, false)?;
        let next = match clean {
            Some(clean) if path == MANIFEST => merge_manifest(original.get(path), now, clean)?,
            Some(clean) => Some(Node::file(encode_plist(&clean, now.data.starts_with(b"bplist"))?)),
            None => None,
        };
        match next {
            Some(node) => { result.insert(path.into(), node); }
            None => { result.remove(path); }
        }
    }
    if [DB, WAL, SHM].iter().any(|path| original.get(*path) != current.get(*path)) {
        if current.get(DB).is_none() {
            if current.contains_key(WAL) || current.contains_key(SHM) {
                return Err("Books содержит WAL без основной базы. Сохранены копии; частичную запись нужно восстановить по ранее сохранённому плану.".into());
            }
        } else if let Some(database) = clean_database(current, &ids, workspace)? {
            result.insert(DB.into(), Node::file(database));
            result.remove(WAL);
            result.remove(SHM);
        }
    }
    for path in LOCKS {
        if !original.contains_key(path) && matches!(result.get(path), Some(n) if n.data.is_empty()) {
            result.remove(path);
        }
    }
    // The caller also checks the actual remote directory is empty before
    // removing it, because its untracked user-book children are not in Tree.
    for path in DIRECTORIES.into_iter().rev() {
        if !original.contains_key(path) && !result.keys().any(|key| key.starts_with(&format!("{path}/"))) {
            result.remove(path);
        }
    }
    validate_books_tree(&result)?;
    Ok(result)
}

// System SQLite is present on supported iOS. No database bytes, SQL values,
// identifiers, or native error messages are included in user-visible errors.
#[repr(C)] struct Sqlite { _private: [u8; 0] }
#[repr(C)] struct SqliteStatement { _private: [u8; 0] }
type Destructor = Option<unsafe extern "C" fn(*mut std::ffi::c_void)>;

#[link(name = "sqlite3")]
extern "C" {
    fn sqlite3_open_v2(filename: *const std::ffi::c_char, db: *mut *mut Sqlite, flags: i32, vfs: *const std::ffi::c_char) -> i32;
    fn sqlite3_close_v2(db: *mut Sqlite) -> i32;
    fn sqlite3_exec(db: *mut Sqlite, sql: *const std::ffi::c_char, callback: Option<unsafe extern "C" fn(*mut std::ffi::c_void, i32, *mut *mut std::ffi::c_char, *mut *mut std::ffi::c_char) -> i32>, arg: *mut std::ffi::c_void, error: *mut *mut std::ffi::c_char) -> i32;
    fn sqlite3_prepare_v2(db: *mut Sqlite, sql: *const std::ffi::c_char, length: i32, statement: *mut *mut SqliteStatement, tail: *mut *const std::ffi::c_char) -> i32;
    fn sqlite3_finalize(statement: *mut SqliteStatement) -> i32;
    fn sqlite3_step(statement: *mut SqliteStatement) -> i32;
    fn sqlite3_column_int64(statement: *mut SqliteStatement, column: i32) -> i64;
    fn sqlite3_column_text(statement: *mut SqliteStatement, column: i32) -> *const u8;
    fn sqlite3_bind_text(statement: *mut SqliteStatement, index: i32, value: *const std::ffi::c_char, length: i32, destructor: Destructor) -> i32;
    fn sqlite3_busy_timeout(db: *mut Sqlite, ms: i32) -> i32;
}

const SQLITE_OK: i32 = 0;
const SQLITE_ROW: i32 = 100;
const SQLITE_DONE: i32 = 101;
const DB_ERROR: &str = "Не удалось безопасно очистить текущую очередь Books. Исходная и текущая копии сохранены; база не перезаписана.";

struct Database(*mut Sqlite);
impl Drop for Database { fn drop(&mut self) { unsafe { sqlite3_close_v2(self.0); } } }
struct Statement(*mut SqliteStatement);
impl Drop for Statement { fn drop(&mut self) { unsafe { sqlite3_finalize(self.0); } } }

impl Database {
    fn open(path: &Path) -> Result<Self, String> {
        let path = path.to_str().ok_or("Недопустимый путь временной копии SQLite")?;
        let path = CString::new(path).map_err(|_| DB_ERROR)?;
        let mut db = std::ptr::null_mut();
        // READWRITE | CREATE | NOMUTEX; this handle has one synchronous owner.
        let rc = unsafe { sqlite3_open_v2(path.as_ptr(), &mut db, 0x02 | 0x04 | 0x8000, std::ptr::null()) };
        if rc != SQLITE_OK || db.is_null() {
            if !db.is_null() { unsafe { sqlite3_close_v2(db); } }
            return Err(DB_ERROR.into());
        }
        let database = Self(db);
        if unsafe { sqlite3_busy_timeout(db, 1500) } != SQLITE_OK { return Err(DB_ERROR.into()); }
        Ok(database)
    }

    fn exec(&self, sql: &str) -> Result<(), String> {
        let sql = CString::new(sql).map_err(|_| DB_ERROR)?;
        let result = unsafe { sqlite3_exec(self.0, sql.as_ptr(), None, std::ptr::null_mut(), std::ptr::null_mut()) };
        if result == SQLITE_OK { Ok(()) } else { Err(DB_ERROR.into()) }
    }

    fn prepare(&self, sql: &str) -> Result<Statement, String> {
        let sql = CString::new(sql).map_err(|_| DB_ERROR)?;
        let mut statement = std::ptr::null_mut();
        let result = unsafe { sqlite3_prepare_v2(self.0, sql.as_ptr(), -1, &mut statement, std::ptr::null_mut()) };
        if result != SQLITE_OK || statement.is_null() {
            if !statement.is_null() { unsafe { sqlite3_finalize(statement); } }
            Err(DB_ERROR.into())
        } else { Ok(Statement(statement)) }
    }

    fn count(&self, sql: &str) -> Result<i64, String> {
        let statement = self.prepare(sql)?;
        if unsafe { sqlite3_step(statement.0) } != SQLITE_ROW { return Err(DB_ERROR.into()); }
        let count = unsafe { sqlite3_column_int64(statement.0, 0) };
        if unsafe { sqlite3_step(statement.0) } != SQLITE_DONE { return Err(DB_ERROR.into()); }
        Ok(count)
    }

    fn exact_id_statement(&self, sql: &str, id: &str) -> Result<i64, String> {
        let id = CString::new(id).map_err(|_| DB_ERROR)?;
        // Declared after id: the statement is finalized before its SQLITE_STATIC
        // string buffer is dropped, including every early error return.
        let statement = self.prepare(sql)?;
        if unsafe { sqlite3_bind_text(statement.0, 1, id.as_ptr(), id.as_bytes().len() as i32, None) } != SQLITE_OK {
            return Err(DB_ERROR.into());
        }
        match unsafe { sqlite3_step(statement.0) } {
            SQLITE_DONE => Ok(0),
            SQLITE_ROW => {
                let count = unsafe { sqlite3_column_int64(statement.0, 0) };
                if unsafe { sqlite3_step(statement.0) } != SQLITE_DONE { return Err(DB_ERROR.into()); }
                Ok(count)
            }
            _ => Err(DB_ERROR.into()),
        }
    }

    fn quick_check(&self) -> Result<(), String> {
        let statement = self.prepare("PRAGMA quick_check")?;
        if unsafe { sqlite3_step(statement.0) } != SQLITE_ROW { return Err(DB_ERROR.into()); }
        let result = unsafe { sqlite3_column_text(statement.0, 0) };
        if result.is_null() || unsafe { CStr::from_ptr(result.cast()).to_bytes() } != b"ok" {
            return Err(DB_ERROR.into());
        }
        if unsafe { sqlite3_step(statement.0) } != SQLITE_DONE { return Err(DB_ERROR.into()); }
        Ok(())
    }
}

struct TemporaryDatabase(PathBuf);
impl Drop for TemporaryDatabase { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new(); options.write(true).create_new(true);
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| DB_ERROR)?;
    file.write_all(bytes).and_then(|_| file.sync_all()).map_err(|_| DB_ERROR.into())
}

fn temporary_workspace(workspace: &Path) -> Result<TemporaryDatabase, String> {
    fs::create_dir_all(workspace).map_err(|_| DB_ERROR)?;
    let info = fs::symlink_metadata(workspace).map_err(|_| DB_ERROR)?;
    if !info.is_dir() || info.file_type().is_symlink() { return Err(DB_ERROR.into()); }
    let mut random = [0u8; 16];
    File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut random)).map_err(|_| DB_ERROR)?;
    let directory = workspace.join(format!("books-sqlite-{}", hex::encode(random)));
    fs::create_dir(&directory).map_err(|_| DB_ERROR)?;
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).map_err(|_| DB_ERROR)?;
    }
    Ok(TemporaryDatabase(directory))
}

/// Return None when no owned database rows exist: preserve exact current bytes.
/// SQLite works only on disposable local copies; remote access is the caller's.
fn clean_database(current: &Tree, ids: &BTreeSet<String>, workspace: &Path) -> Result<Option<Vec<u8>>, String> {
    let temporary = temporary_workspace(workspace)?;
    let path = temporary.0.join("queue.sqlite");
    write_private(&path, &current.get(DB).ok_or(DB_ERROR)?.data)?;
    if let Some(wal) = current.get(WAL) { write_private(&temporary.0.join("queue.sqlite-wal"), &wal.data)?; }
    // SHM is a process-local index, not source data. SQLite reconstructs it from
    // the copied database and WAL rather than reusing stale reader lock slots.
    let db = Database::open(&path)?;
    db.exec("PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=OFF;")?;
    db.quick_check()?;
    if db.count("SELECT COUNT(*) FROM sqlite_master WHERE type='trigger'")? != 0 {
        return Err("В очереди Books обнаружены SQL-триггеры; безопасная очистка этой схемы не поддерживается".into());
    }
    if db.count("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='ZBCOUTSTANDINGASSET' AND sql NOT LIKE 'CREATE VIRTUAL TABLE%'")? != 1 {
        return Err("Неизвестная схема очереди Books. Автоматическая перезапись базы остановлена".into());
    }
    const COUNT: &str = "SELECT COUNT(*) FROM ZBCOUTSTANDINGASSET WHERE ZPERSISTENTID COLLATE BINARY = ?1";
    const DELETE: &str = "DELETE FROM ZBCOUTSTANDINGASSET WHERE ZPERSISTENTID COLLATE BINARY = ?1";
    let mut owned = 0i64;
    for id in ids { owned = owned.checked_add(db.exact_id_statement(COUNT, id)?).ok_or(DB_ERROR)?; }
    if owned == 0 { return Ok(None); }
    let before = db.count("SELECT COUNT(*) FROM ZBCOUTSTANDINGASSET")?;
    db.exec("BEGIN IMMEDIATE")?;
    for id in ids { db.exact_id_statement(DELETE, id)?; }
    if db.count("SELECT COUNT(*) FROM ZBCOUTSTANDINGASSET")? != before - owned { return Err(DB_ERROR.into()); }
    for id in ids { if db.exact_id_statement(COUNT, id)? != 0 { return Err(DB_ERROR.into()); } }
    db.exec("COMMIT; PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;")?;
    db.quick_check()?;
    drop(db);
    let info = fs::metadata(&path).map_err(|_| DB_ERROR)?;
    if info.len() > MAX_BYTES as u64 { return Err("Очищенная база Books превышает 64 МБ".into()); }
    let bytes = fs::read(&path).map_err(|_| DB_ERROR)?;
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> Vec<String> {
        let token = "0123456789abcdefabcd";
        vec![format!("../../airlift-src-{token}/p0/p1/p2/link"),
             format!("../../airlift-src-{token}/../../Library/Carrier Bundles/iPhone"),
             format!("../../airlift-saved-{token}")]
    }

    fn manifest(ids: &[&str]) -> Node {
        let rows = ids.iter().map(|id| Value::Dictionary(plist::Dictionary::from_iter([
            ("Persistent ID", Value::String((*id).into())),
            ("Item ID", Value::String("1".into())),
        ]))).collect();
        Node::file(encode_plist(&Value::Dictionary(plist::Dictionary::from_iter([
            ("Books", Value::Array(rows)),
        ])), true).unwrap())
    }

    fn tree_with_manifest(node: Node) -> Tree {
        Tree::from([("Sync".into(), Node::directory()), (MANIFEST.into(), node)])
    }

    fn workspace() -> TemporaryDatabase {
        temporary_workspace(&std::env::temp_dir()).unwrap()
    }

    fn row_ids(node: &Node) -> Vec<String> {
        parse_plist(node).unwrap().as_dictionary().unwrap()["Books"].as_array().unwrap()
            .iter().filter_map(owner_id).map(str::to_owned).collect()
    }

    #[test]
    fn synthetic_manifest_restores_exact_original_bytes() {
        let original = tree_with_manifest(manifest(&["user-before"]));
        let own = ids();
        let current = tree_with_manifest(manifest(&own.iter().map(String::as_str).collect::<Vec<_>>()));
        assert_eq!(reconcile_books(&original, &current, &own, &workspace().0).unwrap(), original);
    }

    #[test]
    fn mixed_manifest_preserves_new_and_previous_user_rows() {
        let own = ids();
        let original = tree_with_manifest(manifest(&["user-before"]));
        let current = tree_with_manifest(manifest(&[&own[0], "user-new"]));
        let reconciled = reconcile_books(&original, &current, &own, &workspace().0).unwrap();
        assert_eq!(row_ids(&reconciled[MANIFEST]), vec!["user-new", "user-before"]);
    }

    #[test]
    fn normal_catalog_keeps_current_unrelated_additions_and_deletions() {
        let own = ids();
        let original = Tree::from([("Books.plist".into(), manifest(&["user-deleted"]))]);
        let current = Tree::from([("Books.plist".into(), manifest(&["user-new", &own[0]]))]);
        let reconciled = reconcile_books(&original, &current, &own, &workspace().0).unwrap();
        assert_eq!(row_ids(&reconciled["Books.plist"]), vec!["user-new"]);
    }

    #[test]
    fn unrelated_manifest_changes_are_not_replaced_and_only_new_empty_locks_drop() {
        let own = ids();
        let original = tree_with_manifest(manifest(&["user-old"]));
        let mut current = tree_with_manifest(manifest(&["user-new"]));
        current.insert("Sync/.bookSync.lock".into(), Node::file(vec![]));
        let result = reconcile_books(&original, &current, &own, &workspace().0).unwrap();
        assert_eq!(row_ids(&result[MANIFEST]), vec!["user-new"]);
        assert!(!result.contains_key("Sync/.bookSync.lock"));
        current.insert("Sync/.bookSync.lock".into(), Node::file(b"active-user-lock".to_vec()));
        assert!(reconcile_books(&original, &current, &own, &workspace().0).unwrap().contains_key("Sync/.bookSync.lock"));
    }

    #[test]
    fn unrelated_recovery_targets_and_ambiguous_references_are_rejected() {
        let mut own = ids(); own[1] = "../../Library/Safari".into();
        assert!(reconcile_books(&Tree::new(), &Tree::new(), &own, &workspace().0).is_err());
        let own = ids();
        let node = Node::file(encode_plist(&Value::Dictionary(plist::Dictionary::from_iter([
            ("unknownReference", Value::String(own[0].clone())),
        ])), true).unwrap());
        assert!(reconcile_books(&Tree::new(), &Tree::from([("Books.plist".into(), node)]), &own, &workspace().0).is_err());
    }

    fn db_tree(bytes: Vec<u8>, wal: Option<Vec<u8>>) -> Tree {
        let mut tree = Tree::from([("Sync".into(), Node::directory()),
            ("Sync/Database".into(), Node::directory()), (DB.into(), Node::file(bytes))]);
        if let Some(wal) = wal { tree.insert(WAL.into(), Node::file(wal)); }
        tree
    }

    #[test]
    fn sqlite_wal_cleanup_removes_exact_owned_rows_and_preserves_new_user_data() {
        let space = workspace();
        let path = space.0.join("fixture.sqlite");
        let db = Database::open(&path).unwrap();
        db.exec("CREATE TABLE ZBCOUTSTANDINGASSET(Z_PK INTEGER PRIMARY KEY,ZPERSISTENTID TEXT,ZDOWNLOADCOMPLETEPATH TEXT); CREATE TABLE Other(value TEXT); INSERT INTO Other VALUES('untouched'); INSERT INTO ZBCOUTSTANDINGASSET VALUES(1,'user-before','/old');").unwrap();
        let original = db_tree(fs::read(&path).unwrap(), None);
        db.exec("PRAGMA journal_mode=WAL; INSERT INTO ZBCOUTSTANDINGASSET VALUES(2,'user-after','/new');").unwrap();
        let own = ids();
        db.exact_id_statement("INSERT INTO ZBCOUTSTANDINGASSET(ZPERSISTENTID,ZDOWNLOADCOMPLETEPATH) VALUES(?1,'/ours')", &own[0]).unwrap();
        db.exact_id_statement("INSERT INTO ZBCOUTSTANDINGASSET(ZPERSISTENTID,ZDOWNLOADCOMPLETEPATH) VALUES(?1,'/similar-user')", &(own[0].clone() + "-not-owned")).unwrap();
        let current = db_tree(fs::read(&path).unwrap(), Some(fs::read(space.0.join("fixture.sqlite-wal")).unwrap()));
        let reconciled = reconcile_books(&original, &current, &own, &space.0).unwrap();
        assert!(!reconciled.contains_key(WAL));
        let checked_path = space.0.join("checked.sqlite");
        write_private(&checked_path, &reconciled[DB].data).unwrap();
        let checked = Database::open(&checked_path).unwrap();
        assert_eq!(checked.count("SELECT COUNT(*) FROM ZBCOUTSTANDINGASSET").unwrap(), 3);
        assert_eq!(checked.count("SELECT COUNT(*) FROM ZBCOUTSTANDINGASSET WHERE ZPERSISTENTID IN ('user-before','user-after')").unwrap(), 2);
        assert_eq!(checked.count("SELECT COUNT(*) FROM Other WHERE value='untouched'").unwrap(), 1);
        assert_eq!(checked.exact_id_statement("SELECT COUNT(*) FROM ZBCOUTSTANDINGASSET WHERE ZPERSISTENTID = ?1", &own[0]).unwrap(), 0);
    }

    #[test]
    fn sqlite_triggers_stop_recovery_before_any_original_bytes_change() {
        let space = workspace();
        let path = space.0.join("fixture.sqlite");
        let db = Database::open(&path).unwrap();
        db.exec("CREATE TABLE ZBCOUTSTANDINGASSET(ZPERSISTENTID TEXT); CREATE TABLE Other(value TEXT); CREATE TRIGGER side_effect AFTER DELETE ON ZBCOUTSTANDINGASSET BEGIN DELETE FROM Other; END;").unwrap();
        let own = ids();
        db.exact_id_statement("INSERT INTO ZBCOUTSTANDINGASSET VALUES(?1)", &own[0]).unwrap();
        drop(db);
        let bytes = fs::read(&path).unwrap();
        let current = db_tree(bytes.clone(), None);
        assert!(reconcile_books(&Tree::new(), &current, &own, &space.0).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
}
