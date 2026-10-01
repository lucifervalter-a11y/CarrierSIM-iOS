//! CarrierSIM's bounded, recoverable carrier catalogue transaction.
//!
//! The only destination outside AFC Media is TARGET. A transaction exports the
//! existing directory, durably saves it, checks the frozen device/SIM binding,
//! and only then authorizes the final FileComplete. A successful placement is
//! deliberately distinct from an independent read-back and a CommCenter
//! signature/selection confirmation. No failed write is retried automatically.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{c_char, c_void};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use idevice::afc::{errors::AfcError, opcode::AfcFopenMode, AfcClient, FileInfo};
use idevice::lockdown::LockdownClient;
use idevice::{IdeviceError, IdeviceService, ReadWrite};
use plist::{Dictionary, Value as Plist};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::carrier_data::{self as data, BundleConfig, Node, NodeKind, Sim, Tree, MAX_BYTES,
    MAX_NODES, PARENT, PAYLOAD_PATH, TARGET};
use crate::carrier_trigger;
use crate::exploit::{self, AppDeviceTunnel, Logger, ALLogCallback};

type Result<T> = std::result::Result<T, String>;

#[derive(Default)]
struct FailureContext { device_hash: Option<String>, operation: Option<PathBuf> }

const BOOK_DIRS: &[&str] = &["Books", "Books/Managed", "Books/Sync", "Books/Sync/Database"];
const BOOK_FILES: &[&str] = &[
    "Books/Books.plist", "Books/Backup-Books.plist", "Books/Sync/Books.plist", "Books/Sync/Upload.plist",
    "Books/Sync/Database/OutstandingAssets_4.sqlite",
    "Books/Sync/Database/OutstandingAssets_4.sqlite-shm",
    "Books/Sync/Database/OutstandingAssets_4.sqlite-wal",
];
const BOOK_LOCKS: &[&str] = &["Books/Managed/.Managed.plist.lock", "Books/Sync/.bookSync.lock"];
const IO_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    action: String,
    #[serde(default)]
    target: Option<crate::device_target::DeviceTarget>,
    #[serde(default)]
    expected_device_hash: Option<String>,
    #[serde(default = "default_bundle")]
    bundle: String,
    #[serde(default = "default_slots")]
    slots: Vec<String>,
}
fn default_bundle() -> String { "Vodafone_hu".into() }
fn default_slots() -> Vec<String> { vec!["kOne".into(), "kTwo".into()] }

#[derive(Clone)]
pub(crate) struct Device {
    pub(crate) udid_hash: String,
    name: String,
    model: String,
    hardware: String,
    pub(crate) ios: String,
    build: String,
    activation: String,
    rows: Plist,
}

impl Device {
    pub(crate) fn public(&self) -> Value {
        json!({"identity_hash":self.udid_hash,"name":self.name,"model":self.model,"hardware":self.hardware,
               "ios":self.ios,"build":self.build,"activated":self.activation=="Activated"})
    }
    // Only hash identity fields, not the currently selected carrier profile,
    // which is expected to change during the independent rescan.
    fn sim_binding(&self) -> String {
        let mut rows: Vec<Vec<String>> = self.rows.as_array().into_iter().flatten().map(|v| {
            ["Slot", "MCC", "MNC", "InternationalMobileSubscriberIdentity"].iter()
                .map(|k| v.as_dictionary().and_then(|d| d.get(*k)).map(plist_string).unwrap_or_default())
                .collect()
        }).collect();
        rows.sort();
        data::digest(&serde_json::to_vec(&rows).unwrap_or_default())
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct BooksState { existed: bool, hash: String, top: Vec<String> }

#[derive(Clone, Serialize, Deserialize)]
struct BooksRepair {
    schema: u32,
    udid_hash: String,
    source: String,
    original_hash: String,
    before_hash: String,
    desired_hash: String,
    existed: bool,
    phase: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct Journal {
    schema: u32,
    udid_hash: String,
    target: String,
    source: String,
    link: String,
    exported: String,
    phase: String,
    complete: bool,
    requires_recovery: bool,
    books_restored: bool,
    original_hash: Option<String>,
    payload_hash: Option<String>,
    recovery: bool,
    recovered: bool,
    error: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Operation {
    schema: u32,
    udid_hash: String,
    target: String,
    action: String,
    bundle: String,
    slots: Vec<String>,
    sim_binding: String,
    closed: bool,
    catalog_verified: bool,
    commcenter_verified: bool,
    original_hash: Option<String>,
    desired_hash: Option<String>,
    /// An unrelated live catalogue observed during recovery must survive.
    /// Recovery may restore this exact tree, never the older requested payload.
    #[serde(default)]
    preserved_hash: Option<String>,
    recovered: bool,
}

pub(crate) struct OpLock(File);
impl OpLock {
    pub(crate) fn acquire(root: &Path) -> Result<Self> {
        private_dir(root)?;
        let f = OpenOptions::new().create(true).read(true).write(true).mode(0o600)
            .open(root.join("operation.lock")).map_err(|e| format!("Журнал недоступен: {e}"))?;
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("Другая операция уже выполняется. Дождитесь её окончания.".into());
        }
        Ok(Self(f))
    }
}
impl Drop for OpLock { fn drop(&mut self) { unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN); } } }

fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|e| format!("Не удалось создать журнал: {e}"))?;
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    ensure(meta.is_dir() && !meta.file_type().is_symlink(), "Каталог журнала имеет неверный тип")?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())
}
fn random_token(bytes: usize) -> Result<String> {
    let mut b=vec![0;bytes];
    File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b))
        .map_err(|e| format!("Генератор случайных идентификаторов недоступен: {e}"))?;
    Ok(hex::encode(b))
}
fn sync_parent(path: &Path) -> Result<()> {
    if let Some(p)=path.parent() {
        File::open(p).and_then(|f| f.sync_all()).map_err(|e| format!("Не сохранён каталог журнала: {e}"))?;
    }
    Ok(())
}
fn atomic_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent=path.parent().ok_or("Не задан каталог файла")?;
    private_dir(parent)?;
    let temp=parent.join(format!(".write-{}",random_token(10)?));
    let mut file=OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temp)
        .map_err(|e| format!("Не сохранён файл журнала: {e}"))?;
    let result=(|| {
        file.write_all(bytes).and_then(|_| file.sync_all()).map_err(|e| e.to_string())?;
        fs::rename(&temp,path).map_err(|e|e.to_string())?;
        sync_parent(path)
    })();
    if result.is_err() { let _=fs::remove_file(&temp); }
    result
}
fn save_json<T: Serialize>(path:&Path,value:&T)->Result<()> {
    atomic_bytes(path,&serde_json::to_vec_pretty(value).map_err(|e|e.to_string())?)
}
fn load_json<T: for<'de> Deserialize<'de>>(path:&Path)->Result<T> {
    let meta=fs::symlink_metadata(path).map_err(|e| format!("Резервная копия недоступна: {e}"))?;
    ensure(meta.is_file() && !meta.file_type().is_symlink() && meta.len()<2*1024*1024,
           "Неверный файл журнала")?;
    serde_json::from_slice(&fs::read(path).map_err(|e|e.to_string())?).map_err(|e|format!("Журнал повреждён: {e}"))
}
fn save_tree(path:&Path,tree:&Tree)->Result<()> { atomic_bytes(path,&data::tree_zip_bytes(tree)?) }
fn preserved_backup(op:&Path,hash:&str)->Result<PathBuf> {
    ensure(hash.len()==64&&hash.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)),
           "Неверная контрольная сумма сохранённого каталога")?;
    Ok(op.join(format!("recovery-preserved-{hash}.zip")))
}
fn store_preserved(op:&Path,tree:&Tree)->Result<String> {
    let hash=data::tree_hash(tree);let path=preserved_backup(op,&hash)?;
    if path.exists(){
        ensure(data::tree_hash(&data::read_tree_zip(&path)?)==hash,"Сохранённая копия новых настроек повреждена")?;
    }else{save_tree(&path,tree)?;}
    // The operation pointer is updated only after this immutable file is
    // fsynced. Older hashes continue to name their intact copies after a crash.
    Ok(hash)
}
fn ensure(ok:bool,message:&str)->Result<()> { if ok {Ok(())} else {Err(message.into())} }
fn redact(text:&str)->String {
    // IMSI, ICCID, serial-like digit strings and account identifiers never enter
    // logs or error JSON. Tree/Books archives remain private recovery material.
    let mut out=String::new(); let mut digits=String::new();
    for c in text.chars().chain(std::iter::once('\0')) {
        if c.is_ascii_digit() { digits.push(c); continue; }
        if !digits.is_empty() { if digits.len()>=10 {out.push_str("[скрыто]");} else {out.push_str(&digits);} digits.clear(); }
        if c!='\0' {out.push(c);}
    }
    out
}
fn plist_string(v:&Plist)->String {
    match v { Plist::String(s)=>s.clone(), Plist::Integer(i)=>i.as_unsigned().map(|n|n.to_string()).unwrap_or_default(), _=>String::new() }
}

pub(crate) async fn lockdown(tunnel:&mut AppDeviceTunnel)->Result<LockdownClient> {
    match tunnel {
        AppDeviceTunnel::Rsd{adapter,handshake}=>handshake.connect::<LockdownClient>(adapter).await
            .map_err(|e|format!("Lockdown по защищённому туннелю недоступен: {e}")),
        AppDeviceTunnel::Lockdown{provider,pairing_file,..}=> {
            let mut client=LockdownClient::connect(provider).await.map_err(|e|e.to_string())?;
            client.start_session(pairing_file).await.map_err(|e|e.to_string())?;
            Ok(client)
        }
    }
}
async fn identity_from_lockdown(ld:&mut LockdownClient)->Result<Device> {
        let mut values=BTreeMap::new();
        for key in ["UniqueDeviceID","DeviceName","ProductType","HardwareModel","ProductVersion","BuildVersion","ActivationState"] {
            values.insert(key,plist_string(&ld.get_value(Some(key),None).await
                .map_err(|e|format!("iPhone не сообщил {key}: {e}"))?));
        }
        let udid=values.get("UniqueDeviceID").cloned().unwrap_or_default();
        ensure(!udid.is_empty(),"Не удалось определить iPhone; запись запрещена")?;
        Ok(Device{udid_hash:data::digest(udid.as_bytes()),name:values["DeviceName"].clone(),
            model:values["ProductType"].clone(),hardware:values["HardwareModel"].clone(),
            ios:values["ProductVersion"].clone(),build:values["BuildVersion"].clone(),
            activation:values["ActivationState"].clone(),rows:Plist::Array(vec![])})
}
pub(crate) async fn device_identity(tunnel:&mut AppDeviceTunnel)->Result<Device> {
    tokio::time::timeout(IO_TIMEOUT,async {
        let mut ld=lockdown(tunnel).await?;
        identity_from_lockdown(&mut ld).await
    }).await.map_err(|_|"iPhone не ответил при чтении сведений".to_string())?
}
pub(crate) async fn device_info(tunnel:&mut AppDeviceTunnel)->Result<Device> {
    tokio::time::timeout(IO_TIMEOUT,async {
        let mut ld=lockdown(tunnel).await?;
        let mut device=identity_from_lockdown(&mut ld).await?;
        device.rows=ld.get_value(Some("CarrierBundleInfoArray"),None).await
            .map_err(|e|format!("Сведения о SIM недоступны: {e}"))?;
        ensure(device.rows.as_array().is_some(),"iPhone вернул неверные сведения о SIM")?;
        Ok(device)
    }).await.map_err(|_|"iPhone не ответил при чтении сведений".to_string())?
}
async fn require_binding(tunnel:&mut AppDeviceTunnel,frozen:&Device,check_sims:bool)->Result<()> {
    let current=device_info(tunnel).await?;
    ensure(current.udid_hash==frozen.udid_hash,"Подключён другой iPhone; запись отменена")?;
    if check_sims {ensure(current.sim_binding()==frozen.sim_binding(),"SIM изменились во время операции. Запись отменена; выполните восстановление.")?;}
    Ok(())
}

async fn stat(afc:&mut AfcClient,path:&str)->Result<Option<FileInfo>> {
    match tokio::time::timeout(IO_TIMEOUT,afc.get_file_info(path)).await {
        Ok(Ok(v))=>Ok(Some(v)),
        Ok(Err(IdeviceError::Afc(AfcError::ObjectNotFound)))=>Ok(None),
        Ok(Err(e))=>Err(format!("Не удалось проверить объект AFC: {e}")),
        Err(_)=>Err("AFC не ответил при проверке файла".into()),
    }
}
fn same_stat(a:&FileInfo,b:&FileInfo)->bool {
    a.size==b.size && a.blocks==b.blocks && a.creation==b.creation && a.modified==b.modified
        && a.st_nlink==b.st_nlink && a.st_ifmt==b.st_ifmt && a.st_link_target==b.st_link_target
}
async fn children(afc:&mut AfcClient,path:&str)->Result<Vec<String>> {
    let raw=tokio::time::timeout(IO_TIMEOUT,afc.list_dir(path)).await
        .map_err(|_|"AFC не ответил при чтении каталога".to_string())?
        .map_err(|e|format!("Каталог AFC недоступен: {e}"))?;
    let mut names=Vec::new();
    for name in raw { if name=="."||name==".." {continue;}
        ensure(!name.is_empty()&&!name.contains('/')&&!name.contains('\\')&&!name.contains('\0'),"Неверное имя объекта AFC")?;
        names.push(name);
    }
    names.sort();
    ensure(names.windows(2).all(|w|w[0]!=w[1]),"AFC вернул повторяющиеся имена")?;
    Ok(names)
}
async fn read_file(afc:&mut AfcClient,path:&str,expected:usize)->Result<Vec<u8>> {
    ensure(expected<=MAX_BYTES,"Файл превышает допустимый размер")?;
    let before=stat(afc,path).await?.ok_or("Файл исчез до чтения")?;
    ensure(before.st_ifmt=="S_IFREG"&&before.size==expected,"Размер или тип файла изменился до чтения")?;
    let bytes=tokio::time::timeout(IO_TIMEOUT,async {
        let mut fd=afc.open(path,AfcFopenMode::RdOnly).await.map_err(|e|e.to_string())?;
        // Never ask AFC past known EOF: EndOfData is exposed as an I/O error,
        // not EOF, by the vendor client. read_exact is bounded, and stat on both
        // sides detects truncation, appended bytes, replacement and mtime edits.
        let mut bytes=vec![0;expected];
        let result=if expected==0 {Ok(0)}else{fd.read_exact(&mut bytes).await};
        let close=fd.close().await;
        result.map_err(|e|e.to_string())?; close.map_err(|e|e.to_string())?;
        Ok::<Vec<u8>,String>(bytes)
    }).await.map_err(|_|"AFC не ответил при чтении файла".to_string())??;
    let after=stat(afc,path).await?.ok_or("Файл исчез после чтения")?;
    ensure(same_stat(&before,&after),"Файл изменился во время чтения")?;
    Ok(bytes)
}
async fn write_file(afc:&mut AfcClient,path:&str,bytes:&[u8])->Result<()> {
    if let Some(before)=stat(afc,path).await? {ensure(before.st_ifmt=="S_IFREG","Вместо файла найден другой объект; запись остановлена")?;}
    tokio::time::timeout(IO_TIMEOUT,async {
        let mut fd=afc.open(path,AfcFopenMode::WrOnly).await.map_err(|e|e.to_string())?;
        let result=fd.write_entire(bytes).await; let close=fd.close().await;
        result.map_err(|e|e.to_string())?; close.map_err(|e|e.to_string())?;
        Ok::<(),String>(())
    }).await.map_err(|_|"AFC не ответил при записи файла".to_string())??;
    ensure(read_file(afc,path,bytes.len()).await?==bytes,"Обратное чтение файла не совпало")
}
async fn mkdirs(afc:&mut AfcClient,path:&str)->Result<()> {
    let mut cursor=String::new();
    for name in path.split('/') {
        ensure(!name.is_empty()&&name!="."&&name!="..","Неверный служебный путь")?;
        if !cursor.is_empty(){cursor.push('/');}cursor.push_str(name);
        match stat(afc,&cursor).await? {
            Some(s)=>ensure(s.st_ifmt=="S_IFDIR","Служебный каталог имеет неверный тип")?,
            None=>tokio::time::timeout(IO_TIMEOUT,afc.mk_dir(&cursor)).await
                .map_err(|_|"AFC не ответил при создании каталога".to_string())?.map_err(|e|e.to_string())?,
        }
    }
    Ok(())
}

fn visit<'a>(afc:&'a mut AfcClient,path:String,name:String,depth:usize,tree:&'a mut Tree,total:&'a mut usize)
    -> std::pin::Pin<Box<dyn std::future::Future<Output=Result<()>>+'a>> {
    Box::pin(async move {
        ensure(depth<32&&tree.len()<MAX_NODES,"Каталог превышает лимит вложенности или количества файлов")?;
        let before=stat(afc,&path).await?.ok_or("Объект исчез во время чтения")?;
        match before.st_ifmt.as_str() {
            "S_IFDIR"=> {
                if !name.is_empty(){tree.insert(name.clone(),Node::directory());}
                let list=children(afc,&path).await?;
                for child in &list {
                    let next=if name.is_empty(){child.clone()}else{format!("{name}/{child}")};
                    visit(afc,format!("{path}/{child}"),next,depth+1,tree,total).await?;
                }
                ensure(children(afc,&path).await?==list,"Содержимое каталога изменилось во время чтения")?;
            },
            "S_IFREG"=> {
                ensure(!name.is_empty(),"Корень каталога оказался файлом")?;
                ensure(before.size<=MAX_BYTES && *total<=MAX_BYTES-before.size,"Каталог превышает лимит размера")?;
                let bytes=read_file(afc,&path,before.size).await?;
                *total+=bytes.len();tree.insert(name,Node::file(bytes));
            },
            "S_IFLNK"=> {
                ensure(!name.is_empty(),"Корень каталога оказался символической ссылкой")?;
                let target=before.st_link_target.clone().ok_or("AFC не сообщил адрес символической ссылки")?;
                ensure(target.len()<=4096&&!target.contains('\0'),"Неверная символическая ссылка")?;
                *total+=target.len();ensure(*total<=MAX_BYTES,"Каталог превышает лимит размера")?;
                tree.insert(name,Node::symlink(target.into_bytes()));
            },
            _=>return Err("Неподдерживаемый тип файла; оригинал сохранён".into()),
        }
        let after=stat(afc,&path).await?.ok_or("Объект исчез во время чтения")?;
        ensure(same_stat(&before,&after),"Файл или каталог изменился во время чтения")
    })
}
async fn remote_tree(afc:&mut AfcClient,path:&str)->Result<Tree> {
    let mut tree=Tree::new();let mut total=0;
    visit(afc,path.into(),String::new(),0,&mut tree,&mut total).await?;
    data::validate_tree(&tree)?;Ok(tree)
}
fn remove_node<'a>(afc:&'a mut AfcClient,path:String,depth:usize)
    ->std::pin::Pin<Box<dyn std::future::Future<Output=Result<()>>+'a>> {
    Box::pin(async move {
        ensure(depth<32,"Слишком глубокий служебный каталог")?;
        let Some(node)=stat(afc,&path).await? else{return Ok(())};
        // AFC GetFileInfo is lstat: never descend through symbolic links.
        if node.st_ifmt=="S_IFDIR" {
            for child in children(afc,&path).await? {remove_node(afc,format!("{path}/{child}"),depth+1).await?;}
        }
        tokio::time::timeout(IO_TIMEOUT,afc.remove(path)).await
            .map_err(|_|"AFC не ответил при удалении служебного объекта".to_string())?
            .map_err(|e|e.to_string())
    })
}

async fn read_books(afc:&mut AfcClient)->Result<(bool,Tree)> {
    let Some(root)=stat(afc,"Books").await? else{return Ok((false,Tree::new()))};
    ensure(root.st_ifmt=="S_IFDIR","Books имеет неверный тип")?;
    let mut tree=Tree::new();let mut total=0usize;
    for path in &BOOK_DIRS[1..] {if let Some(s)=stat(afc,path).await? {
        ensure(s.st_ifmt=="S_IFDIR","Служебная папка Books имеет неверный тип")?;
        tree.insert(path.trim_start_matches("Books/").into(),Node::directory());
    }}
    for path in BOOK_FILES.iter().chain(BOOK_LOCKS.iter()) {if let Some(s)=stat(afc,path).await? {
        ensure(s.st_ifmt=="S_IFREG","Служебный файл Books имеет неверный тип")?;
        ensure(s.size<=MAX_BYTES&&total<=MAX_BYTES-s.size,"Служебные файлы Books превышают лимит резервной копии")?;
        total+=s.size;
        let bytes=read_file(afc,path,s.size).await?;
        let after=stat(afc,path).await?.ok_or("Служебный файл Books исчез")?;
        ensure(same_stat(&s,&after),"Books изменились во время чтения")?;
        tree.insert(path.trim_start_matches("Books/").into(),Node::file(bytes));
    }}
    data::validate_tree(&tree)?;Ok((true,tree))
}
async fn snapshot_books(afc:&mut AfcClient,path:&Path)->Result<(BooksState,Tree)> {
    let mut previous=read_books(afc).await?;let mut stable=false;
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let current=read_books(afc).await?;
        if current==previous {stable=true;break;}previous=current;
    }
    ensure(stable,"Служебные файлы Books постоянно меняются. Закройте «Книги» и дождитесь окончания загрузок.")?;
    let (existed,tree)=previous;
    let state=BooksState{existed,hash:data::tree_hash(&tree),top:if existed{children(afc,"Books").await?}else{vec![]}};
    save_tree(&path.join("books.zip"),&tree)?;save_json(&path.join("books.json"),&state)?;
    Ok((state,tree))
}
async fn restore_books(afc:&mut AfcClient,state:&BooksState,tree:&Tree)->Result<()> {
    ensure(data::tree_hash(tree)==state.hash,"Резервная копия Books повреждена")?;
    for path in BOOK_FILES {
        let current=stat(afc,path).await?;
        ensure(current.as_ref().map(|s|s.st_ifmt=="S_IFREG").unwrap_or(true),"Служебные файлы Books изменили тип; копия сохранена")?;
        if let Some(node)=tree.get(path.trim_start_matches("Books/")) {
            ensure(node.kind==NodeKind::File,"Неверная резервная копия Books")?;
            mkdirs(afc,path.rsplit_once('/').unwrap().0).await?;write_file(afc,path,&node.data).await?;
        }else if current.is_some(){afc.remove(*path).await.map_err(|e|e.to_string())?;}
    }
    for path in BOOK_LOCKS {
        if let Some(node)=tree.get(path.trim_start_matches("Books/")) {
            if let Some(current)=stat(afc,path).await? {
                ensure(current.st_ifmt=="S_IFREG"&&read_file(afc,path,current.size).await?==node.data,
                       "Исходный lock-файл Books изменился; копия сохранена")?;
            }else{
                mkdirs(afc,path.rsplit_once('/').unwrap().0).await?;write_file(afc,path,&node.data).await?;
            }
        }else if let Some(s)=stat(afc,path).await? {
            ensure(s.st_ifmt=="S_IFREG"&&s.size==0,"Books создало непустой lock-файл; копия сохранена")?;
            afc.remove(*path).await.map_err(|e|e.to_string())?;
        }
    }
    for path in &BOOK_DIRS[1..] {if tree.contains_key(path.trim_start_matches("Books/")){mkdirs(afc,path).await?;}}
    for path in BOOK_DIRS.iter().rev() {
        let was_present=if *path=="Books"{state.existed}else{tree.contains_key(path.trim_start_matches("Books/"))};
        if !was_present && stat(afc,path).await?.is_some() && children(afc,path).await?.is_empty(){
            afc.remove(*path).await.map_err(|e|e.to_string())?;
        }
    }
    let (_,after)=read_books(afc).await?;
    ensure(after==*tree,"Не удалось точно восстановить служебные файлы Books. Используйте «Восстановить после сбоя».")
}

fn stage_asset_ids(j:&Journal)->Vec<String> {
    let final_source=if j.payload_hash.is_some(){format!("{}/{PAYLOAD_PATH}",j.source)}else{j.exported.clone()};
    vec![format!("../../{}/p0/p1/p2/link",j.source),
        format!("../../{}/../../{}",j.source,TARGET.trim_start_matches("/var/mobile/")),
        format!("../../{final_source}")]
}

fn interrupted_books_match(before:&Tree,desired:&Tree,current:&Tree)->bool {
    // Each managed object must still be either its saved pre-write value or
    // its intended value. A third value may contain unrelated new Books data;
    // never overwrite it by resuming a stale multi-file plan.
    let names:BTreeSet<&String>=before.keys().chain(desired.keys()).chain(current.keys()).collect();
    names.into_iter().all(|name|current.get(name)==before.get(name)||current.get(name)==desired.get(name))
}

async fn recover_books(afc:&mut AfcClient,stage:&Path,j:&Journal,original_state:&BooksState,original:&Tree)->Result<()> {
    ensure(data::tree_hash(original)==original_state.hash,"Копия Books повреждена")?;
    let repair_path=stage.join("books-repair");private_dir(&repair_path)?;
    let journal_path=repair_path.join("repair.json");
    let (observed_state,observed)=snapshot_books(afc,&repair_path.join(format!("observed-{}",random_token(5)?))).await?;
    let mut existing=if journal_path.exists(){Some(load_json::<BooksRepair>(&journal_path)?)}else{None};
    if let Some(record)=&existing {
        ensure(record.schema==1&&record.udid_hash==j.udid_hash&&record.source==j.source
            &&record.original_hash==original_state.hash,"Журнал восстановления Books относится к другому этапу")?;
        if record.phase=="writing" {
            let before=data::read_tree_zip(&repair_path.join("before.zip"))?;
            let desired=data::read_tree_zip(&repair_path.join("desired.zip"))?;
            ensure(data::tree_hash(&before)==record.before_hash&&data::tree_hash(&desired)==record.desired_hash,
                   "Копия прерванного восстановления Books повреждена")?;
            ensure(interrupted_books_match(&before,&desired,&observed),
                   "После прерванного восстановления Books появились новые данные. Они сохранены отдельно; перезапись остановлена, чтобы не потерять изменения.")?;
            ensure(read_books(afc).await?==(observed_state.existed,observed),
                   "Books изменились перед продолжением восстановления. Закройте «Книги» и повторите действие.")?;
            // Resume the already durable plan, including the original WAL-only
            // rows incorporated into desired.sqlite before the first write.
            let state=BooksState{existed:record.existed,hash:record.desired_hash.clone(),top:observed_state.top};
            restore_books(afc,&state,&desired).await?;
            let mut complete=record.clone();complete.phase="complete".into();save_json(&journal_path,&complete)?;
            return Ok(());
        }
        ensure(record.phase=="prepared"||record.phase=="complete","Неверное состояние восстановления Books")?;
    }
    let desired=crate::carrier_recovery::reconcile_books(original,&observed,&stage_asset_ids(j),&repair_path)?;
    save_tree(&repair_path.join("before.zip"),&observed)?;
    save_tree(&repair_path.join("desired.zip"),&desired)?;
    let existed=original_state.existed||observed_state.existed;
    let mut record=BooksRepair{schema:1,udid_hash:j.udid_hash.clone(),source:j.source.clone(),
        original_hash:original_state.hash.clone(),before_hash:data::tree_hash(&observed),desired_hash:data::tree_hash(&desired),
        existed,phase:"prepared".into()};
    save_json(&journal_path,&record)?;
    ensure(read_books(afc).await?==(observed_state.existed,observed),"Books изменились при подготовке восстановления. Повторите восстановление после закрытия приложения «Книги».")?;
    record.phase="writing".into();save_json(&journal_path,&record)?;
    let state=BooksState{existed,hash:record.desired_hash.clone(),top:observed_state.top};
    restore_books(afc,&state,&desired).await?;
    record.phase="complete".into();save_json(&journal_path,&record)?;
    existing.take(); // no stale plan is reused once a complete state is saved
    Ok(())
}

fn phase(path:&Path,journal:&mut Journal,name:&str)->Result<()> {
    journal.phase=name.into();save_json(&path.join("journal.json"),journal)
}
fn valid_stage_name(name:&str,prefix:&str)->bool {
    name.strip_prefix(prefix).map(|s|s.len()==20&&s.bytes().all(|b|b.is_ascii_hexdigit()&&!b.is_ascii_uppercase())).unwrap_or(false)
}
fn bound(journal:&Journal,device:&Device)->Result<()> {
    ensure(journal.schema==2&&journal.target==TARGET&&journal.udid_hash==device.udid_hash,
           "Копия относится к другому iPhone или каталогу")?;
    ensure(valid_stage_name(&journal.source,"airlift-src-")&&valid_stage_name(&journal.link,"airlift-link-")
        &&valid_stage_name(&journal.exported,"airlift-saved-"),"Неверный путь восстановления")?;
    let token=journal.source.trim_start_matches("airlift-src-");
    ensure(journal.link==format!("airlift-link-{token}")&&journal.exported==format!("airlift-saved-{token}"),"Идентификаторы восстановления не совпадают")
}
fn binary_plist(value:&Plist)->Result<Vec<u8>> {let mut b=Vec::new();plist::to_writer_binary(&mut b,value).map_err(|e|e.to_string())?;Ok(b)}
fn dict(entries:Vec<(&str,Plist)>)->Dictionary {entries.into_iter().map(|(k,v)|(k.to_owned(),v)).collect()}

async fn stage_zip(tunnel:&mut AppDeviceTunnel,source:&str,bytes:&[u8],logger:&Logger)->Result<()> {
    let mut stream=tunnel.connect_service("com.apple.streaming_zip_conduit",logger).await?;
    let request=binary_plist(&Plist::Dictionary(dict(vec![("MediaSubdir",Plist::String(source.into()))])))?;
    tokio::time::timeout(Duration::from_secs(90),async {
        stream.write_all(&(request.len() as u32).to_be_bytes()).await.map_err(|e|e.to_string())?;
        stream.write_all(&request).await.map_err(|e|e.to_string())?;
        stream.write_all(bytes).await.map_err(|e|e.to_string())?;stream.flush().await.map_err(|e|e.to_string())?;
        let length=stream.read_u32().await.map_err(|e|e.to_string())? as usize;
        ensure(length>0&&length<=1024*1024,"Неверный ответ Streaming ZIP")?;
        let mut body=vec![0;length];stream.read_exact(&mut body).await.map_err(|e|e.to_string())?;
        let response:Plist=plist::from_bytes(&body).map_err(|e|e.to_string())?;
        ensure(response.as_dictionary().and_then(|d|d.get("Status")).and_then(Plist::as_string)==Some("DataComplete"),
               "iPhone отклонил архив Streaming ZIP")
    }).await.map_err(|_|"Streaming ZIP не завершился; запустите восстановление после сбоя".to_string())?
}
async fn atc_read(stream:&mut Box<dyn ReadWrite>)->Result<Dictionary> {
    // Never restart a partially consumed frame after a timeout.
    tokio::time::timeout(IO_TIMEOUT,exploit::read_atc_dict(stream)).await
        .map_err(|_|"AirTraffic не ответил; сессия остановлена".to_string())?
}
async fn atc_send(stream:&mut Box<dyn ReadWrite>,name:&str,session:i64,params:Option<Dictionary>)->Result<()> {
    tokio::time::timeout(IO_TIMEOUT,exploit::send_atc_dict(stream,&exploit::make_atc_msg(name,session,params)))
        .await.map_err(|_|"AirTraffic не подтвердил отправку".to_string())?
}
async fn atc_until(stream:&mut Box<dyn ReadWrite>,wanted:&str)->Result<Dictionary> {
    for _ in 0..40 {
        let message=atc_read(stream).await?;let name=exploit::atc_message_name(&message).unwrap_or_default();
        if name=="Ping"{atc_send(stream,"Pong",1,None).await?;continue;}
        if name==wanted{return Ok(message);}
        if name=="SyncFailed"||name=="SyncFinished" {
            let session=exploit::atc_session_number(&message).unwrap_or(1);
            if session==1{return Err("AirTraffic завершил синхронизацию до подтверждения операции".into());}
        }
    }
    Err(format!("AirTraffic не прислал {wanted}"))
}
async fn atc_prepare(tunnel:&mut AppDeviceTunnel,assets:&[(String,String)],logger:&Logger)->Result<Box<dyn ReadWrite>> {
    let mut stream=tunnel.connect_service("com.apple.atc",logger).await?;
    let mut grappa=None;let mut allowed=false;
    for _ in 0..20 {
        let message=atc_read(&mut stream).await?;let name=exploit::atc_message_name(&message).unwrap_or_default();
        if name=="Capabilities" {
            if let Some(info)=message.get("Params").and_then(Plist::as_dictionary)
                .and_then(|d|d.get("GrappaSupportInfo")).and_then(Plist::as_dictionary) {
                let number=|key:&str,default:u32|info.get(key).and_then(Plist::as_unsigned_integer)
                    .and_then(|n|u32::try_from(n).ok()).unwrap_or(default);
                grappa=Some((number("version",1),number("deviceType",0),number("protocolVersion",1)));
            }
        }
        if name=="SyncAllowed"{allowed=true;break;}
        if name=="Ping"{atc_send(&mut stream,"Pong",0,None).await?;}
    }
    ensure(allowed,"AirTraffic не разрешил синхронизацию. Проверьте, что приложение «Книги» установлено и открывалось.")?;
    let token=crate::grappa::generate_grappa_token(grappa,|_|{}).ok_or("iOS не выдала токен AirTraffic; запись остановлена")?;
    let library_token=random_token(16)?;
    let library_id=format!("{}-{}-{}-{}-{}",&library_token[..8],&library_token[8..12],
        &library_token[12..16],&library_token[16..20],&library_token[20..]);
    let host=Plist::Dictionary(dict(vec![
        ("Type",Plist::String("iTunes".into())),("Version",Plist::String("13.7.0.161".into())),
        ("MacOSVersion",Plist::String("15.0".into())),("SyncHostName",Plist::String("CarrierSIM".into())),
        ("LibraryID",Plist::String(library_id)),("SyncedDataclasses",Plist::Array(vec![Plist::String("Book".into())])),
        ("SyncedAssetTypes",Plist::Array(vec![Plist::String("Book".into())])),("Wakeable",Plist::Boolean(false)),
        ("Grappa",Plist::Data(token.clone())),
    ]));
    atc_send(&mut stream,"HostInfo",0,Some(dict(vec![("HostInfo",host.clone()),("LocalCloudSupport",Plist::Boolean(false))]))).await?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    atc_send(&mut stream,"RequestingSync",1,Some(dict(vec![
        ("Dataclasses",Plist::Array(vec![Plist::String("Book".into())])),
        ("DataclassAnchors",Plist::Dictionary(Dictionary::new())),("HostInfo",host),("Grappa",Plist::Data(token)),
    ]))).await?;
    atc_until(&mut stream,"ReadyForSync").await?;
    atc_send(&mut stream,"FinishedSyncingMetadata",1,Some(dict(vec![
        ("SyncTypes",Plist::Dictionary(dict(vec![("Book",Plist::Integer(1.into()))]))),
        ("DataclassAnchors",Plist::Dictionary(Dictionary::new())),
    ]))).await?;
    let message=atc_until(&mut stream,"AssetManifest").await?;
    let manifest=message.get("Params").and_then(Plist::as_dictionary).and_then(|d|d.get("AssetManifest"))
        .or_else(||message.get("AssetManifest")).and_then(Plist::as_dictionary).ok_or("Неверный манифест AirTraffic")?;
    let books=manifest.get("Book").and_then(Plist::as_array).ok_or("AirTraffic не включил каталог Books в манифест")?;
    let found:BTreeSet<String>=books.iter().filter_map(Plist::as_dictionary).filter(|d|{
        d.get("IsDownload").map(|v|v.as_boolean()==Some(true)||v.as_unsigned_integer()==Some(1)).unwrap_or(false)
    }).filter_map(|d|d.get("AssetID").and_then(Plist::as_string).map(str::to_owned)).collect();
    ensure(assets.iter().all(|(id,_)|found.contains(id)),"AirTraffic не подтвердил все три объекта. Каталог не заменён; используйте восстановление.")?;
    Ok(stream)
}
async fn asset_complete(stream:&mut Box<dyn ReadWrite>,asset:&(String,String))->Result<()> {
    atc_send(stream,"FileComplete",1,Some(dict(vec![("AssetID",Plist::String(asset.0.clone())),
        ("Dataclass",Plist::String("Book".into())),("AssetPath",Plist::String(asset.1.clone()))]))).await
}

async fn transfer(tunnel:&mut AppDeviceTunnel,device:&Device,path:&Path,payload:Option<&Tree>,expected:Option<&Tree>,
                  recovery:bool,check_sims:bool,logger:&Logger)->Result<Option<Tree>> {
    ensure(!path.exists(),"Повтор этапа запрещён: создайте новую операцию восстановления")?;private_dir(path)?;
    let token=random_token(10)?;
    let mut journal=Journal{schema:2,udid_hash:device.udid_hash.clone(),target:TARGET.into(),
        source:format!("airlift-src-{token}"),link:format!("airlift-link-{token}"),exported:format!("airlift-saved-{token}"),
        phase:"created".into(),complete:false,requires_recovery:false,books_restored:true,
        original_hash:None,payload_hash:payload.map(data::tree_hash),recovery,recovered:false,error:None};
    save_json(&path.join("journal.json"),&journal)?;
    let mut afc=tunnel.connect_afc(logger).await?;
    for name in [&journal.source,&journal.link,&journal.exported]{ensure(stat(&mut afc,name).await?.is_none(),"Коллизия служебного пути; запись отменена")?;}
    let (books_state,books)=snapshot_books(&mut afc,path).await?;
    let mut allowed_recovery=BTreeSet::new();
    if recovery {
        let op_path=path.parent().and_then(Path::parent).ok_or("Нет привязки этапа к операции")?;
        let op:Operation=load_json(&op_path.join("operation.json"))?;
        ensure(op.target==TARGET&&op.udid_hash==device.udid_hash,"Восстановление относится к другому iPhone")?;
        allowed_recovery.extend(op.original_hash);
        allowed_recovery.extend(op.desired_hash);
        allowed_recovery.extend(op.preserved_hash);
        if let Some(payload)=payload{allowed_recovery.insert(data::tree_hash(payload));}
    }
    let raw=data::staging_archive(payload)?;atomic_bytes(&path.join("staging.zip"),&raw)?;
    if let Some(tree)=payload {save_tree(&path.join("desired.zip"),tree)?;}
    let final_source=if payload.is_some(){format!("{}/{PAYLOAD_PATH}",journal.source)}else{journal.exported.clone()};
    let assets=vec![
        (format!("../../{}/p0/p1/p2/link",journal.source),journal.link.clone()),
        (format!("../../{}/../../{}",journal.source,TARGET.trim_start_matches("/var/mobile/")),journal.exported.clone()),
        (format!("../../{final_source}"),format!("{}/iPhone",journal.link)),
    ];
    journal.requires_recovery=true;journal.books_restored=false;
    phase(path,&mut journal,"staging")?; // durable intent BEFORE the first phone mutation
    let result:Result<Option<Tree>>=async {
        stage_zip(tunnel,&journal.source,&raw,logger).await?;
        let link=stat(&mut afc,&format!("{}/p0/p1/p2/link",journal.source)).await?.ok_or("Служебная ссылка не распакована")?;
        ensure(link.st_ifmt=="S_IFLNK"&&link.st_link_target.as_deref()==Some(&format!("../../../{}",PARENT.trim_start_matches('/'))),
               "Служебная символическая ссылка не совпала")?;
        if let Some(tree)=payload {ensure(remote_tree(&mut afc,&final_source).await?==*tree,"Распакованный каталог не совпал с планом")?;}
        mkdirs(&mut afc,"Books/Sync").await?;
        let book_rows=assets.iter().enumerate().map(|(index,(id,_))|Plist::Dictionary(dict(vec![
            ("Persistent ID",Plist::String(id.clone())),("Item ID",Plist::String((index+1).to_string())),("DSID",Plist::String("1".into()))
        ]))).collect();
        write_file(&mut afc,"Books/Sync/Books.plist",&binary_plist(&Plist::Dictionary(dict(vec![("Books",Plist::Array(book_rows))])))?).await?;
        phase(path,&mut journal,"host-started")?;
        let mut atc=atc_prepare(tunnel,&assets,logger).await?;
        phase(path,&mut journal,"first-asset-intent")?;asset_complete(&mut atc,&assets[0]).await?;
        tokio::time::sleep(Duration::from_millis(900)).await;
        // A kill after this journal entry is ambiguous until the exported copy
        // is found. Recovery must not assume an error means no rename occurred.
        phase(path,&mut journal,"export-intent")?;asset_complete(&mut atc,&assets[1]).await?;
        phase(path,&mut journal,"export-check")?;
        let mut found=None;
        for _ in 0..50 {
            found=stat(&mut afc,&journal.exported).await?;if found.is_some(){break;}
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let snapshot=if let Some(node)=found {
            ensure(node.st_ifmt=="S_IFDIR","Экспортированный каталог имеет неверный тип")?;
            phase(path,&mut journal,"original-exported")?;
            let tree=remote_tree(&mut afc,&journal.exported).await?;
            save_tree(&path.join("original.zip"),&tree)?;journal.original_hash=Some(data::tree_hash(&tree));
            phase(path,&mut journal,"backup-saved")?;
            if let Some(expected)=expected {ensure(tree==*expected,"Настройки оператора изменились во время операции. Запись отменена; выполните восстановление.")?;}
            ensure(remote_tree(&mut afc,&journal.exported).await?==tree,"Экспорт изменился после создания копии")?;
            if recovery&&!allowed_recovery.contains(&data::tree_hash(&tree)) {
                phase(path,&mut journal,"recovery-current-conflict")?;
                return Err("Во время восстановления найден изменившийся каталог. Новые настройки сохранены отдельно и не будут заменены старой копией.".into());
            }
            Some(tree)
        }else{
            ensure(recovery&&payload.is_some(),"iPhone не отдал каталог операторов. Не повторяйте установку; используйте «Восстановить после сбоя».")?;
            None
        };
        require_binding(tunnel,device,check_sims).await?;
        phase(path,&mut journal,if snapshot.is_some(){"final-authorized"}else{"recovery-final-authorized"})?;
        asset_complete(&mut atc,&assets[2]).await?;
        tokio::time::sleep(Duration::from_secs(2)).await;drop(atc);
        let mut consumed=false;
        for _ in 0..30 {
            if stat(&mut afc,&final_source).await?.is_none(){consumed=true;break;}
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        ensure(consumed,"iPhone не забрал конечный каталог. Размещение не подтверждено; выполните восстановление.")?;
        journal.complete=true;journal.requires_recovery=false;
        phase(path,&mut journal,"placement-observed")?;
        Ok(snapshot)
    }.await;
    drop(afc);
    if let Err(e)=&result {journal.error=Some(redact(e));save_json(&path.join("journal.json"),&journal)?;}
    // Use a fresh AFC stream: a timed-out frame leaves the old stream unusable.
    let restored=async {
        let mut clean=tunnel.connect_afc(logger).await?;recover_books(&mut clean,path,&journal,&books_state,&books).await
    }.await;
    match restored {
        Ok(())=>{journal.books_restored=true;save_json(&path.join("journal.json"),&journal)?;}
        Err(e)=>{journal.books_restored=false;journal.error=Some(redact(&e));save_json(&path.join("journal.json"),&journal)?;
            return Err(format!("Служебные файлы Books требуют восстановления. {}",redact(&e)));}
    }
    result
}

fn stage_dirs(op:&Path)->Result<Vec<PathBuf>> {
    let root=op.join("stages");if !root.exists(){return Ok(vec![]);}
    let mut dirs=Vec::new();
    for e in fs::read_dir(root).map_err(|e|e.to_string())? {
        let e=e.map_err(|e|e.to_string())?;let typ=e.file_type().map_err(|e|e.to_string())?;
        ensure(!typ.is_symlink(),"Ссылка в каталоге журнала запрещена")?;
        if typ.is_dir(){dirs.push(e.path());}
    }
    dirs.sort();ensure(dirs.len()<=400,"Слишком много этапов в журнале")?;Ok(dirs)
}
fn pending_ops(runs:&Path,hash:Option<&str>)->Result<Vec<PathBuf>> {
    if !runs.exists(){return Ok(vec![]);}
    let mut pending=Vec::new();
    for e in fs::read_dir(runs).map_err(|e|e.to_string())? {
        let e=e.map_err(|e|e.to_string())?;let typ=e.file_type().map_err(|e|e.to_string())?;
        if !typ.is_dir()||typ.is_symlink(){continue;}
        let path=e.path();if !path.join("operation.json").exists(){continue;}
        let op:Operation=load_json(&path.join("operation.json"))?;
        if hash.map(|h|h!=op.udid_hash).unwrap_or(false){continue;}
        if !op.closed {pending.push(path);continue;}
        let mut unfinished=false;
        for stage in stage_dirs(&path)? {
            if stage.join("trigger-staging.json").exists(){
                unfinished|=carrier_trigger::trigger_needs_recovery(&stage)?;
            }
            if stage.join("journal.json").exists(){
                let j:Journal=load_json(&stage.join("journal.json"))?;
                unfinished|=!j.recovered&&(j.requires_recovery||!j.books_restored);
            }
        }
        if unfinished{pending.push(path);}
    }
    pending.sort();Ok(pending)
}
pub(crate) fn needs_recovery(work:&Path,hash:&str)->Result<bool> {
    Ok(!pending_ops(&work.join("runs"),Some(hash))?.is_empty())
}
fn new_stage(op:&Path,label:&str)->Result<PathBuf> {
    let root=op.join("stages");private_dir(&root)?;
    let count=stage_dirs(op)?.len();Ok(root.join(format!("{count:04}-{label}-{}",random_token(3)?)))
}

#[derive(Debug,PartialEq)]
enum RecoveryDecision { BooksOnly, RemoteOriginal, LocalOriginal, MediaOnly, Ambiguous }
fn recovery_decision(j:&Journal,remote:bool,local:bool)->RecoveryDecision {
    if j.complete{return RecoveryDecision::BooksOnly;}
    if remote{return RecoveryDecision::RemoteOriginal;}
    if local&&j.original_hash.is_some(){return RecoveryDecision::LocalOriginal;}
    if ["created","staging","host-started","first-asset-intent"].contains(&j.phase.as_str()){
        RecoveryDecision::MediaOnly
    }else{RecoveryDecision::Ambiguous}
}
async fn recover_stage(tunnel:&mut AppDeviceTunnel,device:&Device,failed:&Path,op:&Path,logger:&Logger)->Result<()> {
    let mut j:Journal=load_json(&failed.join("journal.json"))?;bound(&j,device)?;
    if j.recovered{return Ok(());}
    if !j.requires_recovery&&j.books_restored {
        // A failure while taking local snapshots never touched the phone and
        // may not have a complete books.zip/books.json pair yet.
        if !j.complete {
            ensure(j.phase=="created","Незавершённый этап имеет противоречивый журнал")?;
            j.recovered=true;save_json(&failed.join("journal.json"),&j)?;
        }
        return Ok(());
    }
    let state:BooksState=load_json(&failed.join("books.json"))?;
    let books=data::read_tree_zip(&failed.join("books.zip"))?;
    ensure(data::tree_hash(&books)==state.hash,"Копия Books повреждена")?;
    let mut afc=tunnel.connect_afc(logger).await?;
    let remote=stat(&mut afc,&j.exported).await?.is_some();
    let decision=recovery_decision(&j,remote,failed.join("original.zip").exists());
    let mut original=match decision {
        RecoveryDecision::BooksOnly|RecoveryDecision::MediaOnly=>None,
        RecoveryDecision::RemoteOriginal=>{
            let tree=remote_tree(&mut afc,&j.exported).await?;
            if let Some(hash)=&j.original_hash {ensure(data::tree_hash(&tree)==*hash,"Удалённая резервная копия изменилась")?;}
            ensure(remote_tree(&mut afc,&j.exported).await?==tree,"Удалённая копия нестабильна")?;
            Some(tree)
        },
        RecoveryDecision::LocalOriginal=>{
            let tree=data::read_tree_zip(&failed.join("original.zip"))?;
            ensure(Some(data::tree_hash(&tree))==j.original_hash,"Локальная резервная копия повреждена")?;Some(tree)
        },
        RecoveryDecision::Ambiguous=>return Err("Экспорт каталога мог начаться, но проверенная копия пока не найдена. Подождите несколько секунд и снова запустите восстановление. Журналы сохранены; повторная установка заблокирована.".into()),
    };
    recover_books(&mut afc,failed,&j,&state,&books).await?;drop(afc);
    let mut operation:Operation=load_json(&op.join("operation.json"))?;
    if j.phase=="recovery-current-conflict" {
        if let Some(tree)=&original {
            operation.preserved_hash=Some(store_preserved(op,tree)?);
            save_json(&op.join("operation.json"),&operation)?;
        }
    }else if let (Some(preserved),Some(tree))=(&operation.preserved_hash,&original) {
        if data::tree_hash(tree)!=*preserved {
            // A newer recovery detected changes made outside this transaction.
            // Do not let an older pending stage overwrite the preserved tree.
            original=None;
        }
    }
    if let Some(original)=original {
        // This recovery write has its own durable journal. A second failure is
        // recovered newest-first, before returning to this earlier stage.
        let stage=new_stage(op,"recover-placement")?;
        let placed=transfer(tunnel,device,&stage,Some(&original),None,true,false,logger).await;
        let mut expected_original=original;
        if let Err(error)=placed {
            let mut conflict:Journal=load_json(&stage.join("journal.json"))?;
            if conflict.phase!="recovery-current-conflict" {return Err(error);}
            // Preserve the previously unknown live tree immediately. This is
            // an undo of the inspection move, not a retry of the old mutation.
            let current=data::read_tree_zip(&stage.join("original.zip"))?;
            ensure(Some(data::tree_hash(&current))==conflict.original_hash,"Копия изменившегося каталога повреждена")?;
            operation.preserved_hash=Some(store_preserved(op,&current)?);
            save_json(&op.join("operation.json"),&operation)?;
            if !conflict.books_restored {
                let bstate:BooksState=load_json(&stage.join("books.json"))?;
                let btree=data::read_tree_zip(&stage.join("books.zip"))?;
                let mut afc=tunnel.connect_afc(logger).await?;recover_books(&mut afc,&stage,&conflict,&bstate,&btree).await?;
            }
            logger.log("Новые настройки оператора сохранены. Возвращаю именно их на прежнее место…");
            let preserve=new_stage(op,"preserve-current")?;
            transfer(tunnel,device,&preserve,Some(&current),None,true,false,logger).await?;
            expected_original=current;
            conflict.recovered=true;conflict.requires_recovery=false;conflict.books_restored=true;
            save_json(&stage.join("journal.json"),&conflict)?;
        }
        let readback=new_stage(op,"recover-readback")?;
        let observed=transfer(tunnel,device,&readback,None,None,false,false,logger).await?
            .ok_or("Не прочитан восстановленный каталог")?;
        ensure(observed==expected_original,"Восстановленный каталог не совпал с копией")?;
    }
    j.recovered=true;j.requires_recovery=false;j.books_restored=true;
    save_json(&failed.join("journal.json"),&j)
}

async fn cleanup_stages(tunnel:&mut AppDeviceTunnel,device:&Device,op:&Path,logger:&Logger)->Result<()> {
    let mut afc=tunnel.connect_afc(logger).await?;
    for stage in stage_dirs(op)? {if stage.join("journal.json").exists(){
        let j:Journal=load_json(&stage.join("journal.json"))?;bound(&j,device)?;
        ensure((j.complete||j.recovered)&&!j.requires_recovery&&j.books_restored,"Нельзя удалять незавершённые резервные копии")?;
        for name in [&j.source,&j.link,&j.exported]{remove_node(&mut afc,name.clone(),0).await?;}
    }}
    Ok(())
}

async fn recover_operation(tunnel:&mut AppDeviceTunnel,device:&Device,path:&Path,logger:&Logger)->Result<bool> {
    let mut op:Operation=load_json(&path.join("operation.json"))?;
    ensure(op.schema==2&&op.target==TARGET&&op.udid_hash==device.udid_hash,"Операция относится к другому iPhone")?;
    op.catalog_verified=false;op.commcenter_verified=false;op.closed=false;
    save_json(&path.join("operation.json"),&op)?;
    let mut stages=stage_dirs(path)?;stages.reverse();
    for stage in stages {
        if stage.join("trigger-staging.json").exists(){carrier_trigger::recover_trigger(tunnel,logger,&stage).await?;}
        if stage.join("journal.json").exists(){recover_stage(tunnel,device,&stage,path,logger).await?;}
    }
    // recover_stage may have discovered and protected a newer live tree.
    op=load_json(&path.join("operation.json"))?;
    let mut verified=op.catalog_verified;
    if let Some(original_hash)=&op.original_hash {
        let original=data::read_tree_zip(&path.join("original.zip"))?;
        ensure(data::tree_hash(&original)==*original_hash,"Исходная резервная копия повреждена")?;
        let desired=if let Some(hash)=&op.desired_hash {
            let tree=data::read_tree_zip(&path.join("desired.zip"))?;
            ensure(data::tree_hash(&tree)==*hash,"Сохранённый план повреждён")?;Some(tree)
        }else{None};
        let stage=new_stage(path,"recover-verify")?;
        let observed=transfer(tunnel,device,&stage,None,None,false,false,logger).await?.ok_or("Нет обратного чтения")?;
        // A fully placed stage is retained if either the new catalogue or the
        // exact prior catalogue is observed. Never overwrite unrelated changes.
        let preserved=if let Some(hash)=&op.preserved_hash {
            let tree=data::read_tree_zip(&preserved_backup(path,hash)?)?;
            ensure(data::tree_hash(&tree)==*hash,"Копия новых настроек повреждена")?;Some(tree)
        }else{None};
        ensure(observed==original||desired.as_ref()==Some(&observed)||preserved.as_ref()==Some(&observed),
               "Текущий каталог отличается от исходной копии и плана. Автоматическая перезапись остановлена; копии сохранены.")?;
        verified=true;
    }
    cleanup_stages(tunnel,device,path,logger).await?;
    op.recovered=true;op.closed=true;op.catalog_verified=verified;op.commcenter_verified=false;
    save_json(&path.join("operation.json"),&op)?;Ok(verified)
}

fn public_sims(device:&Device)->Vec<Value> {
    device.rows.as_array().into_iter().flatten().filter_map(Plist::as_dictionary).map(|row|{
        let string=|key:&str|row.get(key).map(plist_string).unwrap_or_default();
        let imsi=string("InternationalMobileSubscriberIdentity");
        let tail=if imsi.len()==15&&imsi.bytes().all(|c|c.is_ascii_digit()){imsi[11..].to_string()}else{String::new()};
        json!({"slot":string("Slot"),"mcc":string("MCC"),"mnc":string("MNC"),"imsi_tail":tail,
            "carrier":string("CFBundleIdentifier"),"version":string("CFBundleVersion")})
    }).collect()
}
fn request_config(request:&Request)->Result<BundleConfig> {
    ensure(["status","apply","restore","recover"].contains(&request.action.as_str()),"Неизвестное действие")?;
    ensure(!request.slots.is_empty()&&request.slots.len()<=2&&request.slots.iter().all(|s|s=="kOne"||s=="kTwo"),"Выберите SIM 1, SIM 2 или обе линии")?;
    ensure(request.slots.iter().collect::<BTreeSet<_>>().len()==request.slots.len(),"Слот SIM выбран дважды")?;
    let mut config=BundleConfig::new();config.insert("default".into(),data::normalize_bundle(&request.bundle)?);Ok(config)
}

async fn execute(pairing_path:PathBuf,work:PathBuf,assets_path:PathBuf,request:Request,logger:&Logger,
                 failure_context:&Arc<Mutex<FailureContext>>)->Result<(i32,Value)> {
    let config=request_config(&request)?;let _lock=OpLock::acquire(&work)?;
    let runs=work.join("runs");private_dir(&runs)?;
    let bytes=fs::read(&pairing_path).map_err(|_|"Файл сопряжения не найден. Создайте сопряжение в приложении.".to_string())?;
    ensure(bytes.len()<=2*1024*1024,"Файл сопряжения слишком большой")?;
    logger.log(if request.target.is_some(){"Подключаюсь к iPhone друга по локальной сети…"}else{"Подключаюсь к этому iPhone через защищённый туннель…"});
    let mut tunnel=exploit::connect_tunnel_for_target(&bytes,logger,request.target.as_ref()).await?;
    let device=device_info(&mut tunnel).await?;
    crate::device_target::verify_identity(request.expected_device_hash.as_deref(), &device.udid_hash,
        request.target.is_some() && matches!(request.action.as_str(), "apply" | "restore"))?;
    if let Ok(mut context)=failure_context.lock(){context.device_hash=Some(device.udid_hash.clone());}
    let pending=pending_ops(&runs,Some(&device.udid_hash))?;
    let slots:Vec<&str>=request.slots.iter().map(String::as_str).collect();
    let selected=data::select_sims(&device.rows,&slots,&config);
    let warning=if device.ios!="27.0"||!["24A435","24A437"].contains(&device.build.as_str()) {
        Some("Эта версия iOS не входила в исходные проверенные сборки CarrierSIM. Работа не гарантирована.")
    }else{None};
    if request.action=="status" {
        let reason=if device.activation!="Activated"{Some("iPhone не активирован".to_string())}
            else if !pending.is_empty(){Some("Требуется восстановление после незавершённой операции".to_string())}
            else{selected.as_ref().err().cloned()};
        return Ok((0,json!({"action":"status","device":device.public(),"sims":public_sims(&device),
            "needs_recovery":!pending.is_empty(),"can_apply":reason.is_none(),"reason":reason,"warning":warning,
            "catalog_verified":false,"commcenter_verified":false})));
    }
    ensure(device.activation=="Activated","iPhone не активирован")?;
    if request.action=="recover" {
        if pending.is_empty(){return Ok((0,json!({"action":"recover","device":device.public(),"sims":public_sims(&device),
            "needs_recovery":false,"catalog_verified":false,"commcenter_verified":false,"message":"Незавершённых операций нет."})));}
        logger.log("Восстанавливаю незавершённые этапы. Сначала проверяю сохранённые копии…");
        let mut verified=false;
        for path in pending.iter().rev(){
            if let Ok(mut context)=failure_context.lock(){context.operation=Some(path.clone());}
            verified|=recover_operation(&mut tunnel,&device,path,logger).await?;
        }
        return Ok((2,json!({"action":"recover","device":device.public(),"sims":public_sims(&device),
            "needs_recovery":false,"catalog_verified":verified,"commcenter_verified":false,
            "message":if verified{"Восстановление завершено. Каталог и служебные файлы проверены. Выбор профиля CommCenter заново не подтверждён."}
                else{"Незавершённые служебные действия восстановлены. Проверка выбора профиля CommCenter не выполнялась."}})));
    }
    ensure(pending.is_empty(),"Прошлая операция не завершилась. Сначала нажмите «Восстановить после сбоя».")?;
    let sims:Vec<Sim>=if request.action=="apply"{selected?}else{
        // Restore affects exact root-level IMSI aliases only, including aliases
        // from previously inserted SIMs. Current IMSI is not required to undo.
        device.rows.as_array().into_iter().flatten().filter_map(Plist::as_dictionary).filter_map(|r|{
            let string=|k:&str|r.get(k).map(plist_string).unwrap_or_default();let slot=string("Slot");
            if slot!="kOne"&&slot!="kTwo"{return None;}
            Some(Sim{slot,mcc:string("MCC"),mnc:string("MNC"),imsi:String::new(),bundle:String::new()})
        }).collect()
    };
    let assets=data::load_assets(&assets_path)?;
    let plmns:Vec<String>=public_sims(&device).iter().map(|r|format!("{}{}",r["mcc"].as_str().unwrap_or(""),r["mnc"].as_str().unwrap_or(""))).collect();
    let targets:Vec<String>=sims.iter().filter(|s|!s.bundle.is_empty()).map(|s|s.bundle.clone()).collect();
    let trigger=data::choose_trigger(&assets,&plmns,&targets,&device.hardware)?;
    let stamp=SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e|e.to_string())?.as_millis();
    let path=runs.join(format!("{stamp:015}-{}",random_token(5)?));private_dir(&path)?;
    if let Ok(mut context)=failure_context.lock(){context.operation=Some(path.clone());}
    let mut operation=Operation{schema:2,udid_hash:device.udid_hash.clone(),target:TARGET.into(),action:request.action.clone(),
        bundle:config["default"].clone(),slots:request.slots.clone(),sim_binding:device.sim_binding(),closed:false,
        catalog_verified:false,commcenter_verified:false,original_hash:None,desired_hash:None,preserved_hash:None,recovered:false};
    save_json(&path.join("operation.json"),&operation)?;
    logger.log("Подготавливаю независимое пересканирование профилей…");
    let init=new_stage(&path,"initialize")?;private_dir(&init)?;
    carrier_trigger::install_trigger(&mut tunnel,&trigger,logger,&init).await?;
    require_binding(&mut tunnel,&device,true).await?;
    logger.log("Сохраняю точную копию каталога, включая символические ссылки…");
    let snapshot=new_stage(&path,"snapshot")?;
    let original=transfer(&mut tunnel,&device,&snapshot,None,None,false,true,logger).await?.ok_or("Исходный каталог не прочитан")?;
    save_tree(&path.join("original.zip"),&original)?;operation.original_hash=Some(data::tree_hash(&original));
    save_json(&path.join("operation.json"),&operation)?;
    require_binding(&mut tunnel,&device,true).await?;
    let desired=if request.action=="apply"{data::make_plan(&original,&sims)?}else{data::remove_imsi_links(&original)?};
    save_tree(&path.join("desired.zip"),&desired)?;operation.desired_hash=Some(data::tree_hash(&desired));
    save_json(&path.join("operation.json"),&operation)?;
    logger.log(if request.action=="apply"{"Записываю ссылки только для выбранных SIM…"}else{"Возвращаю штатный выбор профилей операторов…"});
    if desired!=original {
        let apply=new_stage(&path,&request.action)?;
        transfer(&mut tunnel,&device,&apply,Some(&desired),Some(&original),false,true,logger).await?;
    }
    logger.log("Проверяю каталог независимым обратным чтением…");
    let readback=new_stage(&path,"readback")?;
    let observed=transfer(&mut tunnel,&device,&readback,None,None,false,true,logger).await?.ok_or("Обратное чтение не выполнено")?;
    ensure(observed==desired,"Обратное чтение не совпало. Запустите восстановление после сбоя.")?;
    operation.catalog_verified=true;save_json(&path.join("operation.json"),&operation)?;
    logger.log("Каталог совпал. Проверяю фактический выбор профиля и подписи CommCenter…");
    let rescan=new_stage(&path,"rescan")?;private_dir(&rescan)?;
    let scan=carrier_trigger::install_trigger(&mut tunnel,&trigger,logger,&rescan).await?;
    let profiles=data::report_log(&scan.commcenter_log,&sims);
    let confirmed=scan.log_error.is_none()&&!profiles.is_empty()&&profiles.iter().all(|p|p.verified&&(request.action=="restore"||
        p.selected.as_ref().map(|s|s.eq_ignore_ascii_case(&p.expected)).unwrap_or(false)));
    operation.commcenter_verified=confirmed;
    // A requested system bundle may be missing on this firmware. If CommCenter
    // positively selected another package, restore the exact previous tree.
    let explicit_mismatch=request.action=="apply"&&profiles.iter().any(|p|
        p.selected.as_ref().map(|s|!s.eq_ignore_ascii_case(&p.expected)).unwrap_or(false));
    if explicit_mismatch {
        logger.log("iOS выбрала другой пакет. Возвращаю предыдущий проверенный каталог…");
        operation.catalog_verified=false;operation.commcenter_verified=false;
        save_json(&path.join("operation.json"),&operation)?;
        let rollback=new_stage(&path,"rollback")?;
        transfer(&mut tunnel,&device,&rollback,Some(&original),Some(&desired),false,true,logger).await?;
        let verify=new_stage(&path,"rollback-readback")?;
        ensure(transfer(&mut tunnel,&device,&verify,None,None,false,true,logger).await?==Some(original.clone()),"Предыдущий каталог не подтверждён; выполните восстановление")?;
        operation.catalog_verified=true;save_json(&path.join("operation.json"),&operation)?;
        let rescan=new_stage(&path,"rollback-rescan")?;private_dir(&rescan)?;
        carrier_trigger::install_trigger(&mut tunnel,&trigger,logger,&rescan).await?;
        cleanup_stages(&mut tunnel,&device,&path,logger).await?;
        operation.closed=true;operation.commcenter_verified=false;save_json(&path.join("operation.json"),&operation)?;
        return Ok((2,json!({"action":request.action,"device":device.public(),"sims":public_sims(&device),"profiles":profiles,
            "catalog_verified":true,"commcenter_verified":false,"rolled_back":true,"needs_recovery":false,
            "message":"iOS не выбрала запрошенный профиль. Предыдущий каталог возвращён и проверен."})));
    }
    cleanup_stages(&mut tunnel,&device,&path,logger).await?;
    operation.closed=true;save_json(&path.join("operation.json"),&operation)?;
    let message=if confirmed {
        if request.action=="apply"{"Каталог проверен, CommCenter подтвердил выбранный профиль и подпись. Включите авиарежим на 15 секунд и проверьте связь."}
        else{"Ссылки по IMSI удалены. Каталог проверен, CommCenter подтвердил штатный выбор профиля."}
    }else{"Каталог записан и точно проверен. Выбор профиля и подпись CommCenter пока не подтверждены; включите авиарежим на 15 секунд и проверьте связь. Успешная работа сети не утверждается."};
    Ok((if confirmed{0}else{2},json!({"action":request.action,"device":device.public(),"sims":public_sims(&device),"profiles":profiles,
        "catalog_verified":true,"commcenter_verified":confirmed,"needs_recovery":false,"message":message,
        "warning":warning,"ipcc_installation_completed":scan.ipcc_installation_completed,
        "log_error":scan.log_error,"nr_data_verified":false})))
}

/// C ABI implementation. Strings are copied before starting the worker. The
/// caller owns callbacks until this blocking call completes. Returns 2 for an
/// explicitly unverified profile, 1 for an error, 0 only for verified outcomes
/// (or a read-only/no-op request). Returned strings use al_string_free.
pub unsafe fn run(pairing_path:*const c_char,work_dir:*const c_char,assets_zip:*const c_char,request_json:*const c_char,
    cb:ALLogCallback,ctx:*mut c_void,result_json:*mut *mut c_char,error:*mut *mut c_char)->i32 {
    if !result_json.is_null(){*result_json=std::ptr::null_mut();}if !error.is_null(){*error=std::ptr::null_mut();}
    let pairing=crate::ffi_util::opt_str(pairing_path,"");let work=crate::ffi_util::opt_str(work_dir,"");
    let assets=crate::ffi_util::opt_str(assets_zip,"");let request_text=crate::ffi_util::opt_str(request_json,"");
    let work_copy=work.clone();let ctx_bits=ctx as usize;
    let failure_context=Arc::new(Mutex::new(FailureContext::default()));let worker_context=failure_context.clone();
    let task=crate::ffi_util::run_with_large_stack("carrier-transaction",move||{
        ensure(!pairing.is_empty()&&!work.is_empty()&&!assets.is_empty(),"Не заданы пути приложения")?;
        ensure(request_text.len()<8192,"Запрос слишком большой")?;
        let request:Request=serde_json::from_str(&request_text).map_err(|e|format!("Неверный запрос: {e}"))?;
        let logger=Logger{cb,ctx:ctx_bits as *mut c_void};
        idevice_ffi::run_sync_local(execute(pairing.into(),work.into(),assets.into(),request,&logger,&worker_context))
    });
    match task {
        Ok(Ok((code,value)))=>{if !result_json.is_null(){*result_json=crate::ffi_util::cstr(value.to_string());}code}
        failure=>{
            let msg=match failure{Ok(Err(e))|Err(e)=>redact(&e),_=>"Неизвестная ошибка".into()};
            let context=failure_context.lock().ok();
            let hash=context.as_ref().and_then(|c|c.device_hash.as_deref());
            let verified=context.as_ref().and_then(|c|c.operation.as_ref()).and_then(|path|
                load_json::<Operation>(&path.join("operation.json")).ok()).map(|o|o.catalog_verified).unwrap_or(false);
            let needs=pending_ops(&PathBuf::from(work_copy).join("runs"),hash).map(|v|!v.is_empty()).unwrap_or(true);
            if !result_json.is_null(){*result_json=crate::ffi_util::cstr(json!({"catalog_verified":verified,"commcenter_verified":false,
                "needs_recovery":needs,"message":msg,"error":true}).to_string());}
            if !error.is_null(){*error=crate::ffi_util::cstr(&msg);}1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn journal(phase:&str)->Journal {Journal{schema:2,udid_hash:"x".into(),target:TARGET.into(),source:String::new(),link:String::new(),
        exported:String::new(),phase:phase.into(),complete:false,requires_recovery:true,books_restored:false,original_hash:None,
        payload_hash:None,recovery:false,recovered:false,error:None}}
    #[test] fn interrupted_export_is_never_treated_as_no_change(){
        for phase in ["export-intent","export-check","original-exported","final-authorized","recovery-final-authorized"]{
            assert_eq!(recovery_decision(&journal(phase),false,false),RecoveryDecision::Ambiguous);
        }
    }
    #[test] fn finished_catalog_is_not_rolled_back_for_books_failure(){
        let mut j=journal("placement-observed");j.complete=true;
        assert_eq!(recovery_decision(&j,true,true),RecoveryDecision::BooksOnly);
    }
    #[test] fn unhashed_local_backup_never_authorizes_recovery(){
        let mut j=journal("backup-saved");
        assert_eq!(recovery_decision(&j,false,true),RecoveryDecision::Ambiguous);
        j.original_hash=Some("valid-hash".into());
        assert_eq!(recovery_decision(&j,false,true),RecoveryDecision::LocalOriginal);
    }
    #[test] fn pre_export_failure_needs_only_media_cleanup(){
        assert_eq!(recovery_decision(&journal("host-started"),false,false),RecoveryDecision::MediaOnly);
        assert_eq!(recovery_decision(&journal("host-started"),true,false),RecoveryDecision::RemoteOriginal);
    }
    #[test] fn errors_do_not_expose_full_imsi(){
        let text="неверная ссылка 250011234567890; SIM 1; 24A435";
        assert_eq!(redact(text),"неверная ссылка [скрыто]; SIM 1; 24A435");
    }
    #[test] fn destination_names_cannot_escape_media(){
        assert!(valid_stage_name("airlift-src-0123456789abcdefabcd","airlift-src-"));
        assert!(!valid_stage_name("airlift-src-../../Library","airlift-src-"));
        assert!(!valid_stage_name("airlift-src-0123456789ABCDEFABCD","airlift-src-"));
    }
    #[test] fn interrupted_books_resume_accepts_only_known_object_values(){
        let before=Tree::from([("Books.plist".into(),Node::file(b"old".to_vec())),
            ("db".into(),Node::file(b"old db".to_vec()))]);
        let desired=Tree::from([("Books.plist".into(),Node::file(b"new".to_vec())),
            ("db".into(),Node::file(b"new db with WAL rows".to_vec()))]);
        let mut partial=before.clone();partial.insert("Books.plist".into(),desired["Books.plist"].clone());
        assert!(interrupted_books_match(&before,&desired,&partial));
        partial.insert("db".into(),Node::file(b"new unrelated purchases".to_vec()));
        assert!(!interrupted_books_match(&before,&desired,&partial));
    }
    #[test] fn interrupted_books_resume_cannot_discard_new_file(){
        let mut current=Tree::new();current.insert("Books.plist".into(),Node::file(b"new user book".to_vec()));
        assert!(!interrupted_books_match(&Tree::new(),&Tree::new(),&current));
    }
    #[test] fn pending_recovery_knows_exact_three_owned_ids(){
        let mut j=journal("staging");j.source="airlift-src-0123456789abcdefabcd".into();
        j.exported="airlift-saved-0123456789abcdefabcd".into();
        let read_ids=stage_asset_ids(&j);assert_eq!(read_ids.len(),3);
        assert_eq!(read_ids[2],format!("../../{}",j.exported));
        j.payload_hash=Some("hash".into());
        assert_eq!(stage_asset_ids(&j)[2],format!("../../{}/{PAYLOAD_PATH}",j.source));
        assert!(stage_asset_ids(&j)[1].ends_with("Library/Carrier Bundles/iPhone"));
    }
}

#[cfg(test)]
#[path = "carrier_transport_tests.rs"]
mod transport_tests;
