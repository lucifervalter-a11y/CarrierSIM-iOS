//! Install a user-selected, already signed IPA through Apple's device services.
//! Presence of provisioning files is a preflight only. iOS verifies the signature.
use std::{collections::BTreeSet, ffi::{c_char,c_void}, fs::File, io::{Read,Seek}, path::Path, time::{Duration,SystemTime,UNIX_EPOCH}};
use idevice::afc::opcode::AfcFopenMode;
use plist::Value;
use serde::Deserialize;
use serde_json::json;
use tokio::io::{AsyncReadExt,AsyncWriteExt};
use zip::ZipArchive;
use crate::{device_target::{DeviceTarget,verify_identity}, exploit::{self,ALLogCallback,Logger}, ffi_util};

const MAX_IPA: u64 = 512 * 1024 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallRequest { target: DeviceTarget, expected_device_hash: String }
#[derive(Debug)]
struct Package { bundle_id: String, display_name: String, minimum_ios: String }

fn version(text: &str) -> Result<Vec<u32>,String> {
    if text.is_empty() || text.len()>32 { return Err("Неверная версия iOS в IPA.".into()); }
    let mut parts: Vec<u32> = text.split('.').map(|p| p.parse().map_err(|_| "Неверная версия iOS в IPA.".to_string())).collect::<Result<_,_>>()?;
    if parts.len()>3 { return Err("Неверная версия iOS в IPA.".into()); }
    parts.resize(3,0); Ok(parts)
}
fn read_entry<R: Read+Seek>(z: &mut ZipArchive<R>, name: &str, maximum: u64) -> Result<Vec<u8>,String> {
    let mut entry=z.by_name(name).map_err(|_|format!("В IPA отсутствует {name}."))?;
    if entry.size()==0 || entry.size()>maximum { return Err("Служебный файл IPA пустой или слишком большой.".into()); }
    let mut bytes=Vec::new(); entry.read_to_end(&mut bytes).map_err(|e|format!("Повреждён ZIP: {e}"))?; Ok(bytes)
}
fn inspect<R: Read+Seek>(reader:R) -> Result<Package,String> {
    let mut z=ZipArchive::new(reader).map_err(|e|format!("Это не IPA: {e}"))?;
    if z.len()>100000 { return Err("В IPA слишком много файлов.".into()); }
    let mut names=BTreeSet::new(); let mut roots=BTreeSet::new(); let mut total=0u64;
    for i in 0..z.len() {
        let e=z.by_index(i).map_err(|e|e.to_string())?;
        let name=e.name();
        if name.starts_with('/') || name.contains('\\') || name.contains('\0') || name.split('/').any(|p|p==".." || p==".") || !names.insert(name.to_string()) {
            return Err("Недопустимые или повторяющиеся пути в IPA.".into());
        }
        total=total.checked_add(e.size()).ok_or("IPA слишком большой.")?;
        if total>2*1024*1024*1024 { return Err("Распакованный IPA превышает 2 ГБ.".into()); }
        let p: Vec<_>=name.split('/').collect();
        if p.len()==3 && p[0]=="Payload" && p[1].ends_with(".app") && p[2]=="Info.plist" { roots.insert(format!("Payload/{}",p[1])); }
    }
    if roots.len()!=1 { return Err("В IPA должно быть ровно одно приложение в Payload.".into()); }
    let root=roots.into_iter().next().unwrap();
    let bytes=read_entry(&mut z,&format!("{root}/Info.plist"),1024*1024)?;
    let info=Value::from_reader(std::io::Cursor::new(bytes)).map_err(|e|e.to_string())?;
    let info=info.as_dictionary().ok_or("Info.plist не является словарём.")?;
    let string=|key:&str| info.get(key).and_then(Value::as_string).unwrap_or("").to_string();
    let bundle_id=string("CFBundleIdentifier"); let executable=string("CFBundleExecutable");
    if bundle_id.is_empty() || executable.is_empty() || executable.contains('/') || !names.contains(&format!("{root}/{executable}")) {
        return Err("В IPA отсутствуют идентификатор или исполняемый файл приложения.".into());
    }
    let mut bundles=vec![root.clone()];
    for name in &names {
        if name.starts_with(&format!("{root}/PlugIns/")) && name.ends_with(".appex/Info.plist") {
            bundles.push(name.trim_end_matches("/Info.plist").to_string());
        }
    }
    for bundle in bundles {
        read_entry(&mut z,&format!("{bundle}/embedded.mobileprovision"),4*1024*1024)
            .map_err(|_|"Этот IPA не подготовлен для установки. Подпиши приложение и все расширения для iPhone друга в DDE Store или другом сервисе. Подпись для твоего iPhone может ему не подойти.".to_string())?;
        read_entry(&mut z,&format!("{bundle}/_CodeSignature/CodeResources"),8*1024*1024)
            .map_err(|_|"В IPA отсутствуют ресурсы подписи приложения или расширения. Подпиши полный IPA заново.".to_string())?;
    }
    let display_name=string("CFBundleDisplayName");
    let minimum_ios=string("MinimumOSVersion"); version(&minimum_ios)?;
    Ok(Package{display_name:if display_name.is_empty(){bundle_id.clone()}else{display_name},bundle_id,minimum_ios})
}

async fn install(pairing:&Path, ipa:&Path, request:InstallRequest, logger:&Logger)->Result<serde_json::Value,String> {
    request.target.address()?;
    let file=File::open(ipa).map_err(|_|"Не удалось открыть выбранный IPA.".to_string())?;
    let length=file.metadata().map_err(|e|e.to_string())?.len();
    if length==0 || length>MAX_IPA { return Err("Выбери IPA размером от 1 байта до 512 МБ.".into()); }
    let package=inspect(file)?;
    let bytes=std::fs::read(pairing).map_err(|_|"Нет сопряжения с iPhone друга.".to_string())?;
    if bytes.len()>1024*1024 { return Err("Файл сопряжения слишком большой.".into()); }
    let mut tunnel=exploit::connect_tunnel_for_target(&bytes,logger,Some(&request.target)).await?;
    let device=crate::carrier::device_info(&mut tunnel).await?;
    verify_identity(Some(&request.expected_device_hash),&device.udid_hash,true)?;
    if version(&device.ios)? < version(&package.minimum_ios)? { return Err(format!("IPA требует iOS {}, на iPhone друга установлена {}.",package.minimum_ios,device.ios)); }
    let mut afc=tokio::time::timeout(Duration::from_secs(30),tunnel.connect_afc(logger)).await.map_err(|_|"AFC не ответил.".to_string())??;
    match tokio::time::timeout(Duration::from_secs(30),afc.get_file_info("PublicStaging")).await {
        Ok(Ok(info)) if info.st_ifmt=="S_IFDIR" => (),
        Ok(Err(_)) => tokio::time::timeout(Duration::from_secs(30),afc.mk_dir("PublicStaging")).await.map_err(|_|"Не удалось создать PublicStaging.".to_string())?.map_err(|e|e.to_string())?,
        _ => return Err("PublicStaging недоступен или не является каталогом.".into()),
    }
    let nonce=SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e|e.to_string())?.as_nanos();
    let staging=format!("PublicStaging/CarrierSIM-{nonce}.ipa");
    let outcome=async {
        logger.log(format!("Передаю {} на проверенный iPhone друга…",package.display_name));
        let mut local=tokio::fs::File::open(ipa).await.map_err(|e|e.to_string())?;
        let mut remote=tokio::time::timeout(Duration::from_secs(30),afc.open(&staging,AfcFopenMode::WrOnly)).await.map_err(|_|"AFC не открыл IPA.".to_string())?.map_err(|e|e.to_string())?;
        let mut buffer=vec![0u8;256*1024]; let mut sent=0u64; let mut last=0u64;
        loop {
            let count=local.read(&mut buffer).await.map_err(|e|e.to_string())?; if count==0 {break;}
            tokio::time::timeout(Duration::from_secs(30),remote.write_all(&buffer[..count])).await.map_err(|_|"Передача прервалась. Проверь Wi-Fi и повтори установку.".to_string())?.map_err(|e|e.to_string())?;
            sent+=count as u64;
            let percent=sent*100/length;
            if percent>=last+10 {logger.log(format!("Передача IPA: {percent}%"));last=percent;}
        }
        tokio::time::timeout(Duration::from_secs(30),remote.close()).await.map_err(|_|"AFC не подтвердил закрытие файла.".to_string())?.map_err(|e|e.to_string())?;
        if sent!=length {return Err("Выбранный IPA изменился во время передачи.".into());}
        let uploaded=tokio::time::timeout(Duration::from_secs(30),afc.get_file_info(&staging)).await.map_err(|_|"Не удалось проверить передачу.".to_string())?.map_err(|e|e.to_string())?;
        if uploaded.size as u64!=length {return Err("Размер переданного IPA не совпадает.".into());}
        // Re-read identity immediately before requesting an installation.
        let current=crate::carrier::device_info(&mut tunnel).await?;
        verify_identity(Some(&request.expected_device_hash),&current.udid_hash,true)?;
        let mut proxy=tokio::time::timeout(Duration::from_secs(30),tunnel.connect_installation_proxy(logger)).await.map_err(|_|"Служба установки недоступна.".to_string())??;
        logger.log("iOS проверяет подпись и устанавливает приложение…");
        tokio::time::timeout(Duration::from_secs(300),proxy.install(&staging,None)).await
            .map_err(|_|"Нет подтверждения установки. Она могла продолжиться на iPhone друга — проверь экран и журнал перед повтором.".to_string())?
            .map_err(|e|format!("iOS отказала в установке: {e}. Проверь срок сертификата и регистрацию iPhone друга в профиле подписи."))?;
        let apps=tokio::time::timeout(Duration::from_secs(30),proxy.get_apps(Some("Any"),Some(vec![package.bundle_id.clone()]))).await
            .map_err(|_|"iOS завершила установку, но не ответила на проверку списка приложений.".to_string())?.map_err(|e|e.to_string())?;
        if !apps.contains_key(&package.bundle_id) {return Err("iOS завершила установку, но приложение не найдено в списке. Проверь iPhone друга.".into());}
        Ok(json!({"installed":true,"bundle_id":package.bundle_id,"display_name":package.display_name,"device":device.public(),"message":"iOS подтвердила установку; приложение найдено на iPhone друга. Открой его на телефоне друга."}))
    }.await;
    if !matches!(tokio::time::timeout(Duration::from_secs(15),afc.remove(&staging)).await,Ok(Ok(()))) {
        logger.log("Временный IPA в PublicStaging не удалось удалить. Повторная установка использует отдельный файл.");
    }
    outcome
}

/// Blocking C entry point. Output strings are owned by the caller and use
/// al_string_free. No Apple credentials, signing or signature bypass.
#[no_mangle]
pub unsafe extern "C" fn cs_install_ipa(pairing_path:*const c_char,ipa_path:*const c_char,request_json:*const c_char,
    cb:ALLogCallback,ctx:*mut c_void,result_json:*mut *mut c_char,error:*mut *mut c_char)->i32 {
    if !result_json.is_null(){*result_json=std::ptr::null_mut();}
    if !error.is_null(){*error=std::ptr::null_mut();}
    let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let pairing=ffi_util::opt_str(pairing_path,""); let ipa=ffi_util::opt_str(ipa_path,""); let text=ffi_util::opt_str(request_json,"");
        if pairing.is_empty() || ipa.is_empty() || text.len()>8192 {return Err("Неверный запрос установки.".to_string());}
        let request:InstallRequest=serde_json::from_str(&text).map_err(|e|e.to_string())?;
        let logger=Logger{cb,ctx};
        idevice_ffi::run_sync_local(install(Path::new(&pairing),Path::new(&ipa),request,&logger))
    })).unwrap_or_else(|_|Err("Установка прервалась. Проверь iPhone друга перед повтором.".into()));
    match result {
        Ok(value)=>{if !result_json.is_null(){*result_json=ffi_util::cstr(value.to_string());}0},
        Err(message)=>{if !error.is_null(){*error=ffi_util::cstr(message);}1}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor,Write};
    fn fixture(signed:bool,extension:bool,extra:Option<&str>)->Cursor<Vec<u8>> {
        let mut z=zip::ZipWriter::new(Cursor::new(Vec::new()));
        let mut entries=vec![("Payload/Test.app/Info.plist",b"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>test.app</string><key>CFBundleExecutable</key><string>Test</string><key>MinimumOSVersion</key><string>26.0</string></dict></plist>".as_slice()),("Payload/Test.app/Test",b"placeholder")];
        if signed {entries.extend([("Payload/Test.app/embedded.mobileprovision",b"preflight only".as_slice()),("Payload/Test.app/_CodeSignature/CodeResources",b"preflight only")]);}
        if extension {entries.push(("Payload/Test.app/PlugIns/Tunnel.appex/Info.plist",b"placeholder"));}
        if let Some(path)=extra {entries.push((path,b"placeholder"));}
        for (name,data) in entries {z.start_file(name,zip::write::SimpleFileOptions::default()).unwrap();z.write_all(data).unwrap();}
        let mut reader=z.finish().unwrap();reader.set_position(0);reader
    }
    #[test] fn unsigned_package_is_rejected_before_network() {assert!(inspect(fixture(false,false,None)).unwrap_err().contains("DDE Store"));}
    #[test] fn every_extension_requires_provisioning() {assert!(inspect(fixture(true,true,None)).is_err());}
    #[test] fn traversal_and_multiple_apps_are_rejected() {
        assert!(inspect(fixture(true,false,Some("Payload/Test.app/../escape"))).is_err());
        assert!(inspect(fixture(true,false,Some("Payload/Other.app/Info.plist"))).is_err());
    }
    #[test] fn signed_structure_is_only_a_preflight() {
        let p=inspect(fixture(true,false,None)).unwrap();assert_eq!(p.bundle_id,"test.app");assert_eq!(p.minimum_ios,"26.0");
    }
    #[test] fn minimum_ios_uses_numeric_comparison() {
        assert!(version("27.0.1").unwrap()>version("26.9").unwrap());assert_eq!(version("26").unwrap(),version("26.0.0").unwrap());assert!(version("not-ios").is_err());
    }
}
