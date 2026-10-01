//! Repackage only this CarrierSIM, sign locally with an imported P12/profile.
//! P12/private keys never enter the exported app, JSON or logs.
use std::{ffi::{c_char,c_void}, fs::{self,File}, io::Read, os::unix::fs::PermissionsExt,
    path::{Path,PathBuf}, time::SystemTime};
use apple_codesign::{AppleCertificate, KnownCertificate, SettingsScope, SigningSettings, UnifiedSigner,
    cryptography::{parse_pfx_data,PrivateKey}, verify_macho_data};
use plist::{Dictionary,Value};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest,Sha256};
use zeroize::Zeroizing;
use crate::{carrier_data::digest,exploit::{Logger,ALLogCallback},ffi_util};

type Result<T>=std::result::Result<T,String>;
const APP_ID:&str="com.tema.CarrierSIM";
const EXT_ID:&str="com.tema.CarrierSIM.Tunnel";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request { expected_device_hash:String }
struct Profile { raw:Vec<u8>, entitlements:String, team:String }
struct Cleanup(PathBuf);
impl Drop for Cleanup {fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}

fn limited(path:&Path,maximum:u64)->Result<Vec<u8>> {
    let file=File::open(path).map_err(|_|"Не удалось открыть файл подписи.".to_string())?;
    let size=file.metadata().map_err(|_|"Не удалось прочитать файл подписи.".to_string())?.len();
    if size==0 || size>maximum {return Err("Файл подписи пустой или слишком большой.".into());}
    let mut bytes=Vec::new();file.take(maximum+1).read_to_end(&mut bytes).map_err(|_|"Файл подписи недоступен.".to_string())?;
    if bytes.len() as u64>maximum {return Err("Файл подписи слишком большой.".into());} Ok(bytes)
}
fn allows_identifier(pattern:&str,actual:&str)->bool {
    pattern==actual || pattern.strip_suffix(".*").is_some_and(|prefix|actual.starts_with(&format!("{prefix}.")))
}
fn eligible_device(profile:&Dictionary,hash:&str)->bool {
    profile.get("ProvisionsAllDevices").and_then(Value::as_boolean)==Some(true) ||
        profile.get("ProvisionedDevices").and_then(Value::as_array).is_some_and(|devices|devices.iter().any(|v|
            v.as_string().is_some_and(|id|[id.to_string(),id.to_lowercase(),id.to_uppercase()].iter().any(|s|digest(s.as_bytes())==hash))))
}
fn profile_values(profile:&Dictionary,cert_der:&[u8],hash:&str,bundle:&str,vpn:bool)->Result<(String,String)> {
    let now=SystemTime::now();
    let expiration=profile.get("ExpirationDate").and_then(Value::as_date).map(SystemTime::from)
        .ok_or("В профиле нет срока действия.")?;
    if expiration<=now {return Err("Профиль установки просрочен. Получи новый в сервисе сертификата.".into());}
    if profile.get("CreationDate").and_then(Value::as_date).map(SystemTime::from).is_some_and(|date|date>now) {
        return Err("Профиль ещё не действует. Проверь дату телефона.".into());
    }
    if !eligible_device(profile,hash) {return Err("Профиль не разрешает iPhone друга. Добавь его UDID у поставщика сертификата и получи новый .mobileprovision. Профиль App Store для этого не подходит.".into());}
    if !profile.get("DeveloperCertificates").and_then(Value::as_array).is_some_and(|a|a.iter().any(|v|v.as_data()==Some(cert_der))) {
        return Err("P12 и .mobileprovision принадлежат разным сертификатам.".into());
    }
    let permitted=profile.get("Entitlements").and_then(Value::as_dictionary).ok_or("В профиле нет разрешений.")?;
    let application=permitted.get("application-identifier").and_then(Value::as_string).ok_or("В профиле нет application-identifier.")?;
    let prefix=profile.get("ApplicationIdentifierPrefix").and_then(Value::as_array).and_then(|a|a.first()).and_then(Value::as_string)
        .ok_or("В профиле нет префикса приложения.")?;
    let actual=format!("{prefix}.{bundle}");
    if !allows_identifier(application,&actual) {return Err(format!("Профиль не разрешает {bundle}. Нужен профиль для этого идентификатора или подходящий wildcard-профиль."));}
    let team=profile.get("TeamIdentifier").and_then(Value::as_array).and_then(|a|a.first()).and_then(Value::as_string)
        .ok_or("В профиле нет TeamIdentifier.")?.to_string();
    if let Some(value)=permitted.get("com.apple.developer.team-identifier") {
        if value.as_string()!=Some(team.as_str()) {return Err("Профиль содержит противоречивый TeamIdentifier.".into());}
    }
    let mut entitlements=Dictionary::new();
    entitlements.insert("application-identifier".into(),Value::String(actual));
    entitlements.insert("com.apple.developer.team-identifier".into(),Value::String(team.clone()));
    entitlements.insert("get-task-allow".into(),Value::Boolean(false));
    if vpn {
        let key="com.apple.developer.networking.networkextension";
        let allowed=permitted.get(key).and_then(Value::as_array).is_some_and(|a|a.iter().any(|v|v.as_string()==Some("packet-tunnel-provider")));
        if !allowed {return Err(format!("Профиль {bundle} не разрешает встроенный VPN. Нужны профили Network Extension для приложения и расширения; либо отправь вариант без встроенного VPN."));}
        entitlements.insert(key.into(),Value::Array(vec![Value::String("packet-tunnel-provider".into())]));
    }
    let mut xml=Vec::new();Value::Dictionary(entitlements).to_writer_xml(&mut xml).map_err(|_|"Не удалось подготовить разрешения подписи.".to_string())?;
    Ok((String::from_utf8(xml).map_err(|_|"Неверные разрешения подписи.".to_string())?,team))
}
fn profile(path:&Path,cert_der:&[u8],hash:&str,bundle:&str,vpn:bool)->Result<Profile> {
    let raw=limited(path,4*1024*1024)?;
    let signed=cms::SignedData::parse_ber(&raw).map_err(|_|"Нужен оригинальный подписанный .mobileprovision, не XML/plist.".to_string())?;
    let signers:Vec<_>=signed.signers().collect();
    if signers.is_empty(){return Err("В профиле отсутствует подпись.".into());}
    for signer in signers {
        signer.verify_signature_with_signed_data(&signed).map_err(|_|"Подпись .mobileprovision повреждена.".to_string())?;
        if signer.signed_attributes().is_some() {
            signer.verify_message_digest_with_signed_data(&signed).map_err(|_|"Содержимое .mobileprovision изменено после подписи.".to_string())?;
        }
        let (issuer,serial)=signer.certificate_issuer_and_serial().ok_or("Не определён подписант профиля.")?;
        let cert=signed.certificates().find(|c|c.issuer_name()==issuer && c.serial_number_asn1()==serial)
            .ok_or("В профиле нет сертификата подписанта.")?;
        let chain=cert.resolve_signing_chain(signed.certificates().chain(KnownCertificate::all().iter().copied()));
        if !cert.is_apple_root_ca() && !chain.iter().any(|c|c.is_apple_root_ca()) {
            return Err("Профиль не подписан доверенной цепочкой Apple.".into());
        }
    }
    let content=signed.signed_content().ok_or("В профиле нет содержимого.")?;
    let value=Value::from_reader(std::io::Cursor::new(content)).map_err(|_|"Повреждён профиль установки.".to_string())?;
    let (entitlements,team)=profile_values(value.as_dictionary().ok_or("Неверный профиль.")?,cert_der,hash,bundle,vpn)?;
    Ok(Profile{raw,entitlements,team})
}
fn copy_bundle(source:&Path,dest:&Path,total:&mut u64,count:&mut usize)->Result<()> {
    fs::create_dir_all(dest).map_err(|_|"Недостаточно места для копии CarrierSIM.".to_string())?;
    fs::set_permissions(dest,fs::Permissions::from_mode(0o700)).map_err(|e|e.to_string())?;
    for entry in fs::read_dir(source).map_err(|e|e.to_string())? {
        let entry=entry.map_err(|e|e.to_string())?;
        *count+=1;if *count>30000{return Err("Слишком много файлов в приложении.".into());}
        let kind=entry.file_type().map_err(|e|e.to_string())?;
        if kind.is_symlink(){return Err("Неожиданная ссылка в пакете CarrierSIM.".into());}
        let target=dest.join(entry.file_name());
        if kind.is_dir(){copy_bundle(&entry.path(),&target,total,count)?;}
        else if kind.is_file(){
            *total=total.checked_add(entry.metadata().map_err(|e|e.to_string())?.len()).ok_or("Пакет слишком большой.")?;
            if *total>512*1024*1024{return Err("Пакет CarrierSIM превышает 512 МБ.".into());}
            fs::copy(entry.path(),&target).map_err(|_|"Не удалось скопировать CarrierSIM. Освободи память.".to_string())?;
        } else {return Err("Необычный тип файла в CarrierSIM.".into());}
    } Ok(())
}
fn zip_tree(root:&Path,dir:&Path,archive:&mut zip::ZipWriter<File>)->Result<()> {
    let mut entries=fs::read_dir(dir).map_err(|e|e.to_string())?.collect::<std::result::Result<Vec<_>,_>>().map_err(|e|e.to_string())?;
    entries.sort_by_key(|e|e.file_name());
    for entry in entries {
        let path=entry.path();let metadata=fs::symlink_metadata(&path).map_err(|e|e.to_string())?;
        if metadata.is_dir(){zip_tree(root,&path,archive)?;}
        else if metadata.is_file(){
            let name=path.strip_prefix(root).map_err(|e|e.to_string())?.to_str().ok_or("Неверный путь в пакете.")?;
            archive.start_file(name,zip::write::SimpleFileOptions::default().unix_permissions(metadata.permissions().mode()).compression_method(zip::CompressionMethod::Deflated))
                .map_err(|_|"Не удалось упаковать IPA.".to_string())?;
            std::io::copy(&mut File::open(path).map_err(|e|e.to_string())?,archive).map_err(|_|"Не удалось сохранить IPA.".to_string())?;
        } else {return Err("Недопустимый файл в подготовленном приложении.".into());}
    } Ok(())
}

fn sign(source:&Path,work:&Path,p12:&Path,password:&str,main_profile:&Path,extension_profile:Option<&Path>,request:Request,logger:&Logger)->Result<serde_json::Value> {
    if request.expected_device_hash.len()!=64 || !request.expected_device_hash.bytes().all(|b|b.is_ascii_hexdigit()) {
        return Err("Сначала проверь iPhone друга, которому предназначена подпись.".into());
    }
    let _lock=crate::carrier::OpLock::acquire(work)?;
    if crate::carrier::needs_recovery(work,&request.expected_device_hash)? {return Err("Сначала восстанови прерванную операцию CarrierSIM.".into());}
    let info=Value::from_file(source.join("Info.plist")).map_err(|_|"Не найден собственный пакет CarrierSIM.".to_string())?;
    let metadata=info.as_dictionary().ok_or("Повреждён Info.plist CarrierSIM.")?;
    if metadata.get("CFBundleExecutable").and_then(Value::as_string)!=Some("CarrierSIM") || !source.join("assets.zip").is_file() {
        return Err("Подписывать этим действием можно только текущий CarrierSIM.".into());
    }
    let secret=Zeroizing::new(limited(p12,8*1024*1024)?);
    let password=Zeroizing::new(password.to_string());
    let (certificate,key)=parse_pfx_data(&secret,&password).map_err(|_|"Не удалось открыть P12. Проверь пароль и наличие закрытого ключа в сертификате.".to_string())?;
    if !certificate.time_constraints_valid(None){return Err("Сертификат ещё не действует или просрочен.".into());}
    if !certificate.chains_to_apple_root_ca(){return Err("P12 не содержит сертификат подписи с доверенной цепочкой Apple.".into());}
    if key.as_key_info_signer().public_key_data()!=certificate.public_key_data(){return Err("Закрытый ключ P12 не соответствует сертификату.".into());}
    let der=certificate.encode_der().map_err(|_|"Не удалось прочитать сертификат.".to_string())?;
    let has_extension=source.join("PlugIns/CarrierSIMTunnel.appex").is_dir();
    let with_vpn=has_extension && extension_profile.is_some();
    let main=profile(main_profile,&der,&request.expected_device_hash,APP_ID,with_vpn)?;
    let extension=if with_vpn {Some(profile(extension_profile.unwrap(),&der,&request.expected_device_hash,EXT_ID,true)?)} else {None};
    if extension.as_ref().is_some_and(|p|p.team!=main.team){return Err("Профили приложения и VPN принадлежат разным командам.".into());}
    let temp=work.join(format!("share-{}",SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_err(|e|e.to_string())?.as_nanos()));
    let _cleanup=Cleanup(temp.clone());let app=temp.join("Payload/CarrierSIM.app");
    logger.log("Копирую текущий CarrierSIM и подписываю локально…");
    copy_bundle(source,&app,&mut 0,&mut 0)?;
    let mut info=metadata.clone();info.insert("CFBundleIdentifier".into(),Value::String(APP_ID.into()));
    Value::Dictionary(info).to_file_binary(app.join("Info.plist")).map_err(|e|e.to_string())?;
    if !with_vpn && app.join("PlugIns").exists(){fs::remove_dir_all(app.join("PlugIns")).map_err(|e|e.to_string())?;}
    let sign_one=|bundle:&Path,profile:&Profile|->Result<()> {
        fs::write(bundle.join("embedded.mobileprovision"),&profile.raw).map_err(|e|e.to_string())?;
        let mut settings=SigningSettings::default();settings.set_signing_key(key.as_key_info_signer(),certificate.clone());
        settings.chain_apple_certificates();settings.set_team_id(&profile.team);settings.set_for_notarization(false);settings.set_shallow(true);
        settings.set_entitlements_xml(SettingsScope::Main,&profile.entitlements).map_err(|_|"Не удалось подготовить подпись.".to_string())?;
        UnifiedSigner::new(settings).sign_path_in_place(bundle).map_err(|_|"Не удалось подписать пакет CarrierSIM. Проверь P12 и профили.".to_string())?;
        let metadata=Value::from_file(bundle.join("Info.plist")).map_err(|e|e.to_string())?;
        let binary=metadata.as_dictionary().and_then(|d|d.get("CFBundleExecutable")).and_then(Value::as_string).ok_or("Нет исполняемого файла.")?;
        let signed=fs::read(bundle.join(binary)).map_err(|e|e.to_string())?;
        if !verify_macho_data(&signed).is_empty(){return Err("Проверка созданной криптографической подписи не прошла. IPA не будет отправлен.".into());}
        Ok(())
    };
    if let Some(profile)=&extension {
        let path=app.join("PlugIns/CarrierSIMTunnel.appex");
        let mut info=Value::from_file(path.join("Info.plist")).map_err(|e|e.to_string())?;
        info.as_dictionary_mut().ok_or("Повреждён пакет VPN.")?.insert("CFBundleIdentifier".into(),Value::String(EXT_ID.into()));
        info.to_file_binary(path.join("Info.plist")).map_err(|e|e.to_string())?;
        sign_one(&path,profile)?;
    }
    sign_one(&app,&main)?;
    let staged=temp.join("signed.ipa");let mut archive=zip::ZipWriter::new(File::create(&staged).map_err(|e|e.to_string())?);
    zip_tree(&temp,&temp.join("Payload"),&mut archive)?;archive.finish().map_err(|e|e.to_string())?;
    let output=work.join("CarrierSIM-for-friend.ipa");
    fs::set_permissions(&staged,fs::Permissions::from_mode(0o600)).map_err(|e|e.to_string())?;
    fs::rename(&staged,&output).map_err(|_|"Не удалось сохранить подписанный IPA.".to_string())?;
    let mut hasher=Sha256::new();let mut buffer=[0u8;65536];let mut file=File::open(&output).map_err(|e|e.to_string())?;
    loop {let n=file.read(&mut buffer).map_err(|e|e.to_string())?;if n==0{break;}hasher.update(&buffer[..n]);}
    logger.log("Криптографическая подпись и разрешение целевого устройства проверены. Готовлю установку через службы iOS…");
    Ok(json!({"signed":true,"ipa_path":output,"sha256":hex::encode(hasher.finalize()),"with_vpn":with_vpn,"expected_device_hash":request.expected_device_hash}))
}

#[no_mangle]
pub unsafe extern "C" fn cs_sign_self(app_path:*const c_char,work_dir:*const c_char,p12_path:*const c_char,password:*const c_char,
    profile_path:*const c_char,extension_profile_path:*const c_char,request_json:*const c_char,cb:ALLogCallback,ctx:*mut c_void,
    result_json:*mut *mut c_char,error:*mut *mut c_char)->i32 {
    if !result_json.is_null(){*result_json=std::ptr::null_mut();}if !error.is_null(){*error=std::ptr::null_mut();}
    let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||{
        let source=ffi_util::opt_str(app_path,"");let work=ffi_util::opt_str(work_dir,"");let p12=ffi_util::opt_str(p12_path,"");
        let profile=ffi_util::opt_str(profile_path,"");let extension=ffi_util::opt_str(extension_profile_path,"");let text=ffi_util::opt_str(request_json,"");
        if [&source,&work,&p12,&profile,&text].iter().any(|s|s.is_empty()) || text.len()>8192 {return Err("Выбери P12, профиль установки и проверенный iPhone друга.".into());}
        let request:Request=serde_json::from_str(&text).map_err(|_|"Неверный запрос подписи.".to_string())?;
        let password=Zeroizing::new(ffi_util::opt_str(password,""));let logger=Logger{cb,ctx};
        ffi_util::run_with_large_stack("CarrierSIMSigning",move || {
            sign(Path::new(&source),Path::new(&work),Path::new(&p12),&password,Path::new(&profile),
                if extension.is_empty(){None}else{Some(Path::new(&extension))},request,&logger)
        })?
    })).unwrap_or_else(|_|Err("Подпись прервалась. Приложение не отправлено.".into()));
    match result {
        Ok(value)=>{if !result_json.is_null(){*result_json=ffi_util::cstr(value.to_string());}0},
        Err(message)=>{if !error.is_null(){*error=ffi_util::cstr(message);}1},
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn wildcard_is_restricted_to_its_identifier_prefix() {
        assert!(allows_identifier("TEAM.*","TEAM.com.tema.CarrierSIM"));
        assert!(allows_identifier("TEAM.com.tema.*","TEAM.com.tema.CarrierSIM"));
        assert!(!allows_identifier("TEAM.com.tema.*","TEAM.com.tema2.CarrierSIM"));
        assert!(!allows_identifier("TEAM.*","OTHER.com.tema.CarrierSIM"));
        assert!(!allows_identifier("TEAM.com.tema.CarrierSIM","TEAM.com.tema.Other"));
    }
    #[test] fn app_store_and_wrong_udid_profiles_cannot_be_shared() {
        let mut profile=Dictionary::new();let id="00000000-abcdefabcdef1234";
        assert!(!eligible_device(&profile,&digest(id.as_bytes())));
        profile.insert("ProvisionedDevices".into(),Value::Array(vec![Value::String(id.into())]));
        assert!(eligible_device(&profile,&digest(id.to_uppercase().as_bytes())));
        assert!(!eligible_device(&profile,&"0".repeat(64)));
        profile.insert("ProvisionsAllDevices".into(),Value::Boolean(true));
        assert!(eligible_device(&profile,&"0".repeat(64)));
    }
    #[test] fn appended_xml_is_not_a_provisioning_signature() {
        assert!(cms::SignedData::parse_ber(b"garbage<plist><dict/></plist>").is_err());
    }
    fn profile_fixture()->Dictionary {
        let mut p=Dictionary::new();
        p.insert("ExpirationDate".into(),Value::Date((SystemTime::now()+std::time::Duration::from_secs(3600)).into()));
        p.insert("TeamIdentifier".into(),Value::Array(vec![Value::String("TEAM".into())]));
        p.insert("ApplicationIdentifierPrefix".into(),Value::Array(vec![Value::String("TEAM".into())]));
        p.insert("DeveloperCertificates".into(),Value::Array(vec![Value::Data(vec![1,2,3])]));
        p.insert("ProvisionedDevices".into(),Value::Array(vec![Value::String("TEST-IPHONE".into())]));
        let mut e=Dictionary::new();e.insert("application-identifier".into(),Value::String("TEAM.*".into()));
        e.insert("com.apple.developer.team-identifier".into(),Value::String("TEAM".into()));
        p.insert("Entitlements".into(),Value::Dictionary(e));p
    }
    #[test] fn profile_rejects_expiration_wrong_certificate_and_missing_vpn_permission() {
        let mut p=profile_fixture();let hash=digest(b"TEST-IPHONE");
        let (xml,team)=profile_values(&p,&[1,2,3],&hash,APP_ID,false).unwrap();
        assert_eq!(team,"TEAM");assert!(xml.contains("TEAM.com.tema.CarrierSIM"));assert!(!xml.contains("TEAM.*"));
        assert!(profile_values(&p,&[9],&hash,APP_ID,false).unwrap_err().contains("разным сертификатам"));
        assert!(profile_values(&p,&[1,2,3],&hash,APP_ID,true).unwrap_err().contains("VPN"));
        p.insert("ExpirationDate".into(),Value::Date(SystemTime::UNIX_EPOCH.into()));
        assert!(profile_values(&p,&[1,2,3],&hash,APP_ID,false).unwrap_err().contains("просрочен"));
    }
    #[test] fn imported_p12_signs_real_arm64_bundle_and_tampering_is_detected() {
        use std::process::{Command,Stdio};
        let root=std::env::temp_dir().join(format!("carriersim-sign-test-{}-{}",std::process::id(),SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir(&root).unwrap();fs::set_permissions(&root,fs::Permissions::from_mode(0o700)).unwrap();let _cleanup=Cleanup(root.clone());
        let run=|args:&[&str]|assert!(Command::new("openssl").args(args).current_dir(&root).stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap().success());
        run(&["req","-x509","-newkey","rsa:2048","-nodes","-keyout","test.key","-out","test.crt","-days","1","-subj","/CN=CarrierSIM TEST ONLY"]);
        run(&["pkcs12","-export","-inkey","test.key","-in","test.crt","-out","test.p12","-passout","pass:carriersim-test"]);
        let p12=Zeroizing::new(fs::read(root.join("test.p12")).unwrap());
        assert!(parse_pfx_data(&p12,"wrong-password").is_err());
        let (cert,key)=parse_pfx_data(&p12,"carriersim-test").unwrap();
        assert_eq!(cert.public_key_data(),key.as_key_info_signer().public_key_data());
        assert!(!cert.chains_to_apple_root_ca());
        let app=root.join("Payload/CarrierSIM.app");fs::create_dir_all(&app).unwrap();
        fs::write(app.join("Fixture"),include_bytes!("../../Tests/fixtures/unsigned-arm64.macho")).unwrap();
        fs::set_permissions(app.join("Fixture"),fs::Permissions::from_mode(0o755)).unwrap();
        let mut info=Dictionary::new();
        for (k,v) in [("CFBundleIdentifier","com.tema.CarrierSIM.test"),("CFBundleExecutable","Fixture"),("CFBundlePackageType","APPL"),("CFBundleVersion","1"),("CFBundleShortVersionString","1.0")]{info.insert(k.into(),Value::String(v.into()));}
        Value::Dictionary(info).to_file_xml(app.join("Info.plist")).unwrap();
        let mut settings=SigningSettings::default();settings.set_signing_key(key.as_key_info_signer(),cert.clone());settings.set_shallow(true);settings.set_for_notarization(false);
        settings.set_entitlements_xml(SettingsScope::Main,"<plist version=\"1.0\"><dict><key>application-identifier</key><string>TEST.com.tema.CarrierSIM.test</string></dict></plist>").unwrap();
        UnifiedSigner::new(settings).sign_path_in_place(&app).unwrap();
        let signed=fs::read(app.join("Fixture")).unwrap();
        assert!(verify_macho_data(&signed).is_empty(),"{:?}",verify_macho_data(&signed));
        let mut altered=signed;altered[4096]^=1;assert!(!verify_macho_data(&altered).is_empty());
        let mut archive=zip::ZipWriter::new(File::create(root.join("signed.ipa")).unwrap());zip_tree(&root,&root.join("Payload"),&mut archive).unwrap();archive.finish().unwrap();
        let archive=zip::ZipArchive::new(File::open(root.join("signed.ipa")).unwrap()).unwrap();
        assert!(archive.file_names().all(|name|name.starts_with("Payload/") && !name.ends_with(".p12") && !name.ends_with(".key")));
        Value::Dictionary(profile_fixture()).to_file_xml(root.join("profile.plist")).unwrap();
        run(&["cms","-sign","-binary","-in","profile.plist","-signer","test.crt","-inkey","test.key","-outform","DER","-nodetach","-out","untrusted.mobileprovision"]);
        let error=profile(&root.join("untrusted.mobileprovision"),&cert.encode_der().unwrap(),&digest(b"TEST-IPHONE"),APP_ID,false).err().unwrap();
        assert!(error.contains("Apple"));
    }
}
