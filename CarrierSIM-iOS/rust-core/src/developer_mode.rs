//! Owner-authorized Developer Mode preparation. No automatic post-reboot accept.
use std::{ffi::{c_char,c_void}, path::Path, time::Duration};
use idevice::{IdeviceError, services::amfi::AmfiClient};
use serde::Deserialize;
use serde_json::{json, Value};
use crate::{carrier, device_target::{DeviceTarget,verify_identity}, exploit::{self,ALLogCallback,Logger}, ffi_util};

const SERVICE_TIMEOUT:Duration=Duration::from_secs(15);

#[derive(Clone,Copy,Debug,Deserialize,PartialEq)]
#[serde(rename_all="snake_case")]
enum Action { Status, Reveal, RequestEnable }

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    action:Action,
    #[serde(default)] target:Option<DeviceTarget>,
    #[serde(default)] expected_device_hash:Option<String>,
}

fn state(value:Option<&plist::Value>)->&'static str {
    match value.and_then(plist::Value::as_boolean) {
        Some(true)=>"on", Some(false)=>"off", None=>"unknown",
    }
}

async fn mode_status(tunnel:&mut exploit::AppDeviceTunnel)->String {
    match tokio::time::timeout(SERVICE_TIMEOUT,async {
        let mut ld=carrier::lockdown(tunnel).await?;
        ld.get_value(Some("DeveloperModeStatus"),Some("com.apple.security.mac.amfi"))
            .await.map_err(|e|e.to_string())
    }).await {
        Ok(Ok(value))=>state(Some(&value)).into(), _=>"unknown".into(),
    }
}

async fn amfi(tunnel:&mut exploit::AppDeviceTunnel,logger:&Logger)->Result<AmfiClient,String> {
    tokio::time::timeout(SERVICE_TIMEOUT,tunnel.connect_amfi(logger)).await
        .map_err(|_|"Служба AMFI не ответила за 15 секунд.".to_string())?
}

async fn execute(pairing:&Path,work:&Path,request:Request,logger:&Logger)->Result<Value,String> {
    if let Some(target)=&request.target {target.address()?;}
    if request.action!=Action::Status && request.expected_device_hash.as_ref()
        .is_none_or(|s|s.len()!=64 || !s.bytes().all(|b|b.is_ascii_hexdigit())) {
        return Err("Сначала проверь имя и модель выбранного iPhone в разделе режима разработчика.".into());
    }
    let _lock=carrier::OpLock::acquire(work)?;
    let bytes=std::fs::read(pairing).map_err(|_|"Создай или импортируй сопряжение с выбранным iPhone.".to_string())?;
    if bytes.is_empty() || bytes.len()>1024*1024 {return Err("Неверный размер файла сопряжения.".into());}
    let mut tunnel=tokio::time::timeout(Duration::from_secs(40),
        exploit::connect_tunnel_for_target(&bytes,logger,request.target.as_ref())).await
        .map_err(|_|"Телефон не подключился за 40 секунд. Проверь адрес, доступность службы и доверенное сопряжение. Для первоначальной подготовки может потребоваться компьютер.".to_string())??;
    let device=carrier::device_identity(&mut tunnel).await?;
    verify_identity(request.expected_device_hash.as_deref(),&device.udid_hash,request.action!=Action::Status)?;
    let recovery=carrier::needs_recovery(work,&device.udid_hash)?;
    let status=mode_status(&mut tunnel).await;
    let mut result=json!({"device":device.public(),"status":status,"stage":"checked",
        "amfi_available":false,"needs_recovery":recovery,"request_accepted":false,"waiting_needed":false,
        "message":if status=="on" {"Режим разработчика включён: iOS подтвердила состояние."}
            else if status=="off" {"Режим выключен. Можно запросить показ пункта в настройках."}
            else {"iPhone доступен, но состояние режима прочитать не удалось."}});
    if request.action==Action::RequestEnable {
        if recovery {return Err("Сначала восстанови незавершённую операцию CarrierSIM. Перезагрузка сейчас запрещена.".into());}
        if status=="on" {result["stage"]=json!("enabled"); return Ok(result);}
        if status=="unknown" {return Err("iOS не сообщила состояние режима. Включи его вручную в настройках и повтори проверку.".into());}
    }
    let client=amfi(&mut tunnel,logger).await;
    if request.action==Action::Status {
        match client {
            Ok(_)=>result["amfi_available"]=json!(true),
            Err(error)=>result["capability_error"]=json!(format!("{error} Показ пункта через это соединение недоступен. Если он скрыт, начни доверенное сопряжение через компьютер.")),
        }
        return Ok(result);
    }
    // Opening the connection isn't a state-changing request. Recheck identity
    // before sending any AMFI action, including the reveal request.
    drop(client);
    let current=carrier::device_identity(&mut tunnel).await?;
    verify_identity(request.expected_device_hash.as_deref(),&current.udid_hash,true)?;
    let mut client=amfi(&mut tunnel,logger).await?;
    result["amfi_available"]=json!(true);
    if request.action==Action::Reveal {
        tokio::time::timeout(SERVICE_TIMEOUT,client.reveal_developer_mode_option_in_ui()).await
            .map_err(|_|"Нет подтверждения показа пункта. Проверь настройки на выбранном iPhone.".to_string())?
            .map_err(|_|"iOS отказала в показе пункта режима разработчика. Проверь доверие и версию iOS.".to_string())?;
        result["stage"]=json!("menu_requested"); result["request_accepted"]=json!(true);
        result["message"]=json!("Запрос показа пункта принят. На выбранном iPhone открой Настройки → Конфиденциальность и безопасность → Режим разработчика. Владелец включает переключатель, подтверждает перезагрузку и включение после неё.");
        return Ok(result);
    }
    logger.log("Запрашиваю включение режима разработчика на проверенном iPhone. Он может перезагрузиться…");
    match tokio::time::timeout(SERVICE_TIMEOUT,client.enable_developer_mode()).await {
        Ok(Ok(()))=>{
            result["stage"]=json!("waiting");result["request_accepted"]=json!(true);
            result["message"]=json!("Запрос принят. Дождись перезагрузки, затем владелец подтверждает включение на экране iPhone и вводит код-пароль. CarrierSIM проверит состояние после возвращения телефона.");
        }
        Ok(Err(IdeviceError::UnexpectedResponse(error))) if error.contains("Device has a passcode set")=>{
            result["stage"]=json!("manual");
            result["message"]=json!("Код-пароль блокирует сетевой запрос включения. Сохрани код-пароль: включи режим вручную в Настройки → Конфиденциальность и безопасность, подтверди перезагрузку и включение после неё. Затем нажми «Проверить состояние».");
            return Ok(result);
        }
        Ok(Err(IdeviceError::UnexpectedResponse(_)))=>return Err("iOS отклонила запрос включения режима разработчика. Проверь настройки на выбранном телефоне.".into()),
        _=>{
            result["stage"]=json!("unknown");
            result["message"]=json!("Связь пропала без подтверждения запроса. Телефон мог начать перезагрузку. Проверь его экран; CarrierSIM будет только читать состояние и не повторит запрос включения.");
        }
    }
    result["waiting_needed"]=json!(true);
    Ok(result)
}

/// Blocks off the main queue; outputs must be freed with al_string_free.
#[no_mangle]
pub unsafe extern "C" fn cs_developer_mode(pairing_path:*const c_char,work_dir:*const c_char,request_json:*const c_char,
    cb:ALLogCallback,ctx:*mut c_void,result_json:*mut *mut c_char,error:*mut *mut c_char)->i32 {
    if !result_json.is_null(){*result_json=std::ptr::null_mut();}
    if !error.is_null(){*error=std::ptr::null_mut();}
    let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||{
        let pairing=ffi_util::opt_str(pairing_path,"");let work=ffi_util::opt_str(work_dir,"");let text=ffi_util::opt_str(request_json,"");
        if pairing.is_empty() || work.is_empty() || text.is_empty() || text.len()>8192 {return Err("Неверный запрос режима разработчика.".into());}
        let request:Request=serde_json::from_str(&text).map_err(|_|"Неверное действие или параметры режима разработчика.".to_string())?;
        let logger=Logger{cb,ctx};
        idevice_ffi::run_sync_local(execute(Path::new(&pairing),Path::new(&work),request,&logger))
    })).unwrap_or_else(|_|Err("Проверка прервалась. Проверь экран iPhone и повтори только чтение состояния.".into()));
    match result {
        Ok(value)=>{if !result_json.is_null(){*result_json=ffi_util::cstr(value.to_string());}0},
        Err(message)=>{if !error.is_null(){*error=ffi_util::cstr(message);}1},
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn missing_or_non_boolean_status_is_unknown() {
        assert_eq!(state(None),"unknown");
        assert_eq!(state(Some(&plist::Value::String("true".into()))),"unknown");
        assert_eq!(state(Some(&plist::Value::Boolean(false))),"off");
        assert_eq!(state(Some(&plist::Value::Boolean(true))),"on");
    }
    #[test] fn post_reboot_accept_and_unknown_actions_are_not_exposed() {
        assert!(serde_json::from_str::<Request>(r#"{"action":"accept"}"#).is_err());
        assert!(serde_json::from_str::<Request>(r#"{"action":"request_enable","password":"secret"}"#).is_err());
    }
    async fn amfi_exchange(action:u64,response:plist::Dictionary)->Result<(),IdeviceError> {
        use tokio::io::{AsyncReadExt,AsyncWriteExt};
        let (client,server)=tokio::io::duplex(8192);
        let server=tokio::spawn(async move {
            let mut server=server;
            let length=server.read_u32().await.unwrap();assert!(length<8192);
            let mut bytes=vec![0;length as usize];server.read_exact(&mut bytes).await.unwrap();
            let request=plist::Value::from_reader(std::io::Cursor::new(bytes)).unwrap();
            assert_eq!(request.as_dictionary().unwrap().get("action").and_then(plist::Value::as_unsigned_integer),Some(action));
            let mut bytes=Vec::new();plist::Value::Dictionary(response).to_writer_xml(&mut bytes).unwrap();
            server.write_u32(bytes.len() as u32).await.unwrap();server.write_all(&bytes).await.unwrap();
        });
        let mut client=AmfiClient::new(idevice::Idevice::new(Box::new(client),"test client"));
        let result=match action {0=>client.reveal_developer_mode_option_in_ui().await,
            1=>client.enable_developer_mode().await,_=>client.accept_developer_mode().await};
        server.await.unwrap();result
    }
    #[tokio::test] async fn real_plist_exchange_rejects_false_success_for_all_actions() {
        for action in 0..=2 {
            for (value,accepted) in [(plist::Value::Boolean(false),false),(plist::Value::String("true".into()),false),(plist::Value::Boolean(true),true)] {
                let mut response=plist::Dictionary::new();response.insert("success".into(),value);
                assert_eq!(amfi_exchange(action,response).await.is_ok(),accepted);
            }
            assert!(amfi_exchange(action,plist::Dictionary::new()).await.is_err());
        }
    }
    #[tokio::test] async fn passcode_error_takes_precedence_over_success_key() {
        let mut response=plist::Dictionary::new();response.insert("success".into(),plist::Value::Boolean(true));response.insert("Error".into(),plist::Value::String("Device has a passcode set".into()));
        let error=amfi_exchange(1,response).await.unwrap_err();
        assert!(error.to_string().contains("Device has a passcode set"));
    }
}
