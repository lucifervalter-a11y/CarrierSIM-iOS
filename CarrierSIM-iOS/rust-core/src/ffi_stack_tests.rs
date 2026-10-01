//! Exercise the exported entry points from an iOS GCD-sized caller stack.
//! A subprocess contains stack overflow so the regression reports a test failure.
use std::{ffi::CString, path::Path, process::Command, time::{SystemTime, UNIX_EPOCH}};

fn on_small_stack(name: &str, entry: fn(&Path)) {
    if std::env::var("CARRIERSIM_STACK_TEST_CHILD").as_deref() != Ok(name) {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture", "--test-threads=1"])
            .env("CARRIERSIM_STACK_TEST_CHILD", name).output().unwrap();
        assert!(output.status.success(), "small-stack FFI subprocess failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        return;
    }
    let work = std::env::temp_dir().join(format!("carriersim-stack-{}-{}", std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
    std::fs::create_dir(&work).unwrap();
    let worker_path = work.clone();
    std::thread::Builder::new().name("ios-sized-caller".into()).stack_size(512 * 1024)
        .spawn(move || entry(&worker_path)).unwrap().join().unwrap();
    std::fs::remove_dir_all(work).unwrap();
}

#[test]
fn developer_mode_returns_error_from_ios_sized_stack() {
    on_small_stack("ffi_stack_tests::developer_mode_returns_error_from_ios_sized_stack", |work| {
        let pairing = CString::new(work.join("missing-pairing.plist").to_str().unwrap()).unwrap();
        let directory = CString::new(work.to_str().unwrap()).unwrap();
        let request = CString::new(r#"{"action":"status"}"#).unwrap();
        let (mut result, mut error) = (std::ptr::null_mut(), std::ptr::null_mut());
        unsafe {
            let code = crate::developer_mode::cs_developer_mode(pairing.as_ptr(), directory.as_ptr(),
                request.as_ptr(), None, std::ptr::null_mut(), &mut result, &mut error);
            assert_eq!(code, 1); assert!(result.is_null()); assert!(!error.is_null());
            assert!(crate::ffi_util::opt_str(error, "").contains("сопряжение"));
            crate::ffi_util::string_free(error);
        }
    });
}

#[test]
fn installer_returns_error_from_ios_sized_stack() {
    on_small_stack("ffi_stack_tests::installer_returns_error_from_ios_sized_stack", |work| {
        let pairing = CString::new(work.join("missing-pairing.plist").to_str().unwrap()).unwrap();
        let ipa = CString::new(work.join("missing.ipa").to_str().unwrap()).unwrap();
        let directory = CString::new(work.to_str().unwrap()).unwrap();
        let request = CString::new(r#"{"target":{"host":"192.168.1.20","rsd_port":49152},"expected_device_hash":"0000000000000000000000000000000000000000000000000000000000000000"}"#).unwrap();
        let (mut result, mut error) = (std::ptr::null_mut(), std::ptr::null_mut());
        unsafe {
            let code = crate::installer::cs_install_ipa(pairing.as_ptr(), ipa.as_ptr(), directory.as_ptr(),
                request.as_ptr(), None, std::ptr::null_mut(), &mut result, &mut error);
            assert_eq!(code, 1); assert!(result.is_null()); assert!(!error.is_null());
            crate::ffi_util::string_free(error);
        }
    });
}
