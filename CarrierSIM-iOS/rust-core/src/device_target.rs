//! Explicit LAN destination. Remote mode must never fall back to this phone.
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeviceTarget {
    pub host: String,
    #[serde(default = "rsd_port")]
    pub rsd_port: u16,
    #[serde(default = "lockdown_port")]
    pub lockdown_port: u16,
}
fn rsd_port() -> u16 { 49152 }
fn lockdown_port() -> u16 { 62078 }

impl DeviceTarget {
    pub fn address(&self) -> Result<Ipv4Addr, String> {
        let ip: Ipv4Addr = self.host.parse().map_err(|_| "Укажи IPv4-адрес iPhone друга из настроек Wi-Fi.".to_string())?;
        if !(ip.is_private() || ip.is_link_local()) || (ip.octets()[0..3] == [10,7,0] && (1..=3).contains(&ip.octets()[3])) || self.rsd_port == 0 || self.lockdown_port != 62078 {
            return Err("Нужен адрес iPhone в локальной сети и порты от 1 до 65535.".into());
        }
        Ok(ip)
    }
}

pub(crate) fn rsd_targets(target: Option<&DeviceTarget>) -> Result<Vec<SocketAddr>, String> {
    if let Some(target) = target {
        return Ok(vec![SocketAddr::new(IpAddr::V4(target.address()?), target.rsd_port)]);
    }
    Ok([Ipv4Addr::LOCALHOST, Ipv4Addr::new(10,7,0,1), Ipv4Addr::new(10,7,0,2), Ipv4Addr::new(10,7,0,3)]
        .into_iter().map(|ip| SocketAddr::new(IpAddr::V4(ip), rsd_port())).collect())
}

pub(crate) fn verify_identity(expected: Option<&str>, actual: &str, required: bool) -> Result<(), String> {
    match expected {
        Some(hash) if hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()) && hash == actual => Ok(()),
        Some(_) => Err("Подключён другой iPhone. Снова нажми «Проверить iPhone» перед записью.".into()),
        None if required => Err("Сначала проверь iPhone друга; запись без проверки устройства запрещена.".into()),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn remote_destination_is_exclusive() {
        let t: DeviceTarget = serde_json::from_str(r#"{"host":"192.168.1.23","rsd_port":50123}"#).unwrap();
        assert_eq!(rsd_targets(Some(&t)).unwrap(), vec!["192.168.1.23:50123".parse().unwrap()]);
        assert_eq!(t.lockdown_port,62078);
        assert_eq!(rsd_targets(None).unwrap().len(),4);
    }
    #[test]
    fn public_loopback_and_invalid_destinations_are_rejected() {
        for host in ["127.0.0.1","8.8.8.8","0.0.0.0","224.0.0.1","example.com","192.168.1.2:49152"] {
            assert!(DeviceTarget{host:host.into(),rsd_port:49152,lockdown_port:62078}.address().is_err());
        }
        assert!(DeviceTarget{host:"192.168.1.2".into(),rsd_port:0,lockdown_port:62078}.address().is_err());
    }
    #[test]
    fn identity_change_or_missing_check_prevents_write() {
        let actual="a".repeat(64);
        assert!(verify_identity(Some(&actual),&actual,true).is_ok());
        assert!(verify_identity(Some(&"b".repeat(64)),&actual,true).is_err());
        assert!(verify_identity(None,&actual,true).is_err());
        assert!(verify_identity(None,&actual,false).is_ok());
    }
}
