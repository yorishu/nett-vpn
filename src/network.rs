use crate::{Protocol, profiles::Profile};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs,
    net::{SocketAddr, TcpListener, ToSocketAddrs},
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

#[derive(Serialize, Deserialize)]
struct Plan {
    id: String,
    protocol: Protocol,
    split: bool,
    kill_switch: bool,
    peers: Vec<SocketAddr>,
    probe_port: Option<u16>,
    probe_password: String,
}
impl Plan {
    fn alias(&self) -> String {
        if self.split {
            format!("nett-{}", self.id)
        } else {
            self.id.clone()
        }
    }
    fn path(&self) -> Result<PathBuf, String> {
        profile_path(&self.id)
    }
}

fn profile_path(id: &str) -> Result<PathBuf, String> {
    if !crate::profiles::valid_id(id) {
        return Err("INVALID NETWORK PROFILE ID".into());
    }
    Ok(crate::storage::root()?.join(format!("{id}.conf")))
}
fn guard_path() -> Result<PathBuf, String> {
    Ok(crate::storage::root()?.join("kill-switch.json"))
}
pub fn guarded() -> bool {
    guard_path().is_ok_and(|p| p.is_file())
}
fn write_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    fs::write(path, serde_json::to_vec(value).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}
fn read_plan(path: &Path) -> Result<Plan, String> {
    let plan: Plan = serde_json::from_slice(
        &fs::read(path.with_extension("network.json"))
            .map_err(|_| "RECONNECT TO ENABLE TUNNEL VERIFICATION")?,
    )
    .map_err(|_| "INVALID NETWORK SESSION")?;
    if plan.path()? != path
        || plan
            .peers
            .iter()
            .any(|p| p.port() == 0 || p.ip().is_unspecified() || p.ip().is_multicast())
    {
        return Err("INVALID NETWORK SESSION".into());
    }
    Ok(plan)
}

pub fn resolve_peers(options: &mut Value) -> Result<Vec<SocketAddr>, String> {
    let mut peers = Vec::new();
    for endpoint in options["endpoints"]
        .as_array_mut()
        .ok_or("ENDPOINTS MISSING")?
    {
        let awg = endpoint["type"] == "awg";
        for peer in endpoint["peers"].as_array_mut().ok_or("PEERS MISSING")? {
            let host = peer["address"].as_str().ok_or("PEER ADDRESS MISSING")?;
            let port = u16::try_from(peer["port"].as_u64().ok_or("PEER PORT MISSING")?)
                .map_err(|_| "INVALID PEER PORT")?;
            let addresses: Vec<_> = (host, port)
                .to_socket_addrs()
                .map_err(|_| "VPN SERVER DNS LOOKUP FAILED")?
                .collect();
            let address = addresses
                .iter()
                .find(|a| !awg || a.is_ipv4())
                .or_else(|| addresses.first())
                .copied()
                .ok_or("VPN SERVER ADDRESS UNAVAILABLE")?;
            peer["address"] = serde_json::json!(address.ip().to_string());
            peers.push(address);
        }
    }
    Ok(peers)
}

pub(crate) fn direct_ipv6_available() -> Result<bool, String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::*;
    use windows_sys::Win32::Networking::WinSock::AF_INET6;
    unsafe {
        let mut table = std::ptr::null_mut();
        if GetIpForwardTable2(AF_INET6, &mut table) != 0 {
            return Err("CANNOT QUERY DIRECT IPV6 ROUTES".into());
        }
        let routes = std::slice::from_raw_parts(
            std::ptr::addr_of!((*table).Table).cast::<MIB_IPFORWARD_ROW2>(),
            (*table).NumEntries as usize,
        );
        let available = routes.iter().any(|route| {
            if route.DestinationPrefix.PrefixLength != 0 || route.Loopback != 0 {
                return false;
            }
            let mut alias = [0u16; 257];
            ConvertInterfaceLuidToAlias(&route.InterfaceLuid, alias.as_mut_ptr(), alias.len()) == 0
                && !String::from_utf16_lossy(
                    &alias[..alias.iter().position(|c| *c == 0).unwrap_or(alias.len())],
                )
                .starts_with("nett-")
        });
        FreeMibTable(table.cast());
        Ok(available)
    }
}

pub(crate) fn direct_dns_server() -> String {
    use windows_sys::Win32::NetworkManagement::IpHelper::{FIXED_INFO_W2KSP1, GetNetworkParams};
    unsafe {
        let mut bytes = 0;
        GetNetworkParams(std::ptr::null_mut(), &mut bytes);
        if bytes > 0 && bytes <= 1024 * 1024 {
            // usize storage supplies the alignment required by the Windows structures.
            let mut buffer = vec![0usize; (bytes as usize).div_ceil(std::mem::size_of::<usize>())];
            let info = buffer.as_mut_ptr() as *mut FIXED_INFO_W2KSP1;
            if GetNetworkParams(info, &mut bytes) == 0 {
                let mut server: *const windows_sys::Win32::NetworkManagement::IpHelper::IP_ADDR_STRING = &(*info).DnsServerList;
                while !server.is_null() {
                    let address: Vec<u8> = (*server)
                        .IpAddress
                        .String
                        .iter()
                        .take_while(|c| **c != 0)
                        .map(|c| *c as u8)
                        .collect();
                    if let Ok(address) = std::str::from_utf8(&address)
                        && let Ok(ip) = address.parse::<std::net::Ipv4Addr>()
                        && !ip.is_unspecified()
                        && !ip.is_loopback()
                        && !ip.is_multicast()
                    {
                        return ip.to_string();
                    }
                    server = (*server).Next;
                }
            }
        }
    }
    "1.1.1.1".into()
}

pub(crate) fn uses_core(protocol: Protocol, user: &crate::profiles::UserConfig) -> bool {
    protocol == Protocol::AmneziaWg || user.split()
}

pub fn connect(profile: &Profile, user: &crate::profiles::UserConfig) -> Result<(), String> {
    let path = profile.stage()?;
    let split = uses_core(profile.protocol(), user);
    let kill_switch = user.kill_switch;
    let mut password = [0u8; 16];
    unsafe {
        use windows_sys::Win32::Security::Cryptography::{
            BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
        };
        if BCryptGenRandom(
            std::ptr::null_mut(),
            password.as_mut_ptr(),
            password.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        ) < 0
        {
            return Err("CANNOT INITIALIZE VPN PROBE".into());
        }
    }
    let probe_password: String = password.iter().map(|v| format!("{v:02x}")).collect();
    let probe_port = if split {
        Some(
            TcpListener::bind("127.0.0.1:0")
                .map_err(|e| e.to_string())?
                .local_addr()
                .map_err(|e| e.to_string())?
                .port(),
        )
    } else {
        None
    };
    let peers = if let Some(port) = probe_port {
        crate::split::prepare(profile, user, port, &probe_password)?
    } else {
        let mut peers = Vec::new();
        let mut text = String::new();
        for line in profile.config.lines() {
            let parsed = line.split('#').next().unwrap_or("");
            if let Some((key, value)) = parsed.split_once('=')
                && key.trim().eq_ignore_ascii_case("Endpoint")
            {
                let peer = value
                    .trim()
                    .to_socket_addrs()
                    .map_err(|_| "VPN SERVER DNS LOOKUP FAILED")?
                    .next()
                    .ok_or("VPN SERVER ADDRESS UNAVAILABLE")?;
                peers.push(peer);
                text.push_str(&format!("Endpoint = {peer}\n"));
            } else {
                text.push_str(line);
                text.push('\n');
            }
        }
        if peers.is_empty() {
            return Err("VPN PEER ENDPOINT MISSING".into());
        }
        fs::write(&path, text).map_err(|e| e.to_string())?;
        peers
    };
    let plan = Plan {
        id: profile.id.clone(),
        protocol: profile.protocol(),
        split,
        kill_switch,
        peers,
        probe_port,
        probe_password,
    };
    write_json(&path.with_extension("network.json"), &plan)?;
    elevate("connect", &plan.id)
}

pub fn stop(path: &Path, protocol: Protocol) -> Result<(), String> {
    if !path.with_extension("network.json").is_file() {
        let plan = Plan {
            id: crate::tunnel_name(path),
            protocol,
            split: crate::split::running(path),
            kill_switch: false,
            peers: Vec::new(),
            probe_port: None,
            probe_password: String::new(),
        };
        write_json(&path.with_extension("network.json"), &plan)?;
    }
    elevate("stop", &crate::tunnel_name(path))
}
fn sessions(root: &Path) -> Result<Vec<(std::path::PathBuf, Plan)>, String> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.to_string()),
    };
    let mut sessions = Vec::new();
    let mut legacy = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        let Some(id) = name.to_str().and_then(|n| n.strip_suffix(".network.json")) else {
            if let Some(name) = name.to_str()
                && name.to_ascii_lowercase().ends_with(".conf")
                && let Some((id, _)) = name.rsplit_once('.')
                && crate::profiles::valid_id(id)
            {
                legacy.push((id.to_owned(), entry.path()));
            }
            continue;
        };
        if !crate::profiles::valid_id(id) {
            return Err("INVALID NETWORK PROFILE ID".into());
        }
        let path = root.join(format!("{id}.conf"));
        let plan: Plan =
            serde_json::from_slice(&fs::read(entry.path()).map_err(|e| e.to_string())?)
                .map_err(|_| "INVALID NETWORK SESSION")?;
        if plan.id != id {
            return Err("INVALID NETWORK SESSION".into());
        }
        sessions.push((path, plan));
    }
    // Older clients had no session metadata. Use filenames, never read their keys.
    for (id, path) in legacy {
        if sessions
            .iter()
            .any(|(_, plan)| plan.id.eq_ignore_ascii_case(&id))
        {
            continue;
        }
        let protocol = if crate::tunnel_running(Protocol::AmneziaWg, &path) {
            Protocol::AmneziaWg
        } else {
            Protocol::WireGuard
        };
        sessions.push((
            path.clone(),
            Plan {
                id,
                protocol,
                split: crate::split::running(&path),
                kill_switch: false,
                peers: Vec::new(),
                probe_port: None,
                probe_password: String::new(),
            },
        ));
    }
    Ok(sessions)
}
pub fn stop_all() -> Result<(), String> {
    if !guarded()
        && sessions(&crate::storage::root()?)?
            .iter()
            .all(|(path, plan)| !crate::connection_running(plan.protocol, path))
    {
        return Ok(());
    }
    elevate("stop-all", "_global")
}
pub fn clear() -> Result<(), String> {
    elevate("clear", "_global")
}

pub fn verify(path: &Path) -> Result<(), String> {
    let plan = read_plan(path)?;
    crate::health::verify(
        &plan.alias(),
        plan.probe_port.map(|p| (p, plan.probe_password.as_str())),
    )
}

fn elevate(action: &str, id: &str) -> Result<(), String> {
    let path = profile_path(id)?;
    let result_path = path.with_extension("network-result.json");
    match fs::remove_file(&result_path) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.to_string()),
    }
    // Start-Process -Wait also waits for descendants, including the long-running VPN core.
    let script = "$ErrorActionPreference='Stop'; $p=Start-Process -FilePath $env:NETT_SELF -ArgumentList @('--nett-network',$env:NETT_ACTION,$env:NETT_ID) -Verb RunAs -WindowStyle Hidden -PassThru; $p.WaitForExit(); exit $p.ExitCode";
    let status = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env(
            "NETT_SELF",
            std::env::current_exe().map_err(|e| e.to_string())?,
        )
        .env("NETT_ACTION", action)
        .env("NETT_ID", id)
        .creation_flags(0x08000000)
        .status()
        .map_err(|e| e.to_string())?;
    let result: Result<(), String> = fs::read(&result_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_else(|| Err("NETWORK OPERATION CANCELLED OR FAILED".into()));
    if !status.success() && result.is_ok() {
        return Err("NETWORK CONTROLLER FAILED".into());
    }
    result
}

pub fn dispatch() -> Option<i32> {
    let args: Vec<_> = std::env::args().collect();
    if args.get(1).map(String::as_str) != Some("--nett-network") {
        return None;
    }
    let result = (|| {
        let action = args.get(2).ok_or("NETWORK ACTION MISSING")?;
        let id = args.get(3).ok_or("NETWORK PROFILE MISSING")?;
        let path = profile_path(id)?;
        let result = controller(action, &path);
        write_json(&path.with_extension("network-result.json"), &result)?;
        result
    })();
    Some(if result.is_ok() { 0 } else { 1 })
}

fn release_guard() -> Result<(), String> {
    crate::firewall::replace(None, None, None)?;
    match fs::remove_file(guard_path()?) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}
fn controller(action: &str, path: &Path) -> Result<(), String> {
    if action == "clear" {
        return release_guard();
    }
    if action == "stop-all" {
        for (path, plan) in sessions(&crate::storage::root()?)? {
            stop_engine(&plan, &path)?;
        }
        return release_guard();
    }
    let plan = read_plan(path)?;
    if action == "stop" {
        stop_engine(&plan, path)?;
        return release_guard();
    }
    if action != "connect" {
        return Err("UNKNOWN NETWORK ACTION".into());
    }
    let split_engine = if plan.split {
        Some(crate::split::engine()?)
    } else {
        None
    };
    if plan.kill_switch {
        crate::firewall::replace(Some(&plan.peers), None, split_engine.as_deref())?;
        write_json(&guard_path()?, &true)?;
    } else {
        release_guard()?;
    }
    if plan.split {
        crate::split::launch(path)?;
    } else {
        native_engine(&plan, true)?;
    }
    let deadline = Instant::now() + Duration::from_secs(25);
    while Instant::now() < deadline {
        if crate::connection_running(plan.protocol, path)
            && let Some((luid, _)) = crate::health::interface(&plan.alias())
        {
            if plan.kill_switch {
                crate::firewall::replace(Some(&plan.peers), Some(luid), split_engine.as_deref())?;
            }
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err("VPN INTERFACE DID NOT START - DISCONNECT TO RELEASE KILL SWITCH".into())
}

fn stop_engine(plan: &Plan, path: &Path) -> Result<(), String> {
    crate::split::stop(path)?;
    if crate::tunnel_running(plan.protocol, path) {
        native_engine(plan, false)?;
        let deadline = Instant::now() + Duration::from_secs(15);
        while crate::tunnel_running(plan.protocol, path) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        if crate::tunnel_running(plan.protocol, path) {
            return Err("TUNNEL STILL RUNNING - KILL SWITCH RETAINED".into());
        }
    }
    Ok(())
}

fn native_engine(plan: &Plan, start: bool) -> Result<(), String> {
    let engine = crate::engine_path(plan.protocol).ok_or("VPN ENGINE NOT FOUND")?;
    let status = Command::new(engine)
        .arg(if start {
            "/installtunnelservice"
        } else {
            "/uninstalltunnelservice"
        })
        .arg(if start {
            plan.path()?.to_string_lossy().into_owned()
        } else {
            plan.id.clone()
        })
        .creation_flags(0x08000000)
        .status()
        .map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "VPN ENGINE FAILED - EXIT {}",
            status.code().unwrap_or(-1)
        ))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn awg_uses_updated_core_even_without_split_rules() {
        let mut user = crate::profiles::UserConfig::default();
        assert!(!user.split());
        assert!(super::uses_core(crate::Protocol::AmneziaWg, &user));
        assert!(!super::uses_core(crate::Protocol::WireGuard, &user));
        user.sites.enabled = true;
        assert!(super::uses_core(crate::Protocol::WireGuard, &user));
        assert!(super::uses_core(crate::Protocol::AmneziaWg, &user));
    }
    #[test]
    fn recovery_inventory_works_without_vault_and_rejects_mismatched_sessions() {
        let root = std::env::temp_dir().join(format!("nett-recovery-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("old.vpn.network.json");
        let mut plan = serde_json::json!({"id":"old.vpn","protocol":"WireGuard","split":false,"kill_switch":true,"peers":[],"probe_port":null,"probe_password":""});
        std::fs::write(&path, serde_json::to_vec(&plan).unwrap()).unwrap();
        let sessions = super::sessions(&root).unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].0, root.join("old.vpn.conf"));
        std::fs::write(
            root.join("legacy+1.CONF"),
            b"contents intentionally not parsed",
        )
        .unwrap();
        let recovered = super::sessions(&root).unwrap();
        assert_eq!(recovered.len(), 2);
        assert!(recovered.iter().any(|(_, plan)| plan.id == "legacy+1"));
        plan["id"] = serde_json::json!("different");
        std::fs::write(&path, serde_json::to_vec(&plan).unwrap()).unwrap();
        assert!(super::sessions(&root).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn controller_rejects_path_traversal_before_elevation() {
        for id in ["../test", "a/b", "C:\\evil", "", "a b", "aaaaaaaaaaaaaaaa"] {
            assert!(super::profile_path(id).is_err());
        }
        for id in ["old.vpn", "old+vpn=1", "_global"] {
            assert!(super::profile_path(id).is_ok());
        }
    }
    #[test]
    fn peer_resolution_preserves_numeric_server_and_port() {
        let mut options = serde_json::json!({"endpoints":[{"type":"awg","peers":[{"address":"localhost","port":51820}]}]});
        let peers = super::resolve_peers(&mut options).unwrap();
        assert_eq!(peers, vec!["127.0.0.1:51820".parse().unwrap()]);
        assert_eq!(options["endpoints"][0]["peers"][0]["address"], "127.0.0.1");
    }
}
