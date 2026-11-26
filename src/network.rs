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
    if id.is_empty()
        || id.len() > 15
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
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
            let address = (host, port)
                .to_socket_addrs()
                .map_err(|_| "VPN SERVER DNS LOOKUP FAILED")?
                .find(|a| !awg || a.is_ipv4())
                .ok_or("VPN SERVER ADDRESS UNAVAILABLE")?;
            peer["address"] = serde_json::json!(address.ip().to_string());
            peers.push(address);
        }
    }
    Ok(peers)
}

pub fn connect(profile: &Profile, kill_switch: bool) -> Result<(), String> {
    let path = profile.stage()?;
    let split = profile.split();
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
        crate::split::prepare(profile, kill_switch, port, &probe_password)?
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
    crate::firewall::replace(None, None)?;
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
    let plan = read_plan(path)?;
    if action == "stop" {
        crate::split::stop(path)?;
        if crate::tunnel_running(plan.protocol, path) {
            native_engine(&plan, false)?;
            let deadline = Instant::now() + Duration::from_secs(15);
            while crate::tunnel_running(plan.protocol, path) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(100));
            }
            if crate::tunnel_running(plan.protocol, path) {
                return Err("TUNNEL STILL RUNNING - KILL SWITCH RETAINED".into());
            }
        }
        return release_guard();
    }
    if action != "connect" {
        return Err("UNKNOWN NETWORK ACTION".into());
    }
    if plan.kill_switch {
        crate::firewall::replace(Some(&plan.peers), None)?;
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
                crate::firewall::replace(Some(&plan.peers), Some(luid))?;
            }
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err("VPN INTERFACE DID NOT START - DISCONNECT TO RELEASE KILL SWITCH".into())
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
    fn controller_rejects_path_traversal_before_elevation() {
        for id in ["../test", "a/b", "C:\\evil", "", "a b", "aaaaaaaaaaaaaaaa"] {
            assert!(super::profile_path(id).is_err());
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
