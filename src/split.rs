use crate::profiles::{Mode, Profile, Rules};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    net::IpAddr,
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, FILETIME},
    System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        WaitForSingleObject,
    },
};

pub fn site(raw: &str) -> Result<Value, String> {
    let raw = raw.trim();
    if let Some((ip, prefix)) = raw.split_once('/') {
        let ip: IpAddr = ip.parse().map_err(|_| "INVALID CIDR ADDRESS")?;
        let n: u8 = prefix.parse().map_err(|_| "INVALID CIDR PREFIX")?;
        if n > if ip.is_ipv4() { 32 } else { 128 } {
            return Err("INVALID CIDR PREFIX".into());
        }
        return Ok(json!({"ip_cidr":[format!("{ip}/{n}")]}));
    }
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Ok(json!({"ip_cidr":[format!("{ip}/{}", if ip.is_ipv4(){32}else{128})]}));
    }
    let (host, port) = if let Ok(addr) = raw.parse::<std::net::SocketAddr>() {
        (addr.ip().to_string(), Some(addr.port()))
    } else if let Some((host, port)) = raw.rsplit_once(':') {
        (
            host.to_owned(),
            Some(port.parse::<u16>().map_err(|_| "INVALID PORT")?),
        )
    } else {
        (raw.to_owned(), None)
    };
    if port == Some(0) {
        return Err("PORT MUST BE 1-65535".into());
    }
    let mut result = if let Ok(ip) = host.parse::<IpAddr>() {
        json!({"ip_cidr":[format!("{ip}/{}", if ip.is_ipv4(){32}else{128})]})
    } else {
        let host = host
            .strip_prefix("*.")
            .unwrap_or(&host)
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if host.len() > 253
            || host.is_empty()
            || !host.split('.').all(|s| {
                !s.is_empty()
                    && s.len() <= 63
                    && !s.starts_with('-')
                    && !s.ends_with('-')
                    && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return Err("ENTER A DOMAIN, IP, CIDR OR HOST:PORT".into());
        }
        json!({"domain_suffix":[host]})
    };
    if let Some(port) = port {
        result["port"] = json!([port]);
    }
    Ok(result)
}

pub fn validate_rules(rules: &Rules, apps: bool) -> Result<(), String> {
    if rules.entries.len() > 200 {
        return Err("MAXIMUM 200 RULES PER LIST".into());
    }
    if rules.enabled && rules.entries.is_empty() {
        return Err("ADD A RULE BEFORE ENABLING THE LIST".into());
    }
    let mut unique = std::collections::HashSet::new();
    for entry in &rules.entries {
        if !unique.insert(entry.to_ascii_lowercase()) {
            return Err("DUPLICATE SPLIT RULE".into());
        }
        if apps {
            if !Path::new(entry).is_absolute()
                || !entry.to_ascii_lowercase().ends_with(".exe")
                || entry.chars().any(char::is_control)
            {
                return Err("SELECT A FULL .EXE PATH".into());
            }
        } else {
            site(entry)?;
        }
    }
    Ok(())
}

fn process_pattern(path: &str) -> String {
    let mut pattern = String::from("(?i)^");
    for c in path.chars() {
        if "\\.+*?()[]{}^$|".contains(c) {
            pattern.push('\\');
        }
        pattern.push(c);
    }
    pattern.push('$');
    pattern
}

pub fn configuration(
    profile: &Profile,
    user: &crate::profiles::UserConfig,
) -> Result<Value, String> {
    validate_rules(&user.sites, false)?;
    validate_rules(&user.apps, true)?;
    let mut interface = BTreeMap::new();
    let mut peers: Vec<BTreeMap<String, String>> = Vec::new();
    let mut section = 0;
    for raw in profile.config.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.eq_ignore_ascii_case("[Interface]") {
            section = 1;
            continue;
        }
        if line.eq_ignore_ascii_case("[Peer]") {
            section = 2;
            peers.push(BTreeMap::new());
            continue;
        }
        if line.starts_with('[') {
            return Err("UNSUPPORTED CONFIG SECTION".into());
        }
        let (key, value) = line.split_once('=').ok_or("INVALID CONFIG LINE")?;
        let key = key.trim().to_ascii_lowercase();
        let target = if section == 1 {
            &mut interface
        } else if section == 2 {
            peers.last_mut().unwrap()
        } else {
            return Err("CONFIG VALUE OUTSIDE A SECTION".into());
        };
        if target
            .insert(key.clone(), value.trim().to_owned())
            .is_some()
        {
            return Err(format!("DUPLICATE CONFIG FIELD: {key}"));
        }
    }
    let list = |value: Option<&String>| -> Vec<String> {
        value
            .map(|s| {
                s.split(',')
                    .map(|s| s.trim().to_owned())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    };
    let awg = profile.protocol() == crate::Protocol::AmneziaWg;
    let mut endpoint = json!({"type":if awg{"awg"}else{"wireguard"},"tag":"vpn","address":list(interface.get("address")),"private_key":interface.get("privatekey").ok_or("PRIVATE KEY MISSING")?});
    if endpoint["address"].as_array().is_none_or(|a| a.is_empty()) {
        return Err("ADDRESS IS REQUIRED FOR SPLIT TUNNELING".into());
    }
    if awg {
        endpoint["useIntegratedTun"] = json!(false);
    } else {
        endpoint["system"] = json!(false);
    }
    for (key, value) in &interface {
        match key.as_str() {
            "address" | "privatekey" | "dns" => (),
            "mtu" | "listenport" => {
                endpoint[if key == "listenport" {
                    "listen_port"
                } else {
                    "mtu"
                }] = json!(
                    value
                        .parse::<u32>()
                        .map_err(|_| "INVALID MTU OR LISTEN PORT")?
                );
            }
            "jc" | "jmin" | "jmax" | "s1" | "s2" | "s3" | "s4" if awg => {
                endpoint[key] = json!(value.parse::<u32>().map_err(|_| format!("INVALID {key}"))?);
            }
            "h1" | "h2" | "h3" | "h4" | "i1" | "i2" | "i3" | "i4" | "i5" if awg => {
                endpoint[key] = json!(value);
            }
            "headerprotectionkey"
            | "header_protection_key"
            | "contentpaddingaddition"
            | "content_padding_addition"
            | "rekeyaftertime"
            | "rekey_after_time"
            | "rekeytimeout"
            | "rekey_timeout"
            | "rejectaftertime"
            | "reject_after_time"
            | "keepalivetimeout"
            | "keepalive_timeout"
            | "maxhandshakeattempts"
            | "max_handshake_attempts"
                if awg =>
            {
                let mapped = match key.replace('_', "").as_str() {
                    "headerprotectionkey" => "header_protection_key",
                    "contentpaddingaddition" => "content_padding_addition",
                    "rekeyaftertime" => "rekey_after_time",
                    "rekeytimeout" => "rekey_timeout",
                    "rejectaftertime" => "reject_after_time",
                    "keepalivetimeout" => "keepalive_timeout",
                    _ => "max_handshake_attempts",
                };
                endpoint[mapped] = json!(value);
            }
            "randomtrailers" | "random_trailers" | "disablecookie" | "disable_cookie"
            | "disablecookies" | "disable_cookies"
                if awg =>
            {
                let flag = match value.to_ascii_lowercase().as_str() {
                    "" => continue, // AWG optional empty fields are unset, not invalid booleans.
                    "true" | "t" | "1" | "on" | "yes" => true,
                    "false" | "f" | "0" | "off" | "no" => false,
                    _ => return Err(format!("INVALID BOOLEAN: {key}")),
                };
                endpoint[if key.starts_with("random") {
                    "random_trailers"
                } else {
                    "disable_cookies"
                }] = json!(flag);
            }
            _ => return Err(format!("SPLIT ENGINE DOES NOT SUPPORT FIELD: {key}")),
        }
    }
    let mut peer_options = Vec::new();
    for peer in &peers {
        let target = peer.get("endpoint").ok_or("PEER ENDPOINT MISSING")?;
        let (host, port) = target.rsplit_once(':').ok_or("INVALID PEER ENDPOINT")?;
        let port = port.parse::<u16>().map_err(|_| "INVALID PEER PORT")?;
        if port == 0 {
            return Err("INVALID PEER PORT".into());
        }
        let mut p = json!({"address":host.trim_matches(['[',']']),"port":port,"public_key":peer.get("publickey").ok_or("PEER PUBLIC KEY MISSING")?,"allowed_ips":list(peer.get("allowedips"))});
        if p["allowed_ips"].as_array().is_none_or(|a| a.is_empty()) {
            return Err("PEER ALLOWED IPS MISSING".into());
        }
        for (key, value) in peer {
            match key.as_str() {
                "endpoint" | "publickey" | "allowedips" => (),
                "presharedkey" => {
                    p[if awg {
                        "preshared_key"
                    } else {
                        "pre_shared_key"
                    }] = json!(value)
                }
                "persistentkeepalive" => {
                    if value.eq_ignore_ascii_case("off") || value.eq_ignore_ascii_case("(off)") {
                        p["persistent_keepalive_interval"] = json!(0);
                    } else if awg && value.contains('-') {
                        let (min, max) = value.split_once('-').unwrap();
                        let min = min
                            .trim()
                            .parse::<u16>()
                            .map_err(|_| "INVALID KEEPALIVE RANGE")?;
                        let max = max
                            .trim()
                            .parse::<u16>()
                            .map_err(|_| "INVALID KEEPALIVE RANGE")?;
                        if min > max {
                            return Err("INVALID KEEPALIVE RANGE: MIN EXCEEDS MAX".into());
                        }
                        p["persistent_keepalive_range"] = json!(format!("{min}-{max}"));
                    } else {
                        p["persistent_keepalive_interval"] =
                            json!(value.parse::<u16>().map_err(
                                |_| "INVALID KEEPALIVE: EXPECTED 0..65535 OR AWG RANGE"
                            )?);
                    }
                }
                _ => return Err(format!("UNSUPPORTED PEER FIELD: {key}")),
            }
        }
        peer_options.push(p);
    }
    if peer_options.is_empty() {
        return Err("NO PEERS".into());
    }
    endpoint["peers"] = json!(peer_options);
    let final_out = if [&user.sites, &user.apps]
        .iter()
        .any(|r| r.enabled && r.mode == Mode::ViaVpn)
    {
        "direct"
    } else {
        "vpn"
    };
    let mut route_rules = vec![
        json!({"action":"sniff"}),
        json!({"protocol":"dns","action":"hijack-dns"}),
    ];
    let mut dns_rules = Vec::new();
    for mode in [Mode::Direct, Mode::ViaVpn] {
        for (rules, apps) in [(&user.sites, false), (&user.apps, true)] {
            if !rules.enabled || rules.mode != mode {
                continue;
            }
            for entry in &rules.entries {
                let mut rule = if apps {
                    json!({"process_path_regex":[process_pattern(entry)]})
                } else {
                    site(entry)?
                };
                let target = if mode == Mode::Direct {
                    "direct"
                } else {
                    "vpn"
                };
                let mut dns_rule = rule.clone();
                if !apps
                    && dns_rule.get("domain_suffix").is_some()
                    && dns_rule.get("port").is_none()
                {
                    dns_rule["action"] = json!("route");
                    dns_rule["server"] = json!(format!("dns-{target}"));
                    dns_rules.push(dns_rule);
                }
                rule["action"] = json!("route");
                rule["outbound"] = json!(target);
                route_rules.push(rule);
            }
        }
    }
    let vpn_dns = list(interface.get("dns"))
        .into_iter()
        .find(|s| s.parse::<IpAddr>().is_ok())
        .unwrap_or_else(|| "1.1.1.1".into());
    Ok(json!({
        "log":{"level":"warn","timestamp":true,"output":profile.path()?.with_extension("split.log")},
        "dns":{"servers":[{"type":"local","tag":"dns-direct","detour":"direct"},{"type":"udp","tag":"dns-vpn","server":vpn_dns,"detour":"vpn"}],"rules":dns_rules,"final":format!("dns-{final_out}"),"strategy":"prefer_ipv4","reverse_mapping":true},
        "inbounds":[{"type":"tun","tag":"tun","interface_name":format!("nett-{}",profile.id),"address":["172.30.255.1/30","fdfe:dcba:9876::1/126"],"mtu":1400,"auto_route":true,"strict_route":true,"stack":"gvisor"}],
        "endpoints":[endpoint],"outbounds":[{"type":"direct","tag":"direct"}],
        "route":{"auto_detect_interface":true,"find_process":user.apps.enabled,"default_domain_resolver":"dns-direct","rules":route_rules,"final":final_out}
    }))
}

pub(crate) fn engine() -> Result<PathBuf, String> {
    let path = std::env::current_exe()
        .map_err(|e| e.to_string())?
        .parent()
        .ok_or("APP DIRECTORY NOT FOUND")?
        .join(r"engines\AmneziaBox\nett-split-core.exe");
    if !path.is_file() {
        return Err("SPLIT ENGINE NOT FOUND - KEEP engines BESIDE nett.exe".into());
    }
    Ok(path)
}

#[derive(serde::Deserialize)]
struct Ready {
    pid: u32,
    created: u64,
}
pub fn running(path: &Path) -> bool {
    let Ok(bytes) = std::fs::read(path.with_extension("ready.json")) else {
        return false;
    };
    let Ok(ready) = serde_json::from_slice::<Ready>(&bytes) else {
        return false;
    };
    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            ready.pid,
        );
        if handle.is_null() {
            return false;
        }
        let mut created: FILETIME = std::mem::zeroed();
        let mut exit: FILETIME = std::mem::zeroed();
        let mut kernel: FILETIME = std::mem::zeroed();
        let mut user: FILETIME = std::mem::zeroed();
        let ok = GetProcessTimes(handle, &mut created, &mut exit, &mut kernel, &mut user) != 0
            && ((created.dwHighDateTime as u64) << 32 | created.dwLowDateTime as u64)
                == ready.created
            && WaitForSingleObject(handle, 0) == 258;
        CloseHandle(handle);
        ok
    }
}

fn adapt_direct_dns(options: &mut Value, ipv6_available: bool) {
    if ipv6_available {
        return;
    }
    let direct_final = options["dns"]["final"] == "dns-direct";
    let rules = options["dns"]["rules"].as_array_mut().unwrap();
    for rule in rules.iter_mut() {
        if rule["server"] == "dns-direct" {
            rule["strategy"] = json!("ipv4_only");
        }
    }
    if direct_final {
        rules.push(json!({"action":"route","server":"dns-direct","strategy":"ipv4_only"}));
    }
}

pub fn prepare(
    profile: &Profile,
    user: &crate::profiles::UserConfig,
    port: u16,
    password: &str,
) -> Result<Vec<std::net::SocketAddr>, String> {
    if user.apps.enabled
        && user
            .apps
            .entries
            .iter()
            .any(|path| !Path::new(path).is_file())
    {
        return Err("APPLICATION MOVED OR REMOVED - UPDATE ITS .EXE PATH IN SETTINGS".into());
    }
    let path = profile.path()?;
    if running(&path) {
        return Err("SPLIT TUNNEL ALREADY RUNNING".into());
    }
    let engine = engine()?;
    let mut options = configuration(profile, user)?;
    adapt_direct_dns(&mut options, crate::network::direct_ipv6_available()?);
    let peers = crate::network::resolve_peers(&mut options)?;
    let direct_dns = user.kill_switch.then(crate::network::direct_dns_server);
    add_probe(&mut options, direct_dns.as_deref(), port, password);
    let config = path.with_extension("split.json");
    std::fs::write(
        &config,
        serde_json::to_vec_pretty(&options).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let check = Command::new(&engine)
        .arg("check")
        .arg("-c")
        .arg(&config)
        .creation_flags(0x08000000)
        .output()
        .map_err(|e| e.to_string())?;
    if !check.status.success() {
        std::fs::write(path.with_extension("split.log"), &check.stderr)
            .map_err(|e| e.to_string())?;
        return Err("SPLIT CONFIG REJECTED BY ENGINE - SEE PROFILE LOG".into());
    }
    Ok(peers)
}

pub(crate) fn add_probe(options: &mut Value, direct_dns: Option<&str>, port: u16, password: &str) {
    options["inbounds"].as_array_mut().unwrap().push(json!({"type":"socks","tag":"nett-health","listen":"127.0.0.1","listen_port":port,"users":[{"username":"nett","password":password}]}));
    options["route"]["rules"].as_array_mut().unwrap().insert(
        0,
        json!({"inbound":["nett-health"],"action":"route","outbound":"vpn"}),
    );
    if let Some(server) = direct_dns {
        // Windows' shared DNS service is a different process; send DIRECTLY DNS from the allowed core.
        for resolver in options["dns"]["servers"].as_array_mut().unwrap() {
            if resolver["tag"] == "dns-direct" {
                *resolver = json!({"type":"udp","tag":"dns-direct","server":server});
            }
        }
    }
}

// Called only by Nett's elevated controller; no nested UAC prompt.
pub fn launch(path: &Path) -> Result<(), String> {
    let engine = engine()?;
    let config = path.with_extension("split.json");
    let ready = path.with_extension("ready.json");
    let stop = path.with_extension("stop");
    for p in [&ready, &stop] {
        match std::fs::remove_file(p) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.to_string()),
        }
    }
    Command::new(engine)
        .arg("run")
        .arg("-c")
        .arg(config)
        .arg("--nett-ready-file")
        .arg(ready)
        .arg("--nett-stop-file")
        .arg(stop)
        .creation_flags(0x08000000)
        .spawn()
        .map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(25);
    while Instant::now() < deadline {
        if running(&path) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // A late startup must see the stop request instead of becoming an untracked tunnel.
    std::fs::write(path.with_extension("stop"), b"stop").map_err(|e| e.to_string())?;
    Err("SPLIT ENGINE DID NOT START - SEE PROFILE LOG".into())
}

pub fn stop(path: &Path) -> Result<(), String> {
    if !running(path) {
        return Ok(());
    }
    std::fs::write(path.with_extension("stop"), b"stop").map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if !running(path) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err("SPLIT ENGINE IS STILL STOPPING - EXIT CANCELLED".into())
}

#[cfg(test)]
mod tests {
    #[test]
    fn direct_dns_avoids_ipv6_without_changing_vpn_dns_or_dual_stack() {
        let original = serde_json::json!({"dns":{"final":"dns-vpn","rules":[
            {"domain_suffix":["direct.example"],"action":"route","server":"dns-direct"},
            {"domain_suffix":["vpn.example"],"action":"route","server":"dns-vpn"}
        ]}});
        let mut config = original.clone();
        super::adapt_direct_dns(&mut config, true);
        assert_eq!(config, original);
        super::adapt_direct_dns(&mut config, false);
        assert_eq!(config["dns"]["rules"][0]["strategy"], "ipv4_only");
        assert_eq!(config["dns"]["rules"][1], original["dns"]["rules"][1]);
        assert_eq!(config["dns"]["final"], "dns-vpn");
        assert_eq!(config["dns"]["rules"].as_array().unwrap().len(), 2);
        config["dns"]["final"] = serde_json::json!("dns-direct");
        super::adapt_direct_dns(&mut config, false);
        assert_eq!(
            config["dns"]["rules"][2],
            serde_json::json!({"action":"route","server":"dns-direct","strategy":"ipv4_only"})
        );
    }

    fn fixture() -> crate::profiles::Profile {
        crate::profiles::Profile {id:"fixture".into(),name:"test".into(),config:"[Interface]\nPrivateKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress=10.0.0.2/32\nDNS=1.1.1.1\n[Peer]\nPublicKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nEndpoint=127.0.0.1:51820\nAllowedIPs=0.0.0.0/0,::/0".into()}
    }
    fn user() -> crate::profiles::UserConfig {
        crate::profiles::UserConfig {
            sites: crate::profiles::Rules {
                enabled: true,
                mode: crate::profiles::Mode::ViaVpn,
                entries: vec![
                    "example.com".into(),
                    "192.168.10.0/24".into(),
                    "host.ts.net:8766".into(),
                ],
            },
            apps: crate::profiles::Rules {
                enabled: true,
                mode: crate::profiles::Mode::Direct,
                entries: vec![r"C:\Apps\Discord.exe".into()],
            },
            ..Default::default()
        }
    }

    #[test]
    #[ignore = "requires the compiled Amnezia Box sidecar"]
    fn generated_configs_pass_real_engine_check() {
        let engine = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(r"engines\AmneziaBox\nett-split-core.exe");
        let root = std::env::temp_dir().join(format!("nett-box-check-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        for (awg, flag) in [
            (false, ""),
            (true, ""),
            (true, "on"),
            (true, "off"),
            (true, "yes"),
            (true, "no"),
        ] {
            let mut profile = fixture();
            if awg {
                profile.config=profile.config.replace("[Interface]","[Interface]\nJc=4\nJmin=40\nJmax=70\nS1=10\nS2=20\nH1=123456\nH2=234567\nH3=345678\nH4=456789\nDisableCookies=\nRandomTrailers=\nHeaderProtectionKey=\nContentPaddingAddition=\nRekeyAfterTime=\nRekeyTimeout=\nRejectAfterTime=\nKeepaliveTimeout=\nMaxHandshakeAttempts=");
            }
            if awg && !flag.is_empty() {
                profile.config = profile
                    .config
                    .replace("DisableCookies=\n", &format!("DisableCookies={flag}\n"))
                    .replace("RandomTrailers=\n", &format!("RandomTrailers={flag}\n"));
            }
            profile.config.push_str(if awg {
                "\nPersistentKeepalive=25-35"
            } else {
                "\nPersistentKeepalive=25"
            });
            let mut config = super::configuration(&profile, &user()).unwrap();
            super::adapt_direct_dns(&mut config, false);
            super::add_probe(
                &mut config,
                awg.then_some("192.0.2.53"),
                51889,
                "test-password",
            );
            config["log"] = serde_json::json!({"disabled":true});
            let path = root.join("test.json");
            std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
            let result = std::process::Command::new(&engine)
                .arg("check")
                .arg("-c")
                .arg(path)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "awg={awg}, flag={flag}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn awg_optional_booleans_accept_client_config_forms() {
        for (value, expected) in [
            ("", None),
            (" ", None),
            ("false", Some(false)),
            ("0", Some(false)),
            ("F", Some(false)),
            ("TRUE", Some(true)),
            ("1", Some(true)),
            ("t", Some(true)),
            ("on", Some(true)),
            ("ON", Some(true)),
            ("off", Some(false)),
            ("OFF", Some(false)),
            ("yes", Some(true)),
            ("no", Some(false)),
        ] {
            let mut profile = fixture();
            profile.config = profile.config.replace(
                "[Interface]",
                &format!("[Interface]\nJc=4\nDisableCookies={value}\nRandomTrailers={value}"),
            );
            let config = super::configuration(&profile, &user()).unwrap();
            for field in ["disable_cookies", "random_trailers"] {
                assert_eq!(
                    config["endpoints"][0].get(field).and_then(|v| v.as_bool()),
                    expected,
                    "{field}"
                );
            }
        }
        let mut profile = fixture();
        profile.config = profile
            .config
            .replace("[Interface]", "[Interface]\nJc=4\nDisableCookies=invalid");
        assert!(super::configuration(&profile, &user()).is_err());
    }

    #[test]
    #[ignore = "requires the compiled Amnezia Box sidecar"]
    fn split_sidecar_stops_gracefully_without_installing_routes() {
        use std::os::windows::process::CommandExt;
        for awg in [false, true] {
            let engine = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(r"engines\AmneziaBox\nett-split-core.exe");
            let root = std::env::temp_dir()
                .join(format!("nett-box-lifecycle-{}-{awg}", std::process::id()));
            std::fs::create_dir_all(&root).unwrap();
            let path = root.join("test.conf");
            let config = root.join("test.json");
            let mut profile = fixture();
            if awg {
                profile.config = profile.config.replace(
                    "[Interface]",
                    "[Interface]\nJc=4\nDisableCookies=on\nRandomTrailers=on",
                );
                profile.config = profile.config.replace("127.0.0.1:51820", "localhost:51820");
                profile.config.push_str("\nPersistentKeepalive=25-35");
            } else {
                profile.config.push_str("\nPersistentKeepalive=25");
            }
            let mut options = super::configuration(&profile, &user()).unwrap();
            crate::network::resolve_peers(&mut options).unwrap();
            let endpoints = options["endpoints"].clone();
            // No TUN inbound or auto_route: exercise WG/AWG startup without changing host routes.
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            let mut route_free = serde_json::json!({"log":{"disabled":true},"inbounds":[],"dns":{},"endpoints":endpoints,"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rules":[],"final":"direct"}});
            super::add_probe(&mut route_free, None, port, "test-password");
            std::fs::write(&config, serde_json::to_vec(&route_free).unwrap()).unwrap();
            let mut child = std::process::Command::new(engine)
                .args(["run", "-c"])
                .arg(config)
                .arg("--nett-ready-file")
                .arg(path.with_extension("ready.json"))
                .arg("--nett-stop-file")
                .arg(path.with_extension("stop"))
                .creation_flags(0x08000000)
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while !super::running(&path) && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            if !super::running(&path) {
                let _ = child.kill();
                let _ = child.wait();
                panic!("sidecar did not become ready");
            }
            // The engine is alive but the fake peer cannot handshake: never report wired.
            let unverified =
                crate::health::verify("unused", Some((port, "test-password"))).is_err();
            if let Err(e) = super::stop(&path) {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{e}");
            }
            assert!(child.wait().unwrap().success());
            assert!(
                unverified,
                "A running core without a real VPN peer must not pass verification"
            );
            assert!(!super::running(&path));
            assert!(!path.with_extension("ready.json").exists());
            std::fs::remove_dir_all(root).unwrap();
        }
    }
    #[test]
    fn global_rules_apply_to_different_vpn_configs() {
        let first = fixture();
        let mut second = fixture();
        second.id = "other".into();
        second.config = second.config.replace("[Interface]", "[Interface]\nJc=4");
        let user = user();
        let first_options = super::configuration(&first, &user).unwrap();
        let second_options = super::configuration(&second, &user).unwrap();
        assert_eq!(first_options["route"], second_options["route"]);
        assert_eq!(first_options["dns"], second_options["dns"]);
        assert_ne!(
            first_options["endpoints"][0]["type"],
            second_options["endpoints"][0]["type"]
        );
    }
    #[test]
    fn verification_stays_on_vpn_while_direct_dns_rules_are_preserved() {
        let mut config = super::configuration(&fixture(), &user()).unwrap();
        super::add_probe(&mut config, Some("192.0.2.53"), 51889, "test-password");
        let first = &config["route"]["rules"][0];
        assert_eq!(first["inbound"][0], "nett-health");
        assert_eq!(first["outbound"], "vpn");
        assert_eq!(config["dns"]["final"], "dns-direct");
        assert_eq!(config["dns"]["rules"][0]["server"], "dns-vpn");
        assert_eq!(config["dns"]["servers"][0]["type"], "udp");
        assert_eq!(config["dns"]["servers"][0]["server"], "192.0.2.53");
        assert_eq!(config["inbounds"][1]["listen"], "127.0.0.1");
        assert_eq!(
            config["inbounds"][1]["users"][0]["password"],
            "test-password"
        );
    }
    #[test]
    fn awg_hostname_is_resolved_without_changing_saved_config() {
        for host in ["localhost", "127.0.0.1", "[::1]"] {
            let mut profile = fixture();
            profile.config = profile
                .config
                .replace("[Interface]", "[Interface]\nJc=4")
                .replace("127.0.0.1:51820", &format!("{host}:51820"));
            let original = profile.config.clone();
            let mut options = super::configuration(&profile, &user()).unwrap();
            crate::network::resolve_peers(&mut options).unwrap();
            assert_eq!(
                options["endpoints"][0]["peers"][0]["address"],
                if host == "[::1]" { "::1" } else { "127.0.0.1" }
            );
            assert_eq!(options["endpoints"][0]["peers"][0]["port"], 51820);
            assert_eq!(profile.config, original);
        }
        let mut options = super::configuration(&fixture(), &user()).unwrap();
        options["endpoints"][0]["peers"][0]["address"] = serde_json::json!("::1");
        crate::network::resolve_peers(&mut options).unwrap();
        assert_eq!(options["endpoints"][0]["peers"][0]["address"], "::1");
    }
    #[test]
    fn keepalive_preserves_awg_ranges_and_validates_bounds() {
        for awg in [false, true] {
            for (value, valid) in [
                ("0", true),
                ("25", true),
                ("65535", true),
                ("off", true),
                ("(off)", true),
                ("25-35", awg),
                ("35-25", false),
                ("25-65536", false),
                ("-1", false),
                ("", false),
                ("25-x", false),
                ("25-35-40", false),
            ] {
                let mut profile = fixture();
                if awg {
                    profile.config = profile.config.replace("[Interface]", "[Interface]\nJc=4");
                }
                profile
                    .config
                    .push_str(&format!("\nPersistentKeepalive={value}"));
                let result = super::configuration(&profile, &user());
                assert_eq!(result.is_ok(), valid, "awg={awg}, value={value}");
                if awg && value == "25-35" {
                    assert_eq!(
                        result.unwrap()["endpoints"][0]["peers"][0]["persistent_keepalive_range"],
                        "25-35"
                    );
                }
            }
        }
    }
    #[test]
    fn addresses_ports_and_invalid_rules() {
        assert_eq!(
            super::site("192.168.10.0/24").unwrap()["ip_cidr"][0],
            "192.168.10.0/24"
        );
        assert_eq!(super::site("host.ts.net:8766").unwrap()["port"][0], 8766);
        assert_eq!(
            super::site("*.example.com").unwrap()["domain_suffix"][0],
            "example.com"
        );
        for bad in [
            "192.168.0.1/33",
            "foo:0",
            "https://example.com",
            "../x",
            "x:99999",
        ] {
            assert!(super::site(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn direct_exclusions_precede_vpn_inclusions() {
        let profile = fixture();
        let result = super::configuration(&profile, &user()).unwrap();
        assert_eq!(result["route"]["final"], "direct");
        assert_eq!(result["route"]["rules"][2]["outbound"], "direct");
        assert_eq!(result["route"]["rules"][3]["outbound"], "vpn");
        assert!(result["route"]["rules"][2]["process_path_regex"].is_array());
        assert_eq!(
            super::process_pattern(r"C:\Apps\Discord.exe"),
            r"(?i)^C:\\Apps\\Discord\.exe$"
        );
    }
}
