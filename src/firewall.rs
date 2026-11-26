use std::{mem::zeroed, net::SocketAddr, path::Path, ptr};
use windows_sys::{
    Win32::{Foundation::HANDLE, NetworkManagement::WindowsFilteringPlatform::*},
    core::GUID,
};

const PROVIDER: GUID = GUID::from_u128(0x27cafb62_f779_4a04_a317_bfd98d20372c);
const SUBLAYER: GUID = GUID::from_u128(0x27cafb62_f779_4a04_a317_bfd98d20372d);
const ALREADY_EXISTS: u32 = 0x80320009;

struct AppId(*mut FWP_BYTE_BLOB);
impl AppId {
    fn load(path: &Path) -> Result<Self, String> {
        use std::os::windows::ffi::OsStrExt;
        let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut id = ptr::null_mut();
        check(unsafe { FwpmGetAppIdFromFileName0(path.as_ptr(), &mut id) })?;
        Ok(Self(id))
    }
    fn condition(&self) -> FWPM_FILTER_CONDITION0 {
        let mut condition = condition(FWPM_CONDITION_ALE_APP_ID, FWP_BYTE_BLOB_TYPE);
        condition.conditionValue.Anonymous.byteBlob = self.0;
        condition
    }
}
impl Drop for AppId {
    fn drop(&mut self) {
        unsafe {
            FwpmFreeMemory0(&mut self.0 as *mut _ as _);
        }
    }
}

fn check(code: u32) -> Result<(), String> {
    if code == 0 {
        Ok(())
    } else {
        Err(format!("KILL SWITCH WFP ERROR {code:#010x}"))
    }
}

struct Engine(HANDLE);
impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            FwpmEngineClose0(self.0);
        }
    }
}
impl Engine {
    fn open() -> Result<Self, String> {
        let mut handle = ptr::null_mut();
        check(unsafe { FwpmEngineOpen0(ptr::null(), 10, ptr::null(), ptr::null(), &mut handle) })?;
        Ok(Self(handle))
    }

    fn remove_filters(&self) -> Result<(), String> {
        unsafe {
            let mut enumeration = ptr::null_mut();
            check(FwpmFilterCreateEnumHandle0(
                self.0,
                ptr::null(),
                &mut enumeration,
            ))?;
            let result = (|| {
                loop {
                    let mut entries = ptr::null_mut();
                    let mut count = 0;
                    check(FwpmFilterEnum0(
                        self.0,
                        enumeration,
                        128,
                        &mut entries,
                        &mut count,
                    ))?;
                    let mut ids = Vec::new();
                    if count > 0 {
                        for entry in std::slice::from_raw_parts(entries, count as usize) {
                            let filter = &**entry;
                            if !filter.providerKey.is_null()
                                && same_guid(&*filter.providerKey, &PROVIDER)
                            {
                                ids.push(filter.filterId);
                            }
                        }
                    }
                    FwpmFreeMemory0(&mut entries as *mut _ as _);
                    for id in ids {
                        check(FwpmFilterDeleteById0(self.0, id))?;
                    }
                    if count == 0 {
                        return Ok(());
                    }
                }
            })();
            FwpmFilterDestroyEnumHandle0(self.0, enumeration);
            result
        }
    }

    fn add(
        &self,
        layer: GUID,
        permit: bool,
        conditions: &mut [FWPM_FILTER_CONDITION0],
    ) -> Result<(), String> {
        unsafe {
            let mut name: Vec<u16> = "nett kill switch\0".encode_utf16().collect();
            let mut provider = PROVIDER;
            let mut filter: FWPM_FILTER0 = zeroed();
            filter.displayData.name = name.as_mut_ptr();
            filter.providerKey = &mut provider;
            filter.subLayerKey = SUBLAYER;
            filter.layerKey = layer;
            filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
            filter.weight.r#type = FWP_UINT8;
            filter.weight.Anonymous.uint8 = if permit { 15 } else { 0 };
            filter.action.r#type = if permit {
                FWP_ACTION_PERMIT
            } else {
                FWP_ACTION_BLOCK
            };
            filter.numFilterConditions = conditions.len() as u32;
            filter.filterCondition = conditions.as_mut_ptr();
            check(FwpmFilterAdd0(
                self.0,
                &filter,
                ptr::null_mut(),
                ptr::null_mut(),
            ))
        }
    }

    fn install(
        &self,
        peers: &[SocketAddr],
        interface: Option<u64>,
        split_engine: Option<&Path>,
    ) -> Result<(), String> {
        let app = split_engine.map(AppId::load).transpose()?;
        unsafe {
            let mut name: Vec<u16> = "nett kill switch\0".encode_utf16().collect();
            let mut provider: FWPM_PROVIDER0 = zeroed();
            provider.providerKey = PROVIDER;
            provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
            provider.displayData.name = name.as_mut_ptr();
            let code = FwpmProviderAdd0(self.0, &provider, ptr::null_mut());
            if code != ALREADY_EXISTS {
                check(code)?;
            }
            let mut sublayer: FWPM_SUBLAYER0 = zeroed();
            sublayer.subLayerKey = SUBLAYER;
            sublayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
            sublayer.providerKey = &mut provider.providerKey;
            sublayer.displayData.name = name.as_mut_ptr();
            sublayer.weight = 0x8000;
            let code = FwpmSubLayerAdd0(self.0, &sublayer, ptr::null_mut());
            if code != ALREADY_EXISTS {
                check(code)?;
            }
            let layers = if app.is_some() {
                [
                    (FWPM_LAYER_ALE_AUTH_CONNECT_V4, true),
                    (FWPM_LAYER_ALE_AUTH_CONNECT_V6, false),
                    (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, true),
                    (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, false),
                ]
            } else {
                [
                    (FWPM_LAYER_OUTBOUND_TRANSPORT_V4, true),
                    (FWPM_LAYER_OUTBOUND_TRANSPORT_V6, false),
                    (FWPM_LAYER_INBOUND_TRANSPORT_V4, true),
                    (FWPM_LAYER_INBOUND_TRANSPORT_V6, false),
                ]
            };
            for (layer, ipv4) in layers {
                self.add(layer, false, &mut [])?;
                // Only the routing core may open physical connections for DIRECTLY. Other apps stay blocked.
                if let Some(app) = &app {
                    self.add(layer, true, &mut [app.condition()])?;
                }
                let mut loopback = condition(FWPM_CONDITION_FLAGS, FWP_UINT32);
                loopback.matchType = FWP_MATCH_FLAGS_ALL_SET;
                loopback.conditionValue.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
                self.add(layer, true, &mut [loopback])?;
                // DHCP and link-local IPv6 discovery keep the underlying connection usable; no blanket DNS exception.
                let mut protocol = condition(FWPM_CONDITION_IP_PROTOCOL, FWP_UINT8);
                protocol.conditionValue.Anonymous.uint8 = 17;
                let mut local = condition(FWPM_CONDITION_IP_LOCAL_PORT, FWP_UINT16);
                local.conditionValue.Anonymous.uint16 = if ipv4 { 68 } else { 546 };
                let mut remote = condition(FWPM_CONDITION_IP_REMOTE_PORT, FWP_UINT16);
                remote.conditionValue.Anonymous.uint16 = if ipv4 { 67 } else { 547 };
                if ipv4 {
                    self.add(layer, true, &mut [protocol, local, remote])?;
                } else {
                    for (prefix, bits) in [([0xfe, 0x80], 10), ([0xff, 0x02], 16)] {
                        let mut mask = FWP_V6_ADDR_AND_MASK {
                            addr: [0; 16],
                            prefixLength: bits,
                        };
                        mask.addr[0..2].copy_from_slice(&prefix);
                        let mut scope =
                            condition(FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_V6_ADDR_MASK);
                        scope.conditionValue.Anonymous.v6AddrMask = &mut mask;
                        self.add(layer, true, &mut [protocol, local, remote, scope])?;
                        let mut icmp = condition(FWPM_CONDITION_IP_PROTOCOL, FWP_UINT8);
                        icmp.conditionValue.Anonymous.uint8 = 58;
                        for kind in [133, 134, 135, 136] {
                            let mut message = condition(FWPM_CONDITION_IP_LOCAL_PORT, FWP_UINT16);
                            message.conditionValue.Anonymous.uint16 = kind;
                            self.add(layer, true, &mut [icmp, message, scope])?;
                        }
                    }
                }
                if let Some(mut luid) = interface {
                    let mut iface = condition(FWPM_CONDITION_IP_LOCAL_INTERFACE, FWP_UINT64);
                    iface.conditionValue.Anonymous.uint64 = &mut luid;
                    self.add(layer, true, &mut [iface])?;
                }
                for peer in peers {
                    if peer.is_ipv4() != ipv4 {
                        continue;
                    }
                    let mut remote = condition(FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_UINT32);
                    let mut v6: FWP_BYTE_ARRAY16 = zeroed();
                    match peer.ip() {
                        std::net::IpAddr::V4(ip) => {
                            remote.conditionValue.Anonymous.uint32 = u32::from_be_bytes(ip.octets())
                        }
                        std::net::IpAddr::V6(ip) => {
                            v6.byteArray16 = ip.octets();
                            remote.conditionValue.r#type = FWP_BYTE_ARRAY16_TYPE;
                            remote.conditionValue.Anonymous.byteArray16 = &mut v6;
                        }
                    }
                    let mut port = condition(FWPM_CONDITION_IP_REMOTE_PORT, FWP_UINT16);
                    port.conditionValue.Anonymous.uint16 = peer.port();
                    let mut protocol = condition(FWPM_CONDITION_IP_PROTOCOL, FWP_UINT8);
                    protocol.conditionValue.Anonymous.uint8 = 17;
                    self.add(layer, true, &mut [remote, port, protocol])?;
                }
            }
            Ok(())
        }
    }
}

fn same_guid(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}
fn condition(key: GUID, kind: FWP_DATA_TYPE) -> FWPM_FILTER_CONDITION0 {
    unsafe {
        let mut condition: FWPM_FILTER_CONDITION0 = zeroed();
        condition.fieldKey = key;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.r#type = kind;
        condition
    }
}

// Persistent filters survive either client/engine crashing. Replace atomically: no open interval.
pub fn replace(
    peers: Option<&[SocketAddr]>,
    interface: Option<u64>,
    split_engine: Option<&Path>,
) -> Result<(), String> {
    let engine = Engine::open()?;
    check(unsafe { FwpmTransactionBegin0(engine.0, 0) })?;
    let result = (|| {
        engine.remove_filters()?;
        if let Some(peers) = peers {
            engine.install(peers, interface, split_engine)?;
        }
        check(unsafe { FwpmTransactionCommit0(engine.0) })
    })();
    if result.is_err() {
        unsafe {
            FwpmTransactionAbort0(engine.0);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore = "requires elevation; blocks ONLY a temporary loopback test port, auto-removes on handle close"]
    fn scoped_app_exception_allows_only_its_executable() {
        use super::*;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let timeout = std::time::Duration::from_millis(500);
        assert!(std::net::TcpStream::connect_timeout(&address, timeout).is_ok());
        unsafe {
            let mut session: FWPM_SESSION0 = zeroed();
            session.flags = FWPM_SESSION_FLAG_DYNAMIC;
            let mut handle = ptr::null_mut();
            check(FwpmEngineOpen0(
                ptr::null(),
                10,
                ptr::null(),
                &session,
                &mut handle,
            ))
            .unwrap();
            let engine = Engine(handle);
            let mut name: Vec<u16> = "nett scoped localhost test\0".encode_utf16().collect();
            let mut provider: FWPM_PROVIDER0 = zeroed();
            provider.displayData.name = name.as_mut_ptr();
            provider.providerKey = GUID::from_u128(0x27cafb62_f779_4a04_a317_bfd98d203740);
            check(FwpmProviderAdd0(engine.0, &provider, ptr::null_mut())).unwrap();
            let mut sublayer: FWPM_SUBLAYER0 = zeroed();
            sublayer.displayData.name = name.as_mut_ptr();
            sublayer.subLayerKey = GUID::from_u128(0x27cafb62_f779_4a04_a317_bfd98d203741);
            sublayer.providerKey = &mut provider.providerKey;
            sublayer.weight = 0x8000;
            check(FwpmSubLayerAdd0(engine.0, &sublayer, ptr::null_mut())).unwrap();
            let mut remote = condition(FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_UINT32);
            remote.conditionValue.Anonymous.uint32 = 0x7f000001;
            let mut port = condition(FWPM_CONDITION_IP_REMOTE_PORT, FWP_UINT16);
            port.conditionValue.Anonymous.uint16 = address.port();
            let mut protocol = condition(FWPM_CONDITION_IP_PROTOCOL, FWP_UINT8);
            protocol.conditionValue.Anonymous.uint8 = 6;
            let mut conditions = [remote, port, protocol];
            let mut filter: FWPM_FILTER0 = zeroed();
            filter.displayData.name = name.as_mut_ptr();
            filter.providerKey = &mut provider.providerKey;
            filter.subLayerKey = sublayer.subLayerKey;
            filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
            filter.weight.r#type = FWP_UINT8;
            filter.weight.Anonymous.uint8 = 0;
            filter.action.r#type = FWP_ACTION_BLOCK;
            filter.numFilterConditions = conditions.len() as u32;
            filter.filterCondition = conditions.as_mut_ptr();
            let mut block_id = 0;
            check(FwpmFilterAdd0(
                engine.0,
                &filter,
                ptr::null_mut(),
                &mut block_id,
            ))
            .unwrap();
            assert!(
                std::net::TcpStream::connect_timeout(&address, timeout).is_err(),
                "WFP must block a new connection to the test port"
            );
            filter.action.r#type = FWP_ACTION_PERMIT;
            filter.weight.Anonymous.uint8 = 15;
            let app = AppId::load(&std::env::current_exe().unwrap()).unwrap();
            let mut app_conditions = [remote, port, protocol, app.condition()];
            filter.numFilterConditions = app_conditions.len() as u32;
            filter.filterCondition = app_conditions.as_mut_ptr();
            let mut permit_id = 0;
            check(FwpmFilterAdd0(
                engine.0,
                &filter,
                ptr::null_mut(),
                &mut permit_id,
            ))
            .unwrap();
            assert!(
                std::net::TcpStream::connect_timeout(&address, timeout).is_ok(),
                "Only the permitted executable should bypass the scoped block"
            );
            use std::os::windows::process::CommandExt;
            let script = "try { $c=New-Object Net.Sockets.TcpClient; $c.Connect('127.0.0.1',[int]$env:NETT_TEST_PORT); $c.Dispose(); exit 0 } catch { exit 7 }";
            let other = std::process::Command::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-Command", script])
                .env("NETT_TEST_PORT", address.port().to_string())
                .creation_flags(0x08000000)
                .status()
                .unwrap();
            assert_eq!(
                other.code(),
                Some(7),
                "An unrelated process must remain blocked"
            );
            check(FwpmFilterDeleteById0(engine.0, permit_id)).unwrap();
            assert!(std::net::TcpStream::connect_timeout(&address, timeout).is_err());
            let core = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(r"engines\AmneziaBox\nett-split-core.exe");
            let core_app = AppId::load(&core).unwrap();
            app_conditions[3] = core_app.condition();
            filter.filterCondition = app_conditions.as_mut_ptr();
            check(FwpmFilterAdd0(
                engine.0,
                &filter,
                ptr::null_mut(),
                &mut permit_id,
            ))
            .unwrap();
            assert_core_direct_rules(&core, address, false);
            assert_core_direct_rules(&core, address, true);
            check(FwpmFilterDeleteById0(engine.0, permit_id)).unwrap();
            check(FwpmFilterDeleteById0(engine.0, block_id)).unwrap();
        }
        assert!(std::net::TcpStream::connect_timeout(&address, timeout).is_ok());
    }

    // Real core + unreachable synthetic VPN peer. No TUN/routes, only an owned localhost server.
    fn assert_core_direct_rules(
        engine: &std::path::Path,
        target: std::net::SocketAddr,
        apps: bool,
    ) {
        use crate::profiles::{Mode, Profile, Rules, UserConfig};
        use std::{
            net::{TcpListener, UdpSocket},
            os::windows::process::CommandExt,
            time::{Duration, Instant},
        };
        let root =
            std::env::temp_dir().join(format!("nett-direct-core-{}-{apps}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("test.conf");
        let unreachable = UdpSocket::bind("127.0.0.1:0").unwrap();
        let profile = Profile {
            id: "fixture".into(),
            name: "test".into(),
            config: format!(
                "[Interface]\nJc=4\nPrivateKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress=10.0.0.2/32\n[Peer]\nPublicKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nEndpoint={}\nAllowedIPs=0.0.0.0/0",
                unreachable.local_addr().unwrap()
            ),
        };
        let mut user = UserConfig::default();
        if apps {
            user.apps = Rules {
                enabled: true,
                mode: Mode::Direct,
                entries: vec![
                    std::env::current_exe()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                ],
            };
        } else {
            user.sites = Rules {
                enabled: true,
                mode: Mode::Direct,
                entries: vec![target.to_string()],
            };
        }
        let sockets = [
            TcpListener::bind("127.0.0.1:0").unwrap(),
            TcpListener::bind("127.0.0.1:0").unwrap(),
        ];
        let direct_port = sockets[0].local_addr().unwrap().port();
        let probe_port = sockets[1].local_addr().unwrap().port();
        drop(sockets);
        let mut config = crate::split::configuration(&profile, &user).unwrap();
        config["log"] = serde_json::json!({"disabled":true});
        config["inbounds"] = serde_json::json!([{"type":"socks","tag":"test-user","listen":"127.0.0.1","listen_port":direct_port,"users":[{"username":"nett","password":"test"}]}]);
        config["route"]["auto_detect_interface"] = serde_json::json!(false);
        // IP-only fixture: no payload sniffing is needed before the SOCKS connect reply.
        config["route"]["rules"]
            .as_array_mut()
            .unwrap()
            .retain(|r| r["action"] != "sniff");
        crate::split::add_probe(&mut config, Some("192.0.2.53"), probe_port, "test");
        std::fs::write(root.join("test.json"), serde_json::to_vec(&config).unwrap()).unwrap();
        let check = std::process::Command::new(engine)
            .arg("check")
            .arg("-c")
            .arg(root.join("test.json"))
            .creation_flags(0x08000000)
            .output()
            .unwrap();
        assert!(
            check.status.success(),
            "Core fixture rejected: {}",
            String::from_utf8_lossy(&check.stderr)
        );
        let log = std::fs::File::create(root.join("core.log")).unwrap();
        let child = std::process::Command::new(engine)
            .arg("run")
            .arg("-c")
            .arg(root.join("test.json"))
            .arg("--nett-ready-file")
            .arg(path.with_extension("ready.json"))
            .arg("--nett-stop-file")
            .arg(path.with_extension("stop"))
            .creation_flags(0x08000000)
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        struct Core {
            child: std::process::Child,
            path: std::path::PathBuf,
            root: std::path::PathBuf,
        }
        impl Drop for Core {
            fn drop(&mut self) {
                let _ = crate::split::stop(&self.path);
                if self.child.try_wait().ok().flatten().is_none() {
                    let _ = self.child.kill();
                }
                let _ = self.child.wait();
                let _ = std::fs::remove_dir_all(&self.root);
            }
        }
        let mut core = Core { child, path, root };
        let deadline = Instant::now() + Duration::from_secs(10);
        while !crate::split::running(&core.path) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        if !crate::split::running(&core.path) {
            let _ = core.child.kill();
            let _ = core.child.wait();
            panic!(
                "Core must become ready: {}",
                std::fs::read_to_string(core.root.join("core.log")).unwrap_or_default()
            );
        }
        let direct = crate::health::socks_connect(direct_port, "test", target);
        let protected = crate::health::socks_connect(probe_port, "test", target);
        drop(core);
        assert!(
            direct.is_ok(),
            "DIRECTLY must work with an unreachable VPN peer (apps={apps}): {direct:?}"
        );
        assert!(
            protected.is_err(),
            "VPN route must never fall back to DIRECTLY (apps={apps})"
        );
    }

    #[test]
    #[ignore = "requires elevation; validates filters inside an ABORTED transaction, never blocks traffic"]
    fn strict_filters_validate_without_changing_network_policy() {
        let engine = super::Engine::open().unwrap();
        super::check(unsafe { super::FwpmTransactionBegin0(engine.0, 0) }).unwrap();
        let result = engine
            .install(
                &[
                    "192.0.2.1:51820".parse().unwrap(),
                    "[2001:db8::1]:51820".parse().unwrap(),
                ],
                Some(1234),
                None,
            )
            .and_then(|_| engine.remove_filters())
            .and_then(|_| {
                engine.install(
                    &["192.0.2.1:51820".parse().unwrap()],
                    Some(1234),
                    Some(&std::env::current_exe().unwrap()),
                )
            })
            .and_then(|_| engine.remove_filters());
        unsafe {
            super::FwpmTransactionAbort0(engine.0);
        }
        result.unwrap();
    }
}
