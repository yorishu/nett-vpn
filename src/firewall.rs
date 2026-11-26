use std::{mem::zeroed, net::SocketAddr, ptr};
use windows_sys::{
    Win32::{Foundation::HANDLE, NetworkManagement::WindowsFilteringPlatform::*},
    core::GUID,
};

const PROVIDER: GUID = GUID::from_u128(0x27cafb62_f779_4a04_a317_bfd98d20372c);
const SUBLAYER: GUID = GUID::from_u128(0x27cafb62_f779_4a04_a317_bfd98d20372d);
const ALREADY_EXISTS: u32 = 0x80320009;

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
            let mut name: Vec<u16> = "nett strict kill switch\0".encode_utf16().collect();
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

    fn install(&self, peers: &[SocketAddr], interface: Option<u64>) -> Result<(), String> {
        unsafe {
            let mut name: Vec<u16> = "nett strict kill switch\0".encode_utf16().collect();
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
            for (layer, ipv4) in [
                (FWPM_LAYER_OUTBOUND_TRANSPORT_V4, true),
                (FWPM_LAYER_OUTBOUND_TRANSPORT_V6, false),
                (FWPM_LAYER_INBOUND_TRANSPORT_V4, true),
                (FWPM_LAYER_INBOUND_TRANSPORT_V6, false),
            ] {
                self.add(layer, false, &mut [])?;
                let mut loopback = condition(FWPM_CONDITION_FLAGS, FWP_UINT32);
                loopback.matchType = FWP_MATCH_FLAGS_ALL_SET;
                loopback.conditionValue.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
                self.add(layer, true, &mut [loopback])?;
                // DHCP and link-local IPv6 discovery keep the underlying connection usable; no DNS exception.
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
pub fn replace(peers: Option<&[SocketAddr]>, interface: Option<u64>) -> Result<(), String> {
    let engine = Engine::open()?;
    check(unsafe { FwpmTransactionBegin0(engine.0, 0) })?;
    let result = (|| {
        engine.remove_filters()?;
        if let Some(peers) = peers {
            engine.install(peers, interface)?;
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
    fn scoped_loopback_block_is_enforced_and_permit_priority_works() {
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
            filter.layerKey = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
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
                "Higher permit in the same sublayer must win"
            );
            check(FwpmFilterDeleteById0(engine.0, permit_id)).unwrap();
            check(FwpmFilterDeleteById0(engine.0, block_id)).unwrap();
        }
        assert!(std::net::TcpStream::connect_timeout(&address, timeout).is_ok());
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
            )
            .and_then(|_| engine.remove_filters());
        unsafe {
            super::FwpmTransactionAbort0(engine.0);
        }
        result.unwrap();
    }
}
