use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    time::Duration,
};
use windows_sys::Win32::{
    NetworkManagement::{IpHelper::*, Ndis::NET_LUID_LH},
    Networking::WinSock::*,
};

const TIMEOUT: Duration = Duration::from_secs(2);
const TARGETS: [&str; 2] = ["1.1.1.1:443", "1.0.0.1:443"];

pub fn interface(alias: &str) -> Option<(u64, u32)> {
    let alias: Vec<u16> = alias.encode_utf16().chain(Some(0)).collect();
    unsafe {
        let mut luid: NET_LUID_LH = std::mem::zeroed();
        let mut index = 0;
        if ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut luid) != 0
            || ConvertInterfaceLuidToIndex(&luid, &mut index) != 0
        {
            return None;
        }
        Some((luid.Value, index))
    }
}

// A source address alone is insufficient: IP_UNICAST_IF prevents a physical-route fallback.
fn native_connect(index: u32, target: SocketAddr) -> Result<(), String> {
    use std::os::windows::io::FromRawSocket;
    unsafe {
        let mut wsa: WSADATA = std::mem::zeroed();
        if WSAStartup(0x202, &mut wsa) != 0 {
            return Err("WINSOCK INITIALIZATION FAILED".into());
        }
        let result = (|| {
            let socket = WSASocketW(
                AF_INET as i32,
                SOCK_STREAM,
                IPPROTO_TCP,
                std::ptr::null(),
                0,
                WSA_FLAG_OVERLAPPED,
            );
            if socket == INVALID_SOCKET {
                return Err("PROBE SOCKET FAILED".into());
            }
            let stream = TcpStream::from_raw_socket(socket as _);
            let bound = index.to_be();
            if setsockopt(
                socket,
                IPPROTO_IP,
                IP_UNICAST_IF,
                &bound as *const _ as _,
                4,
            ) == SOCKET_ERROR
            {
                return Err("CANNOT BIND PROBE TO VPN INTERFACE".into());
            }
            stream.set_nonblocking(true).map_err(|e| e.to_string())?;
            let SocketAddr::V4(target) = target else {
                return Err("IPV4 PROBE REQUIRED".into());
            };
            let mut address: SOCKADDR_IN = std::mem::zeroed();
            address.sin_family = AF_INET;
            address.sin_port = target.port().to_be();
            address.sin_addr.S_un.S_addr = u32::from_ne_bytes(target.ip().octets());
            if connect(
                socket,
                &address as *const _ as _,
                std::mem::size_of_val(&address) as i32,
            ) == 0
            {
                return Ok(());
            }
            if WSAGetLastError() != WSAEWOULDBLOCK {
                return Err("VPN PROBE CONNECT FAILED".into());
            }
            let mut writable: FD_SET = std::mem::zeroed();
            writable.fd_count = 1;
            writable.fd_array[0] = socket;
            let mut errors = writable;
            let timeout = TIMEVAL {
                tv_sec: TIMEOUT.as_secs() as i32,
                tv_usec: 0,
            };
            if select(
                0,
                std::ptr::null_mut(),
                &mut writable,
                &mut errors,
                &timeout,
            ) <= 0
            {
                return Err("VPN PROBE TIMED OUT".into());
            }
            let mut error = 0i32;
            let mut length = 4;
            if getsockopt(
                socket,
                SOL_SOCKET,
                SO_ERROR,
                &mut error as *mut _ as _,
                &mut length,
            ) != 0
                || error != 0
            {
                return Err("VPN PROBE REJECTED".into());
            }
            Ok(())
        })();
        WSACleanup();
        result
    }
}

pub(crate) fn socks_connect(port: u16, password: &str, target: SocketAddr) -> Result<(), String> {
    let mut stream =
        TcpStream::connect_timeout(&SocketAddr::from((Ipv4Addr::LOCALHOST, port)), TIMEOUT)
            .map_err(|_| "VPN PROBE LISTENER UNAVAILABLE")?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(TIMEOUT))
        .map_err(|e| e.to_string())?;
    stream.write_all(&[5, 1, 2]).map_err(|e| e.to_string())?;
    let mut response = [0; 2];
    stream
        .read_exact(&mut response)
        .map_err(|_| "VPN PROBE NEGOTIATION FAILED")?;
    if response != [5, 2] {
        return Err("INVALID VPN PROBE NEGOTIATION".into());
    }
    if password.is_empty() || password.len() > 255 {
        return Err("INVALID VPN PROBE CREDENTIAL".into());
    }
    let mut auth = vec![1, 4];
    auth.extend(b"nett");
    auth.push(password.len() as u8);
    auth.extend(password.as_bytes());
    stream.write_all(&auth).map_err(|e| e.to_string())?;
    stream
        .read_exact(&mut response)
        .map_err(|_| "VPN PROBE AUTHENTICATION FAILED")?;
    if response != [1, 0] {
        return Err("VPN PROBE AUTHENTICATION FAILED".into());
    }
    let SocketAddr::V4(target) = target else {
        return Err("IPV4 PROBE REQUIRED".into());
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend(target.ip().octets());
    request.extend(target.port().to_be_bytes());
    stream.write_all(&request).map_err(|e| e.to_string())?;
    let mut header = [0; 4];
    stream
        .read_exact(&mut header)
        .map_err(|_| "VPN PROBE DID NOT CONNECT")?;
    if header[0..3] != [5, 0, 0] {
        return Err("VPN PROBE REMOTE CONNECT FAILED".into());
    }
    let length = match header[3] {
        1 => 6,
        4 => 18,
        _ => return Err("INVALID VPN PROBE RESPONSE".into()),
    };
    stream
        .read_exact(&mut vec![0; length])
        .map_err(|_| "TRUNCATED VPN PROBE RESPONSE")?;
    Ok(())
}

pub fn verify(alias: &str, socks: Option<(u16, &str)>) -> Result<(), String> {
    let native = if socks.is_none() {
        Some(interface(alias).ok_or("VPN INTERFACE NOT READY")?.1)
    } else {
        None
    };
    for target in TARGETS {
        let target = target.parse().unwrap();
        let result = if let Some((port, password)) = socks {
            socks_connect(port, password, target)
        } else {
            native_connect(native.unwrap(), target)
        };
        if result.is_ok() {
            return Ok(());
        }
    }
    Err("VPN UNVERIFIED - TUNNEL PROBE FAILED (TCP 443)".into())
}

#[cfg(test)]
mod tests {
    #[test]
    fn native_probe_requires_its_selected_interface() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut index = 0;
        assert_eq!(
            unsafe { super::GetBestInterface(u32::from_ne_bytes([127, 0, 0, 1]), &mut index) },
            0
        );
        assert!(super::native_connect(index, listener.local_addr().unwrap()).is_ok());
        assert!(super::native_connect(u32::MAX, listener.local_addr().unwrap()).is_err());
    }

    #[test]
    fn authenticated_socks_probe_validates_complete_connect_reply() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut stream, _) = listener.accept().unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [5, 1, 2]);
            stream.write_all(&[5, 2]).unwrap();
            let mut auth = [0; 11];
            stream.read_exact(&mut auth).unwrap();
            assert_eq!(&auth, b"\x01\x04nett\x04test");
            stream.write_all(&[1, 0]).unwrap();
            let mut request = [0; 10];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(request, [5, 1, 0, 1, 192, 0, 2, 1, 1, 187]);
            stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
        });
        assert!(super::socks_connect(port, "test", "192.0.2.1:443".parse().unwrap()).is_ok());
        server.join().unwrap();
    }

    #[test]
    fn failed_socks_probe_never_falls_back_to_direct_connection() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut stream, _) = listener.accept().unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).unwrap();
            stream.write_all(&[5, 0xff]).unwrap();
        });
        assert!(super::socks_connect(port, "test", "192.0.2.1:443".parse().unwrap()).is_err());
        server.join().unwrap();
    }
}
