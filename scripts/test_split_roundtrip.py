"""Exercise real WG/AWG encryption on localhost, without a TUN or system routes."""
import json
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORE = ROOT / 'engines/AmneziaBox/nett-split-core.exe'
AWG = ROOT / 'engines/AmneziaWG/awg.exe'
AWG_PEER = ROOT / 'artifacts/nett-awg-test-peer.exe'
HIDDEN = subprocess.CREATE_NO_WINDOW


def keypair():
    private = subprocess.check_output([str(AWG), 'genkey'], creationflags=HIDDEN).strip()
    public = subprocess.check_output([str(AWG), 'pubkey'], input=private + b'\n', creationflags=HIDDEN).strip()
    return private.decode(), public.decode()


def exact(stream, count):
    data = b''
    while len(data) < count:
        chunk = stream.recv(count - len(data))
        if not chunk:
            raise OSError('unexpected SOCKS EOF')
        data += chunk
    return data


def roundtrip(awg, ipv6=False):
    protocol = 'awg' if awg else 'wireguard'
    client_key, client_public = keypair()
    server_key, server_public = keypair()
    children = []
    with tempfile.TemporaryDirectory(prefix='nett-encrypted-test-') as temporary:
        directory = Path(temporary)
        with socket.socket() as backend, socket.socket() as socks, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp1, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp2, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagrams:
            for stream in (backend, socks, udp1, udp2):
                stream.bind(('127.0.0.1', 0))
            backend.listen()
            backend.settimeout(0.2)
            backend_port, socks_port, server_port, client_port = [s.getsockname()[1] for s in (backend, socks, udp1, udp2)]
            datagrams.bind(('127.0.0.1', backend_port))
            datagrams.settimeout(0.2)
            socks.close()
            udp1.close()
            udp2.close()
            done = threading.Event()
            payload = b'nett encrypted roundtrip // ' + protocol.encode() + bytes(range(256)) * 16

            def serve():
                while not done.is_set():
                    try:
                        stream, _ = backend.accept()
                    except socket.timeout:
                        continue
                    except OSError:
                        return
                    with stream:
                        stream.settimeout(5)
                        try:
                            if exact(stream, len(payload)) == payload:
                                stream.sendall(payload)
                        except OSError:
                            pass

            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            def serve_udp():
                while not done.is_set():
                    try:
                        packet, source = datagrams.recvfrom(2048)
                        datagrams.sendto(packet, source)
                    except socket.timeout:
                        continue
                    except OSError:
                        return
            udp_worker = threading.Thread(target=serve_udp, daemon=True)
            udp_worker.start()
            try:
                for server in (True, False):
                    name = 'server' if server else 'client'
                    endpoint = {
                        'type': protocol, 'tag': 'vpn',
                        'address': ['10.231.0.1/32' if server else '10.231.0.2/32'],
                        'private_key': server_key if server else client_key,
                        'listen_port': server_port if server else client_port,
                        'peers': [{'address': '::1' if ipv6 else '127.0.0.1', 'port': client_port if server else server_port,
                                   'public_key': client_public if server else server_public,
                                   'allowed_ips': ['10.231.0.2/32' if server else '10.231.0.1/32']}],
                    }
                    if awg:
                        endpoint.update(useIntegratedTun=False, jc=1, jmin=40, jmax=70, s1=10, s2=20,
                                        h1='123456', h2='234567', h3='345678', h4='456789')
                    else:
                        endpoint['system'] = False
                    config = {
                        'log': {'disabled': True}, 'dns': {}, 'endpoints': [endpoint],
                        'inbounds': [] if server else [{'type': 'socks', 'tag': 'test', 'listen': '127.0.0.1', 'listen_port': socks_port}],
                        'outbounds': [{'type': 'direct', 'tag': 'direct'}],
                        'route': {'auto_detect_interface': False, 'final': 'direct' if server else 'vpn',
                                  'rules': [{'inbound': ['vpn'], 'action': 'route', 'outbound': 'direct',
                                             'override_address': '127.0.0.1', 'override_port': backend_port}] if server else []},
                    }
                    path = directory / (name + '.json')
                    path.write_text(json.dumps(config), encoding='utf-8')
                    if awg and server:
                        command = [str(AWG_PEER), str(path), str(directory / (name + '.ready')), str(directory / (name + '.stop')), str(backend_port)]
                    else:
                        check = subprocess.run([str(CORE), 'check', '-c', str(path)], capture_output=True, creationflags=HIDDEN)
                        if check.returncode:
                            raise RuntimeError(check.stderr.decode(errors='replace'))
                        command = [str(CORE), 'run', '-c', str(path), '--nett-ready-file', str(directory / (name + '.ready')), '--nett-stop-file', str(directory / (name + '.stop'))]
                    child = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=HIDDEN)
                    children.append((name, child))
                    deadline = time.monotonic() + 10
                    while not (directory / (name + '.ready')).exists():
                        if child.poll() is not None or time.monotonic() > deadline:
                            raise RuntimeError(protocol + ' ' + name + ' failed to start')
                        time.sleep(0.05)
                with socket.create_connection(('127.0.0.1', socks_port), timeout=10) as stream:
                    stream.settimeout(10)
                    stream.sendall(bytes([5, 1, 0]))
                    assert exact(stream, 2) == bytes([5, 0])
                    stream.sendall(bytes([5, 1, 0, 1, 10, 231, 0, 1]) + backend_port.to_bytes(2, 'big'))
                    response = exact(stream, 4)
                    assert response[:3] == bytes([5, 0, 0]), protocol + ' encrypted connect failed'
                    exact(stream, 6 if response[3] == 1 else 18)
                    stream.sendall(payload)
                    assert exact(stream, len(payload)) == payload
                with socket.create_connection(('127.0.0.1', socks_port), timeout=10) as control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    control.settimeout(10)
                    udp.settimeout(10)
                    udp.bind(('127.0.0.1', 0))
                    control.sendall(bytes([5, 1, 0]))
                    assert exact(control, 2) == bytes([5, 0])
                    control.sendall(bytes([5, 3, 0, 1, 127, 0, 0, 1]) + udp.getsockname()[1].to_bytes(2, 'big'))
                    response = exact(control, 4)
                    assert response[:3] == bytes([5, 0, 0]) and response[3] == 1
                    relay = exact(control, 6)
                    relay_port = int.from_bytes(relay[4:], 'big')
                    packet = bytes([0, 0, 0, 1, 10, 231, 0, 1]) + backend_port.to_bytes(2, 'big') + payload[:48]
                    udp.sendto(packet, ('127.0.0.1', relay_port))
                    reply, _ = udp.recvfrom(2048)
                    assert reply[:4] == bytes([0, 0, 0, 1]) and reply[10:] == payload[:48]
                print(protocol + (' peer IPv6' if ipv6 else ' peer IPv4') + ': encrypted handshake + segmented TCP + UDP roundtrip PASS', flush=True)
            finally:
                for name, child in reversed(children):
                    if child.poll() is None:
                        (directory / (name + '.stop')).write_text('stop')
                        try:
                            child.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            child.kill()
                            child.wait()
                done.set()
                worker.join(timeout=1)
                udp_worker.join(timeout=1)


if __name__ == '__main__':
    roundtrip(False)
    roundtrip(True)
    roundtrip(False, True)
    roundtrip(True, True)
