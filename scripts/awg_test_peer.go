// Local test peer for Nett's outbound-only userspace AWG adapter. No system TUN.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

func run() error {
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		return err
	}
	var config struct {
		Endpoints []map[string]interface{} `json:"endpoints"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}
	endpoint := config.Endpoints[0]
	private, err := base64.StdEncoding.DecodeString(endpoint["private_key"].(string))
	if err != nil {
		return err
	}
	peer := endpoint["peers"].([]interface{})[0].(map[string]interface{})
	public, err := base64.StdEncoding.DecodeString(peer["public_key"].(string))
	if err != nil {
		return err
	}
	ipc := fmt.Sprintf("private_key=%s\nlisten_port=%d", hex.EncodeToString(private), int(endpoint["listen_port"].(float64)))
	for _, name := range []string{"jc", "jmin", "jmax", "s1", "s2"} {
		ipc += fmt.Sprintf("\n%s=%d", name, int(endpoint[name].(float64)))
	}
	for _, name := range []string{"h1", "h2", "h3", "h4"} {
		ipc += "\n" + name + "=" + endpoint[name].(string)
	}
	ipc += "\npublic_key=" + hex.EncodeToString(public) + "\nallowed_ip=10.231.0.2/32"
	tun, network, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.231.0.1")}, nil, 1408)
	if err != nil {
		return err
	}
	engine := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer engine.Close()
	if err := engine.IpcSet(ipc); err != nil {
		return err
	}
	if err := engine.Up(); err != nil {
		return err
	}
	port, err := strconv.Atoi(os.Args[4])
	if err != nil {
		return err
	}
	listener, err := network.ListenTCP(&net.TCPAddr{IP: net.IPv4(10, 231, 0, 1), Port: port})
	if err != nil {
		return err
	}
	defer listener.Close()
	packets, err := network.ListenUDP(&net.UDPAddr{IP: net.IPv4(10, 231, 0, 1), Port: port})
	if err != nil {
		return err
	}
	defer packets.Close()
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, source, err := packets.ReadFrom(buffer)
			if err != nil {
				return
			}
			packets.WriteTo(buffer[:n], source)
		}
	}()
	go func() {
		for {
			stream, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer stream.Close(); io.Copy(stream, stream) }()
		}
	}()
	if err := os.WriteFile(os.Args[2], []byte("ready"), 0600); err != nil {
		return err
	}
	for {
		if _, err := os.Stat(os.Args[3]); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "config, ready, stop and echo port required")
		os.Exit(1)
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
