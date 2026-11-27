package awg

import (
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestNettIPv6PeerIPC(t *testing.T) {
	options := option.AwgEndpointOptions{
		PrivateKey: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
		Peers:      []option.AwgPeerOptions{{Address: "::1", Port: 51820, PublicKey: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="}},
	}
	ipc, err := genIpcConfig(options)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ipc, "\nendpoint=[::1]:51820") {
		t.Fatal("IPv6 peer was not bracketed")
	}
	if err := newConfigTestDevice(t).IpcSet(ipc); err != nil {
		t.Fatal(err)
	}
}
