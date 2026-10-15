package main

import (
	"bytes"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

func TestWireGuardBindBatchSize(t *testing.T) {
	bind := newWireGuardBind()

	if got := bind.BatchSize(); got != 1 {
		t.Fatalf("batch size = %d, want 1 to avoid per-profile batch-buffer retention", got)
	}
}

func TestPacketBindRoundTrip(t *testing.T) {
	tests := []struct {
		network string
		address net.IP
	}{
		{"udp4", net.IPv4(127, 0, 0, 1)},
		{"udp6", net.IPv6loopback},
	}

	for _, test := range tests {
		t.Run(test.network, func(t *testing.T) {
			peer, err := net.ListenUDP(test.network, &net.UDPAddr{IP: test.address})
			if err != nil {
				if test.network == "udp6" &&
					(errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL)) {
					t.Skipf("IPv6 loopback is unavailable: %v", err)
				}

				t.Fatal(err)
			}
			defer peer.Close()

			bind := &packetBind{}
			defer bind.Close()

			receivers, port, err := bind.Open(0)
			if err != nil {
				t.Fatal(err)
			}

			if len(receivers) != 1 || port == 0 {
				t.Fatalf("receivers=%d port=%d, want one receiver and an allocated port", len(receivers), port)
			}

			deadline := time.Now().Add(5 * time.Second)
			if err := peer.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}

			if err := bind.socket.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}

			endpoint, err := bind.ParseEndpoint(peer.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}

			payload := []byte("WireGuard UDP test")
			if err := bind.Send([][]byte{payload}, endpoint); err != nil {
				t.Fatal(err)
			}

			buffer := make([]byte, 2048)

			n, source, err := peer.ReadFromUDPAddrPort(buffer)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(buffer[:n], payload) || source.Port() != port {
				t.Fatalf("unexpected outbound datagram: payload=%q source=%v", buffer[:n], source)
			}

			if _, err := peer.WriteToUDPAddrPort(payload, source); err != nil {
				t.Fatal(err)
			}

			buffers := [][]byte{make([]byte, 2048)}
			sizes := make([]int, 1)
			endpoints := make([]conn.Endpoint, 1)

			n, err = receivers[0](buffers, sizes, endpoints)
			if err != nil {
				t.Fatal(err)
			}

			if n != 1 || !bytes.Equal(buffers[0][:sizes[0]], payload) {
				t.Fatalf("unexpected inbound datagram: count=%d payload=%q", n, buffers[0][:sizes[0]])
			}

			received := endpoints[0]
			received.ClearSrc()

			if received.DstToString() != endpoint.DstToString() ||
				received.DstIP() != endpoint.DstIP() ||
				!bytes.Equal(received.DstToBytes(), endpoint.DstToBytes()) {
				t.Fatalf("received endpoint %s does not match %s", received.DstToString(), endpoint.DstToString())
			}
		})
	}
}

func TestPacketBindCloseAndReopen(t *testing.T) {
	bind := &packetBind{}
	defer bind.Close()

	receivers, port, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := bind.Open(0); err == nil {
		t.Fatal("opening an already open bind succeeded")
	}

	if err := bind.SetMark(0); err != nil {
		t.Fatal(err)
	}

	endpoint, err := bind.ParseEndpoint("127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)

	go func() {
		_, err := receivers[0](
			[][]byte{make([]byte, 2048)},
			make([]int, 1),
			make([]conn.Endpoint, 1),
		)

		result <- err
	}()

	if err := bind.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("receive after close returned %v, want net.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("closing the bind did not unblock its receiver")
	}

	if err := bind.Send([][]byte{[]byte("closed")}, endpoint); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("send after close returned %v, want net.ErrClosed", err)
	}

	if err := bind.Close(); err != nil {
		t.Fatalf("repeated close: %v", err)
	}

	_, reopenedPort, err := bind.Open(port)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}

	if reopenedPort != port {
		t.Fatalf("reopened port = %d, want %d", reopenedPort, port)
	}
}
