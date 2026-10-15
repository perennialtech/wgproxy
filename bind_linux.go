package main

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

// Single-packet I/O avoids retaining batch-sized groups of WireGuard message
// buffers in every isolated device, including its idle receive loops.
func newWireGuardBind() conn.Bind {
	return &packetBind{}
}

type packetBind struct {
	mu     sync.Mutex
	socket *net.UDPConn
}

func (b *packetBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.socket != nil {
		return nil, 0, errors.New("WireGuard UDP bind is already open")
	}

	// An unspecified IP lets Go use a dual-stack socket when available.
	socket, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(port)})
	if err != nil {
		return nil, 0, err
	}

	b.socket = socket

	receive := func(buffers [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		n, address, err := socket.ReadFromUDPAddrPort(buffers[0])
		if err != nil {
			return 0, err
		}

		sizes[0] = n
		endpoints[0] = &packetEndpoint{
			address: netip.AddrPortFrom(address.Addr().Unmap(), address.Port()),
		}

		return 1, nil
	}

	return []conn.ReceiveFunc{receive}, uint16(socket.LocalAddr().(*net.UDPAddr).Port), nil
}

func (b *packetBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.socket == nil {
		return nil
	}

	err := b.socket.Close()
	b.socket = nil

	return err
}

func (*packetBind) SetMark(mark uint32) error {
	if mark != 0 {
		return errors.New("WireGuard UDP socket marks are not supported")
	}

	return nil
}

func (b *packetBind) Send(buffers [][]byte, endpoint conn.Endpoint) error {
	b.mu.Lock()
	socket := b.socket
	b.mu.Unlock()

	if socket == nil {
		return net.ErrClosed
	}

	address := endpoint.(*packetEndpoint).address

	for _, buffer := range buffers {
		if _, err := socket.WriteToUDPAddrPort(buffer, address); err != nil {
			return err
		}
	}

	return nil
}

func (*packetBind) ParseEndpoint(value string) (conn.Endpoint, error) {
	address, err := netip.ParseAddrPort(value)
	if err != nil {
		return nil, err
	}

	return &packetEndpoint{
		address: netip.AddrPortFrom(address.Addr().Unmap(), address.Port()),
	}, nil
}

func (*packetBind) BatchSize() int {
	return 1
}

type packetEndpoint struct {
	address netip.AddrPort
}

func (*packetEndpoint) ClearSrc() {}

func (*packetEndpoint) SrcToString() string {
	return ""
}

func (*packetEndpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}

func (e *packetEndpoint) DstToString() string {
	return e.address.String()
}

func (e *packetEndpoint) DstIP() netip.Addr {
	return e.address.Addr()
}

func (e *packetEndpoint) DstToBytes() []byte {
	return binary.LittleEndian.AppendUint16(e.address.Addr().AsSlice(), e.address.Port())
}
