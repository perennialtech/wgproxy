//go:build !linux

package main

import "golang.zx2c4.com/wireguard/conn"

func newWireGuardBind() conn.Bind {
	return conn.NewDefaultBind()
}
