/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2020 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"C"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/tunnel"

	"crypto/rand"
	"log"
	"unsafe"
)

//export WireGuardTunnelService
func WireGuardTunnelService(confFile16 *uint16, serviceName16 *uint16) bool {
	confFile := windows.UTF16ToString((*[(1 << 30) - 1]uint16)(unsafe.Pointer(confFile16))[:])
	serviceName := windows.UTF16ToString((*[(1 << 30) - 1]uint16)(unsafe.Pointer(serviceName16))[:])
	
	conf.SetServiceName(serviceName)
	root, error := conf.SetRootDirectory()

	if error != nil {
		log.Printf("Service run error, root cannot be deduced: %v", error)
	} else {
		log.Printf("tunnel.dll Root deduced as: %v", root)
	}

	tunnel.UseFixedGUIDInsteadOfDeterministic = true
	err := tunnel.Run(confFile)
	if err != nil {
		log.Printf("Service run error: %v", err)
	}
	return err == nil
}

//export WireGuardGenerateKeypair
func WireGuardGenerateKeypair(publicKey *byte, privateKey *byte) {
	publicKeyArray := (*[32]byte)(unsafe.Pointer(publicKey))
	privateKeyArray := (*[32]byte)(unsafe.Pointer(privateKey))
	n, err := rand.Read(privateKeyArray[:])
	if err != nil || n != len(privateKeyArray) {
		panic("Unable to generate random bytes")
	}
	privateKeyArray[0] &= 248
	privateKeyArray[31] = (privateKeyArray[31] & 127) | 64

	curve25519.ScalarBaseMult(publicKeyArray, privateKeyArray)
}

func main() {}
