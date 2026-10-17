// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package wg

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"golang.zx2c4.com/wireguard/device"
)

// https://github.com/amnezia-vpn/amneziawg-go/pull/2/files

const (
	sNoop           = 0 // no-op size
	maxJunkPktSz    = 1280
	maxHandshakePad = 1200
)

// Jc (Junk packet count) - number of packets with random data that are sent before the start of the session
// Jmin (Junk packet minimum size) - minimum packet size for Junk packet. That is, all randomly generated packets will have a size no smaller than Jmin.
// Jmax (Junk packet maximum size) - maximum size for Junk packets
// S1 (Init packet junk size) - the size of random data that will be added to the init packet, the size of which is initially fixed.
// S2 (Response packet junk size) - the size of random data that will be added to the response packet, the size of which is initially fixed.
// H1 (Init packet magic header) - the header of the first byte of the handshake
// H2 (Response packet magic header) - header of the first byte of the handshake response
// H4 (Transport packet magic header) - header of the packet of the data packet
// H3 (Underload packet magic header) - UnderLoad packet header."
type Amnezia struct {
	id string

	Jc, Jmin, Jmax uint16 // unused: junk packet count, min, max

	S1, S2         uint16 // handshake init/resp pkt sizes
	H1, H2, H3, H4 uint32 // modified msg types [4]byte
}

func NewAmnezia(id string) *Amnezia {
	return &Amnezia{
		id: id,
	}
}

func (a *Amnezia) String() string {
	if a == nil {
		return "<nil>"
	}
	if !settings.AmneziaWG.Load() {
		return "<disabled>"
	}
	if !a.set() {
		return "<unset>"
	}
	return fmt.Sprintf("%s: amnezia: jc(%d), jmin(%d), jmax(%d), s1(%d), s2(%d), h1(%d), h2(%d), h3(%d), h4(%d)",
		a.id, a.Jc, a.Jmin, a.Jmax, a.S1, a.S2, a.H1, a.H2, a.H3, a.H4)
}

// Set returns true only when the AmneziaWG global flag is enabled
// and valid Amnezia parameters have been supplied. Otherwise it
// returns false, making the tunnel behave exactly like standard
// WireGuard (strict backward compatibility).
func (a *Amnezia) Set() bool {
	if a == nil || !settings.AmneziaWG.Load() {
		return false
	}
	if err := a.Valid(); err != nil {
		log.W("wg: %s: amnezia: invalid params: %v; falling back to wireguard", a.id, err)
		return false
	}
	return a.set()
}

// set reports whether any amnezia-specific parameter is non-zero,
// ignoring both the global flag and validity checks.
func (a *Amnezia) set() bool {
	if a == nil {
		return false
	}
	return a.Jc > 0 || a.Jmin > 0 || a.Jmax > 0 ||
		a.S1 > 0 || a.S2 > 0 || a.H1 > 0 || a.H2 > 0 || a.H3 > 0 || a.H4 > 0
}

// Valid checks the supplied Amnezia parameters for sanity, mirroring
// the checks in github.com/amnezia-vpn/amneziawg-go device/uapi.go
// and device/receive.go. A nil or unset Amnezia is trivially valid
// (standard WireGuard).
func (a *Amnezia) Valid() error {
	if a == nil || !a.set() {
		return nil
	}
	if a.Jmax < a.Jmin {
		return fmt.Errorf("jmax(%d) < jmin(%d)", a.Jmax, a.Jmin)
	}
	if a.Jmin > maxJunkPktSz {
		return fmt.Errorf("jmin(%d) > %d", a.Jmin, maxJunkPktSz)
	}
	if a.Jmax > maxJunkPktSz {
		return fmt.Errorf("jmax(%d) > %d", a.Jmax, maxJunkPktSz)
	}
	if a.S1 > maxHandshakePad {
		return fmt.Errorf("s1(%d) > %d", a.S1, maxHandshakePad)
	}
	if a.S2 > maxHandshakePad {
		return fmt.Errorf("s2(%d) > %d", a.S2, maxHandshakePad)
	}
	// magic headers must not collide with the standard wg message types
	for i, h := range []uint32{a.H1, a.H2, a.H3, a.H4} {
		if h > 0 && h <= device.MessageTransportType {
			return fmt.Errorf("h%d(%d) collides with a wireguard message type", i+1, h)
		}
	}
	return nil
}

func (a *Amnezia) Same(b *Amnezia) bool {
	if a == nil && b == nil {
		return false
	} else if a == nil || b == nil {
		return false
	}

	return a.S1 == b.S1 &&
		a.S2 == b.S2 &&
		a.H1 == b.H1 &&
		a.H2 == b.H2 &&
		a.H3 == b.H3 &&
		a.H4 == b.H4
}

func (a *Amnezia) send(pktptr *[]byte) (ok bool) {
	if a == nil || !a.Set() {
		return
	}

	pkt := *pktptr

	n := len(pkt)
	if n < device.MinMessageSize {
		return
	}

	typ := binary.LittleEndian.Uint32(pkt)

	*pktptr, _ = a.instate(pkt)

	a.logIfNeeded("send", typ, n, len(*pktptr))

	return true
}

func (a *Amnezia) recv(pkt []byte, upto int) (out []byte, ok bool) {
	if a == nil || !a.Set() {
		return
	}
	if upto < device.MinMessageSize {
		return
	}

	var typ uint32
	// h := uint16(device.MessageTransportOffsetReceiver)
	pkt, typ = a.strip(pkt[:upto])
	strippedSz := len(pkt)

	switch typ {
	case device.MessageInitiationType, a.H1:
		typ = device.MessageInitiationType
		binary.LittleEndian.PutUint32(pkt, device.MessageInitiationType)
	case device.MessageResponseType, a.H2:
		typ = device.MessageResponseType
		binary.LittleEndian.PutUint32(pkt, device.MessageResponseType)
	case device.MessageCookieReplyType, a.H3:
		typ = device.MessageCookieReplyType
		binary.LittleEndian.PutUint32(pkt, device.MessageCookieReplyType)
	case device.MessageTransportType, a.H4: // must be default?
		typ = device.MessageTransportType
		binary.LittleEndian.PutUint32(pkt, device.MessageTransportType)
	default:
		log.W("wg: %s: amnezia: recv: unexpected type %d", a.id, typ)
		// TODO: error?
	}

	a.logIfNeeded("recv", typ, strippedSz, upto)

	return pkt, true
}

func (a *Amnezia) instate(pkt []byte) ([]byte, uint32) {
	n := len(pkt)

	defaultType := binary.LittleEndian.Uint32(pkt)

	pad := uint16(0)
	obsType := uint32(0)
	maybeInstate := false

	switch defaultType {
	case device.MessageInitiationType:
		if n == device.MessageInitiationSize {
			// github.com/amnezia-vpn/amneziawg-go/blob/2e3f7d122c/device/send.go#L130
			pad = a.S1
			obsType = a.H1
			maybeInstate = obsType > 0 || pad > 0
		}
	case device.MessageResponseType:
		if n == device.MessageResponseSize {
			// github.com/amnezia-vpn/amneziawg-go/blob/2e3f7d122c/device/send.go#L198
			pad = a.S2
			obsType = a.H2
			maybeInstate = obsType > 0 || pad > 0
		}
	case device.MessageCookieReplyType:
		if n == device.MessageCookieReplySize {
			pad = sNoop
			obsType = a.H3
			maybeInstate = obsType > 0
		}
	case device.MessageTransportType:
		if n >= device.MinMessageSize {
			pad = sNoop
			obsType = a.H4
			maybeInstate = obsType > 0
		}
	}

	log.VV("wg: %s: amnezia: instate: msg size: %d, msg typ: (d: %d, o: %d), pad? %t, s1/s2: %d/%d, do? %t",
		a.id, n, defaultType, obsType, pad > 0, a.S1, a.S2, maybeInstate)

	useObsType := obsType > 0 && defaultType != obsType
	if useObsType {
		binary.LittleEndian.PutUint32(pkt, obsType)
	}
	// pad may be 0
	if random, err := blob(pad); err != nil { // unlikely
		log.E("wg: %s: amnezia: instate: pad err %v", a.id, err)
	} else if len(random) > 0 && len(random) == int(pad) {
		pkt = append(random, pkt...)
	}

	if useObsType {
		return pkt, obsType
	}
	return pkt, defaultType
}

func (a *Amnezia) strip(pkt []byte) ([]byte, uint32) {
	size := uint16(len(pkt))
	h := uint16(device.MessageTransportOffsetReceiver)
	// assume the correct msg type is in just the first byte:
	// github.com/WireGuard/wireguard-go/blob/12269c2761/device/noise-protocol.go#L56
	defaultType := binary.LittleEndian.Uint32(pkt[:h])

	var discard uint16 = 0
	var possibleType uint32 = 0
	maybeStrip := false

	// ref: github.com/amnezia-vpn/amneziawg-go/blob/2e3f7d122c/device/device.go#L765
	if size == a.S1+device.MessageInitiationSize {
		discard = a.S1
		possibleType = a.H1
		maybeStrip = discard > 0
	} else if size == a.S2+device.MessageResponseSize {
		discard = a.S2
		possibleType = a.H2
		maybeStrip = discard > 0
	} // else: default

	log.VV("wg: %s: amnezia: strip: msg size: %d, msg typ (d: %d / o: %d), s1/s2: %d/%d, do? %t",
		a.id, size, defaultType, possibleType, a.S1, a.S2, maybeStrip)

	if maybeStrip {
		hdr := pkt[discard : discard+h]
		obsType := binary.LittleEndian.Uint32(hdr)
		if obsType == possibleType {
			return pkt[discard:], obsType
		} // else: msg type mismatch, but size matched
		log.W("wg: %s: amnezia: strip: mismatched msg type %d != %d", a.id, obsType, possibleType)
	} // else: nothing to discard

	return pkt, defaultType
}

func (a *Amnezia) logIfNeeded(dir string, typ uint32, n int, newn int) {
	switch typ {
	case device.MessageInitiationType:
		notok := n != device.MessageInitiationSize
		logif(notok)("wg: %s: amnezia: %s: err initiation %d != %d (=> %d)",
			a.id, dir, n, device.MessageInitiationSize, newn)
	case device.MessageResponseType:
		notok := n != device.MessageResponseSize
		logif(notok)("wg: %s: amnezia: %s: err response %d != %d (=> %d)",
			a.id, dir, n, device.MessageResponseSize, newn)
	case device.MessageCookieReplyType:
		notok := n != device.MessageCookieReplySize
		logif(notok)("wg: %s: amnezia: %s: err cookie %d != %d (=> %d)",
			a.id, dir, n, device.MessageCookieReplySize, newn)
	case device.MessageTransportType:
		notok := n < device.MinMessageSize
		logif(notok)("wg: %s: amnezia: %s: err data %d < %d (=> %d)",
			a.id, dir, n, device.MinMessageSize, newn)
	default:
		log.W("wg: %s: amnezia: %s: unexpected type %d; sz(pkt): %d => %d",
			a.id, dir, typ, n, newn)
	}
}

// ref: github.com/amnezia-vpn/amneziawg-go/blob/2e3f7d122c/device/util.go#L1
func blob(sz uint16) ([]byte, error) {
	if sz == 0 {
		return nil, nil
	}

	junk := make([]byte, sz)
	n, err := rand.Read(junk)
	return junk[:n], err
}

func logif(cond bool) log.LogFn {
	if cond {
		return log.D
	}
	return log.N
}
