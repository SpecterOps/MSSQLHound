// Package mssql - TDS transport layer for raw EPA testing.
// Implements TDS packet framing and TLS-over-TDS handshake adapter.
package mssql

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// TDS packet types
const (
	tdsPacketTabularResult byte = 0x04
	tdsPacketLogin7        byte = 0x10
	tdsPacketSSPI          byte = 0x11
	tdsPacketPrelogin      byte = 0x12
)

// TDS header size
const tdsHeaderSize = 8

// Maximum TDS packet size for EPA testing
const tdsMaxPacketSize = 4096

// tdsConn wraps a net.Conn with TDS packet-level read/write.
type tdsConn struct {
	conn net.Conn
}

func newTDSConn(conn net.Conn) *tdsConn {
	return &tdsConn{conn: conn}
}

// sendPacket sends a complete TDS packet with the given type and payload.
func (t *tdsConn) sendPacket(packetType byte, payload []byte) error {
	maxPayload := tdsMaxPacketSize - tdsHeaderSize
	offset := 0
	for offset < len(payload) {
		end := offset + maxPayload
		isLast := end >= len(payload)
		if isLast {
			end = len(payload)
		}

		chunk := payload[offset:end]
		pktLen := tdsHeaderSize + len(chunk)

		status := byte(0x00)
		if isLast {
			status = 0x01 // EOM
		}

		hdr := [tdsHeaderSize]byte{
			packetType,
			status,
			byte(pktLen >> 8), byte(pktLen), // Length big-endian
			0x00, 0x00, // SPID
			0x00, // PacketID
			0x00, // Window
		}

		if _, err := t.conn.Write(hdr[:]); err != nil {
			return fmt.Errorf("TDS write header: %w", err)
		}
		if _, err := t.conn.Write(chunk); err != nil {
			return fmt.Errorf("TDS write payload: %w", err)
		}

		offset = end
	}
	return nil
}

// readFullPacket reads all TDS packets until EOM, returning concatenated payload.
func (t *tdsConn) readFullPacket() (byte, []byte, error) {
	var result []byte
	var packetType byte

	for {
		hdr := make([]byte, tdsHeaderSize)
		if _, err := io.ReadFull(t.conn, hdr); err != nil {
			return 0, nil, fmt.Errorf("TDS read header: %w", err)
		}

		packetType = hdr[0]
		status := hdr[1]
		pktLen := int(binary.BigEndian.Uint16(hdr[2:4]))

		if pktLen < tdsHeaderSize {
			return 0, nil, fmt.Errorf("TDS packet length %d too small", pktLen)
		}

		payloadLen := pktLen - tdsHeaderSize
		if payloadLen > 0 {
			payload := make([]byte, payloadLen)
			if _, err := io.ReadFull(t.conn, payload); err != nil {
				return 0, nil, fmt.Errorf("TDS read payload: %w", err)
			}
			result = append(result, payload...)
		}

		if status&0x01 != 0 { // EOM
			break
		}
	}

	return packetType, result, nil
}

// tlsOverTDSConn implements net.Conn to wrap TLS handshake traffic inside
// TDS PRELOGIN (0x12) packets. This is passed to tls.Client() during the
// TLS-over-TDS handshake phase.
type tlsOverTDSConn struct {
	tds     *tdsConn
	readBuf bytes.Buffer
}

func (c *tlsOverTDSConn) Read(b []byte) (int, error) {
	// If we have buffered data from a previous TDS packet, return it first
	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(b)
	}

	// Read a TDS packet and buffer the payload (TLS record data)
	_, payload, err := c.tds.readFullPacket()
	if err != nil {
		return 0, err
	}

	c.readBuf.Write(payload)
	return c.readBuf.Read(b)
}

func (c *tlsOverTDSConn) Write(b []byte) (int, error) {
	// Wrap TLS data in a TDS PRELOGIN packet
	if err := c.tds.sendPacket(tdsPacketPrelogin, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *tlsOverTDSConn) Close() error                       { return c.tds.conn.Close() }
func (c *tlsOverTDSConn) LocalAddr() net.Addr                { return c.tds.conn.LocalAddr() }
func (c *tlsOverTDSConn) RemoteAddr() net.Addr               { return c.tds.conn.RemoteAddr() }
func (c *tlsOverTDSConn) SetDeadline(t time.Time) error      { return c.tds.conn.SetDeadline(t) }
func (c *tlsOverTDSConn) SetReadDeadline(t time.Time) error  { return c.tds.conn.SetReadDeadline(t) }
func (c *tlsOverTDSConn) SetWriteDeadline(t time.Time) error { return c.tds.conn.SetWriteDeadline(t) }

// switchableConn allows swapping the underlying connection after TLS handshake.
// During handshake, it delegates to tlsOverTDSConn. After handshake, it delegates
// to the raw TCP connection for ENCRYPT_OFF or stays on TLS for ENCRYPT_REQ.
type switchableConn struct {
	c net.Conn
}

func (s *switchableConn) Read(b []byte) (int, error)         { return s.c.Read(b) }
func (s *switchableConn) Write(b []byte) (int, error)        { return s.c.Write(b) }
func (s *switchableConn) Close() error                       { return s.c.Close() }
func (s *switchableConn) LocalAddr() net.Addr                { return s.c.LocalAddr() }
func (s *switchableConn) RemoteAddr() net.Addr               { return s.c.RemoteAddr() }
func (s *switchableConn) SetDeadline(t time.Time) error      { return s.c.SetDeadline(t) }
func (s *switchableConn) SetReadDeadline(t time.Time) error  { return s.c.SetReadDeadline(t) }
func (s *switchableConn) SetWriteDeadline(t time.Time) error { return s.c.SetWriteDeadline(t) }

// performTLSHandshake establishes TLS over TDS and returns the tls.Conn.
// The switchable conn allows the caller to swap back to raw TCP after handshake
// (needed for ENCRYPT_OFF where TLS is only used during LOGIN7).
func performTLSHandshake(tds *tdsConn, serverName string) (*tls.Conn, *switchableConn, error) {
	handshakeAdapter := &tlsOverTDSConn{tds: tds}
	sw := &switchableConn{c: handshakeAdapter}

	tlsConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // EPA testing requires connecting to any server
		// Disable dynamic record sizing for TDS compatibility
		DynamicRecordSizingDisabled: true,
	}

	tlsConn := tls.Client(sw, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	// After handshake, switch underlying connection to raw TCP.
	// TLS records now go directly on the wire (no TDS wrapping).
	sw.c = tds.conn

	return tlsConn, sw, nil
}

// performDirectTLSHandshake establishes TLS directly on the TCP connection
// for TDS 8.0 strict encryption mode. Unlike performTLSHandshake which wraps
// TLS records inside TDS PRELOGIN packets, this does a standard TLS handshake
// on the raw socket (like HTTPS). All subsequent TDS messages are sent through
// the TLS connection.
func performDirectTLSHandshake(conn net.Conn, serverName string) (*tls.Conn, error) {
	tlsConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // EPA testing requires connecting to any server
		// Disable dynamic record sizing for TDS compatibility
		DynamicRecordSizingDisabled: true,
	}

	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	return tlsConn, nil
}
