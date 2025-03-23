package bittorrent

import (
	"context"
	"encoding/binary"

	"math"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/errors"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

type SniffHeader struct{}

func (h *SniffHeader) Protocol() string {
	return "bittorrent"
}

func (h *SniffHeader) Domain() string {
	return ""
}

var errNotBittorrent = errors.New("not bittorrent header")

func SniffBittorrent(b []byte, ctx context.Context) (*SniffHeader, error) {
	if len(b) < 20 {
		return nil, common.ErrNoClue
	}

	if strings.Contains(strings.ToLower(string(b)), "torrent") {
		// println("SniffBittorrent OK")
		errors.LogError(ctx, "SniffBittorrent OK")

		return &SniffHeader{}, nil
	}
	// Ethernet header is 14 bytes, IP header is 20 bytes (assuming no options)
	// tcpHeaderStart := 14 + 20 // Offset to TCP header

	// if len(b) > tcpHeaderStart+1 {
	// 	// Extract Source Port (first 2 bytes of TCP header)
	// 	sourcePort := uint16(b[tcpHeaderStart])<<8 | uint16(b[tcpHeaderStart+1])
	// 	println("bittorrent port", sourcePort)
	// }
	return nil, errNotBittorrent
}

func SniffUTP(b []byte) (*SniffHeader, error) {
	if len(b) < 20 {
		return nil, common.ErrNoClue
	}

	buffer := buf.FromBytes(b)

	var typeAndVersion uint8

	if binary.Read(buffer, binary.BigEndian, &typeAndVersion) != nil {
		return nil, common.ErrNoClue
	} else if b[0]>>4&0xF > 4 || b[0]&0xF != 1 {
		return nil, errNotBittorrent
	}

	var extension uint8

	if binary.Read(buffer, binary.BigEndian, &extension) != nil {
		return nil, common.ErrNoClue
	} else if extension != 0 && extension != 1 {
		return nil, errNotBittorrent
	}

	for extension != 0 {
		if extension != 1 {
			return nil, errNotBittorrent
		}
		if binary.Read(buffer, binary.BigEndian, &extension) != nil {
			return nil, common.ErrNoClue
		}

		var length uint8
		if err := binary.Read(buffer, binary.BigEndian, &length); err != nil {
			return nil, common.ErrNoClue
		}
		if common.Error2(buffer.ReadBytes(int32(length))) != nil {
			return nil, common.ErrNoClue
		}
	}

	if common.Error2(buffer.ReadBytes(2)) != nil {
		return nil, common.ErrNoClue
	}

	var timestamp uint32
	if err := binary.Read(buffer, binary.BigEndian, &timestamp); err != nil {
		return nil, common.ErrNoClue
	}
	if math.Abs(float64(time.Now().UnixMicro()-int64(timestamp))) > float64(24*time.Hour) {
		return nil, errNotBittorrent
	}

	return &SniffHeader{}, nil
}
