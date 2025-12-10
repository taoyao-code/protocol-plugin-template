package bkv

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	frameHeaderUp   = 0xfcfe
	frameHeaderDown = 0xfcff
	frameTail       = 0xfcee
)

// Field 代表一个BKV字段
// length(1byte) + type(1byte) + key(1byte) + value(N)
// 长度字段包含type和key的2个字节。
type Field struct {
	Key   uint16
	Type  byte
	Value []byte
}

// Frame 表示一个完整的BKV帧
// 仅关注BKV负载和核心公共字段，保留原始数据用于调试。
type Frame struct {
	Raw        []byte
	Payload    []byte
	Fields     []Field
	fieldIndex map[uint16][]Field
	IsUplink   bool
}

// ParseFrame 校验帧头、帧长、校验和，并解析BKV字段。
func ParseFrame(data []byte) (*Frame, error) {
	if len(data) < 9 {
		return nil, errors.New("数据长度过短")
	}

	header := binary.BigEndian.Uint16(data[:2])
	if header != frameHeaderUp && header != frameHeaderDown {
		return nil, fmt.Errorf("无效帧头: 0x%04x", header)
	}

	declaredLen := int(binary.BigEndian.Uint16(data[2:4]))
	actualLen := len(data) - 4 // 长度不含帧头与帧尾
	if declaredLen != actualLen {
		return nil, fmt.Errorf("帧长不匹配，声明:%d 实际:%d", declaredLen, actualLen)
	}

	// payload范围: [4, len-3)，之后1字节校验和 + 2字节帧尾
	checksumIdx := len(data) - 3
	payload := data[4:checksumIdx]

	if err := validateChecksum(data[2:checksumIdx], data[checksumIdx]); err != nil {
		return nil, err
	}

	if binary.BigEndian.Uint16(data[len(data)-2:]) != frameTail {
		return nil, fmt.Errorf("无效帧尾: 0x%04x", binary.BigEndian.Uint16(data[len(data)-2:]))
	}

	fields, err := parseFields(payload)
	if err != nil {
		return nil, err
	}

	idx := make(map[uint16][]Field)
	for _, f := range fields {
		idx[f.Key] = append(idx[f.Key], f)
	}

	return &Frame{
		Raw:        data,
		Payload:    payload,
		Fields:     fields,
		fieldIndex: idx,
		IsUplink:   header == frameHeaderUp,
	}, nil
}

func (f *Frame) First(key uint16) (Field, bool) {
	list, ok := f.fieldIndex[key]
	if !ok || len(list) == 0 {
		return Field{}, false
	}
	return list[0], true
}

func parseFields(payload []byte) ([]Field, error) {
	fields := make([]Field, 0)
	idx := 0
	for idx < len(payload) {
		length := int(payload[idx])
		idx++
		if length < 2 {
			return nil, fmt.Errorf("字段长度非法: %d", length)
		}
		if idx+length > len(payload) {
			return nil, errors.New("字段长度溢出")
		}

		block := payload[idx : idx+length]
		idx += length

		field := Field{
			Type:  block[0],
			Key:   uint16(block[1]),
			Value: block[2:],
		}
		fields = append(fields, field)
	}
	return fields, nil
}

func buildFrame(isDownlink bool, fields []Field) ([]byte, error) {
	payload := make([]byte, 0)
	for _, f := range fields {
		if len(f.Value)+2 > 0xFF {
			return nil, fmt.Errorf("字段0x%02x长度超限", f.Key)
		}
		payload = append(payload, byte(len(f.Value)+2))
		payload = append(payload, f.Type)
		payload = append(payload, byte(f.Key&0xFF))
		payload = append(payload, f.Value...)
	}

	length := len(payload) + 3 // 帧长字段包含: payload + 校验(1) + 帧尾(2)
	buf := make([]byte, 0, length+2)

	if isDownlink {
		buf = append(buf, 0xfc, 0xff)
	} else {
		buf = append(buf, 0xfc, 0xfe)
	}

	buf = binary.BigEndian.AppendUint16(buf, uint16(length))
	buf = append(buf, payload...)

	checksum := calcChecksum(buf[2:])
	buf = append(buf, checksum)
	buf = append(buf, 0xfc, 0xee)

	return buf, nil
}

func validateChecksum(payloadWithLength []byte, checksum byte) error {
	if calcChecksum(payloadWithLength) != checksum {
		return fmt.Errorf("校验和错误，期望:0x%02x 实际:0x%02x", checksum, calcChecksum(payloadWithLength))
	}
	return nil
}

func calcChecksum(payloadWithLength []byte) byte {
	var sum uint16
	for _, b := range payloadWithLength {
		sum += uint16(b)
	}
	return byte(sum & 0xFF)
}

// newFieldUint16 创建Uint16值字段，默认type=0x01
func newFieldUint16(key uint16, value uint16) Field {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, value)
	return Field{Key: key, Type: 0x01, Value: buf}
}

func newFieldBytes(key uint16, value []byte) Field {
	return Field{Key: key, Type: 0x01, Value: value}
}
