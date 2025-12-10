package bkv

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// parseBCDDateTime 将7字节BCD时间解析为time.Time
// 格式: YYYYMMDDhhmmss，其中年份占2字节BCD
func parseBCDDateTime(data []byte) (time.Time, error) {
	if len(data) < 7 {
		return time.Time{}, fmt.Errorf("时间字段长度不足: %d", len(data))
	}

	nums := make([]int, 0, 7)
	for _, b := range data[:7] {
		high := int(b>>4) & 0x0F
		low := int(b & 0x0F)
		nums = append(nums, high*10+low)
	}

	year := nums[0]*100 + nums[1]
	month := time.Month(nums[2])
	day := nums[3]
	hour := nums[4]
	minute := nums[5]
	second := nums[6]

	return time.Date(year, month, day, hour, minute, second, 0, time.Local), nil
}

func hexStringToBytes(str string) ([]byte, error) {
	clean := strings.ReplaceAll(str, " ", "")
	clean = strings.TrimPrefix(clean, "0x")
	clean = strings.TrimPrefix(clean, "0X")
	if len(clean)%2 != 0 {
		clean = "0" + clean
	}
	return hex.DecodeString(clean)
}

func decodeBCDToString(data []byte) string {
	sb := strings.Builder{}
	for _, b := range data {
		sb.WriteString(fmt.Sprintf("%d%d", (b>>4)&0x0F, b&0x0F))
	}
	return strings.TrimLeft(sb.String(), "0")
}

func encodeBCDFromTime(t time.Time) []byte {
	parts := []int{
		t.Year() / 100,
		t.Year() % 100,
		int(t.Month()),
		t.Day(),
		t.Hour(),
		t.Minute(),
		t.Second(),
	}
	buf := make([]byte, 7)
	for i, v := range parts {
		high := byte(v/10) & 0x0F
		low := byte(v%10) & 0x0F
		buf[i] = high<<4 | low
	}
	return buf
}

// toUintBE 支持2字节或4字节的大端数值解析，覆盖两轮与四轮充电桩的字段规格。
func toUintBE(b []byte) (uint32, bool) {
	switch len(b) {
	case 2:
		return uint32(binary.BigEndian.Uint16(b)), true
	case 4:
		return binary.BigEndian.Uint32(b), true
	default:
		return 0, false
	}
}

func normalizeHex(value []byte) string {
	return strings.ToUpper(fmt.Sprintf("%x", value))
}

func parseStringInt(value []byte) (int, error) {
	return strconv.Atoi(string(value))
}

// parseFlexibleTime 支持常见的时间字符串格式：RFC3339、"2006-01-02 15:04:05"、"20060102150405"。
func parseFlexibleTime(str string) (time.Time, error) {
	clean := strings.TrimSpace(str)
	if t, err := time.Parse(time.RFC3339, clean); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02 15:04:05", clean); err == nil {
		return t, nil
	}
	if t, err := time.Parse("20060102150405", clean); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("无法解析时间格式: %s", str)
}

// normalizeExtraFields 接收 map 格式的额外字段并转换为标准 uint16->[]byte 的映射。
// 支持的输入类型：
// map[uint16][]byte、map[string][]byte、map[string]string、map[string]interface{}
func normalizeExtraFields(raw interface{}) (map[uint16][]byte, error) {
	result := make(map[uint16][]byte)
	switch extras := raw.(type) {
	case map[uint16][]byte:
		for k, v := range extras {
			result[k] = v
		}
	case map[string][]byte:
		for k, v := range extras {
			key, err := parseKeyString(k)
			if err != nil {
				return nil, err
			}
			result[key] = v
		}
	case map[string]string:
		for k, v := range extras {
			key, err := parseKeyString(k)
			if err != nil {
				return nil, err
			}
			bytes, err := hexStringToBytes(v)
			if err != nil {
				return nil, fmt.Errorf("extra_fields[%s]解析失败: %w", k, err)
			}
			result[key] = bytes
		}
	case map[string]interface{}:
		for k, v := range extras {
			key, err := parseKeyString(k)
			if err != nil {
				return nil, err
			}
			switch val := v.(type) {
			case []byte:
				result[key] = val
			case string:
				bytes, err := hexStringToBytes(val)
				if err != nil {
					return nil, fmt.Errorf("extra_fields[%s]解析失败: %w", k, err)
				}
				result[key] = bytes
			case int:
				result[key] = []byte{byte(val)}
			case uint8:
				result[key] = []byte{byte(val)}
			default:
				return nil, fmt.Errorf("extra_fields[%s]类型不支持", k)
			}
		}
	default:
		return nil, errors.New("extra_fields必须为map类型")
	}
	return result, nil
}

func parseKeyString(k string) (uint16, error) {
	clean := strings.TrimSpace(k)
	clean = strings.TrimPrefix(clean, "0x")
	clean = strings.TrimPrefix(clean, "0X")
	val, err := strconv.ParseUint(clean, 16, 16)
	if err != nil {
		return 0, fmt.Errorf("无法解析extra_fields key: %s", k)
	}
	return uint16(val), nil
}
