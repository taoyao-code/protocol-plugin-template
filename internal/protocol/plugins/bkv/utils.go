package bkv

import (
	"encoding/hex"
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

func toUint16BE(b []byte) (uint16, bool) {
	if len(b) < 2 {
		return 0, false
	}
	return uint16(b[0])<<8 | uint16(b[1]), true
}

func normalizeHex(value []byte) string {
	return strings.ToUpper(fmt.Sprintf("%x", value))
}

func parseStringInt(value []byte) (int, error) {
	return strconv.Atoi(string(value))
}
