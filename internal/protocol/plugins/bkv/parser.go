package bkv

import (
	"encoding/binary"
	"fmt"
	"time"
	"tp-plugin/internal/protocol"

	"github.com/sirupsen/logrus"
)

// messageBuilder 将Frame转换为平台标准Message。
type messageBuilder struct {
	frame   *Frame
	baseMsg *protocol.Message
}

func newMessageBuilder(frame *Frame) (*messageBuilder, error) {
	cmdField, ok := frame.First(0x01)
	if !ok || len(cmdField.Value) < 2 {
		return nil, fmt.Errorf("缺少CMD字段")
	}
	cmd := binary.BigEndian.Uint16(cmdField.Value[:2])

	macField, ok := frame.First(0x03)
	if !ok || len(macField.Value) == 0 {
		return nil, fmt.Errorf("缺少设备MAC字段")
	}
	deviceNumber := normalizeHex(macField.Value)

	base := &protocol.Message{
		DeviceNumber: deviceNumber,
		MessageType:  "data",
		Timestamp:    time.Now(),
		Data:         map[string]interface{}{"cmd": fmt.Sprintf("0x%04x", cmd), "raw_hex": normalizeHex(frame.Raw)},
		Quality:      1,
	}

	if req, ok := frame.First(0x02); ok {
		base.Data["request_id"] = normalizeHex(req.Value)
	}
	if version, ok := frame.First(0x04); ok {
		base.Data["version"] = string(version.Value)
	}
	if csq, ok := frame.First(0x05); ok && len(csq.Value) > 0 {
		base.Data["csq"] = int(csq.Value[0])
	}
	if iccid, ok := frame.First(0x48); ok {
		base.Data["iccid"] = string(iccid.Value)
	}

	return &messageBuilder{frame: frame, baseMsg: base}, nil
}

func (b *messageBuilder) build() (*protocol.Message, error) {
	cmd := b.baseMsg.Data["cmd"].(string)
	switch cmd {
	case "0x1001":
		b.baseMsg.MessageType = "heartbeat"
		b.appendHeartbeat()
	case "0x1002":
		b.baseMsg.MessageType = "status"
		b.appendStatus()
	case "0x1003":
		b.baseMsg.MessageType = "status_query"
		b.appendStatus()
	case "0x1004":
		b.baseMsg.MessageType = "charge_end"
		b.appendChargeEnd()
	case "0x1009":
		b.baseMsg.MessageType = "nfc_start"
		b.appendNFCStart()
	case "0x100a":
		b.baseMsg.MessageType = "nfc_end"
		b.appendNFCEnd()
	case "0x1005":
		b.baseMsg.MessageType = "threshold_set_response"
		b.appendThresholdConfig()
	case "0x1006":
		b.baseMsg.MessageType = "threshold_query_response"
		b.appendThresholdConfig()
	case "0x100c":
		b.baseMsg.MessageType = "param_response"
		b.appendParamResponse()
	case "0x1008":
		b.baseMsg.MessageType = "ota_response"
		b.appendAckOnly()
	case "0x1007":
		b.baseMsg.MessageType = "control_response"
		b.appendControlResponse()
	case "0x100b":
		b.baseMsg.MessageType = "system_param_set_response"
		b.appendAckOnly()
	case "0x100d":
		b.baseMsg.MessageType = "reboot_response"
		b.appendAckOnly()
	case "0x1010":
		b.baseMsg.MessageType = "nfc_balance_response"
		b.appendNFCBalance()
	case "0x1011":
		b.baseMsg.MessageType = "quiet_time_response"
		b.appendQuietTime()
	case "0x1014":
		b.baseMsg.MessageType = "qr_update_response"
		b.appendAckOnly()
	case "0x1013":
		b.baseMsg.MessageType = "event"
		b.appendEvent()
	default:
		logrus.WithField("cmd", cmd).Debug("未识别的命令，保持通用解析")
	}
	return b.baseMsg, nil
}

func (b *messageBuilder) appendHeartbeat() {
	if t, ok := b.frame.First(0x06); ok {
		if ts, err := parseBCDDateTime(t.Value); err == nil {
			b.baseMsg.Data["device_time"] = ts.Format(timeLayout)
		}
	}
}

func (b *messageBuilder) appendStatus() {
	if temp, ok := b.frame.First(0x07); ok && len(temp.Value) > 0 {
		b.baseMsg.Data["mcu_temp"] = int(temp.Value[0])
	}
	if coin, ok := b.frame.First(0x5d); ok {
		if val, ok := toUintBE(coin.Value); ok {
			b.baseMsg.Data["coin_count"] = val
		}
	}
	if totalCoin, ok := b.frame.First(0x8a); ok {
		if val, ok := toUintBE(totalCoin.Value); ok {
			b.baseMsg.Data["coin_sum"] = val
		}
	}
	plugs := extractPlugInfos(b.frame)
	if len(plugs) > 0 {
		b.baseMsg.Data["plugs"] = plugs
	}
}

func (b *messageBuilder) appendChargeEnd() {
	appendCommonCharge(b.baseMsg, b.frame)
	if reason, ok := pickupFinishReason(b.frame); ok {
		b.baseMsg.Data["finish_reason"] = reason
	}
	if electricCash, ok := b.frame.First(0x85); ok {
		if val, ok := toUintBE(electricCash.Value); ok {
			b.baseMsg.Data["electric_cash_cent"] = val
		}
	}
	if electricCashHA, ok := firstAny(b.frame, 0x0193, 0x93); ok {
		if val, ok := toUintBE(electricCashHA.Value); ok {
			b.baseMsg.Data["electric_cash_micro"] = val
		}
	}
	if serviceCash, ok := b.frame.First(0x86); ok {
		if val, ok := toUintBE(serviceCash.Value); ok {
			b.baseMsg.Data["service_cash_cent"] = val
		}
	}
	if serviceCashHA, ok := firstAny(b.frame, 0x0194, 0x94); ok {
		if val, ok := toUintBE(serviceCashHA.Value); ok {
			b.baseMsg.Data["service_cash_micro"] = val
		}
	}
	if serviceUsedCash, ok := b.frame.First(0x87); ok {
		if val, ok := toUintBE(serviceUsedCash.Value); ok {
			b.baseMsg.Data["service_cash_used_cent"] = val
		}
	}
	if segments, ok := b.frame.First(0x84); ok {
		b.baseMsg.Data["service_segments_hex"] = normalizeHex(segments.Value)
	}
}

func (b *messageBuilder) appendNFCStart() {
	appendCommonCharge(b.baseMsg, b.frame)
	if card, ok := b.frame.First(0x16); ok {
		b.baseMsg.Data["nfc_id"] = normalizeHex(card.Value)
	}
	if cardType, ok := b.frame.First(0x26); ok && len(cardType.Value) > 0 {
		b.baseMsg.Data["nfc_type"] = int(cardType.Value[0])
	}
	if mode, ok := b.frame.First(0x27); ok && len(mode.Value) > 0 {
		b.baseMsg.Data["card_mode"] = int(mode.Value[0])
	}
	if payMode, ok := b.frame.First(0x17); ok {
		if pay, err := parseStringInt(payMode.Value); err == nil {
			b.baseMsg.Data["nfc_pay_mode"] = pay
		}
	}
	if cash, ok := b.frame.First(0x18); ok {
		if val, ok := toUintBE(cash.Value); ok {
			b.baseMsg.Data["nfc_cash_cent"] = val
		}
	}
	if timePrice, ok := b.frame.First(0x28); ok {
		b.baseMsg.Data["nfc_time_price"] = normalizeHex(timePrice.Value)
	}
	if energyPrice, ok := b.frame.First(0x29); ok {
		b.baseMsg.Data["nfc_energy_price"] = normalizeHex(energyPrice.Value)
	}
	if powerPrice, ok := b.frame.First(0x2a); ok {
		b.baseMsg.Data["nfc_power_price"] = normalizeHex(powerPrice.Value)
	}
}

func (b *messageBuilder) appendNFCEnd() {
	appendCommonCharge(b.baseMsg, b.frame)
	if card, ok := b.frame.First(0x16); ok {
		b.baseMsg.Data["nfc_id"] = normalizeHex(card.Value)
	}
	if cardType, ok := b.frame.First(0x26); ok && len(cardType.Value) > 0 {
		b.baseMsg.Data["nfc_type"] = int(cardType.Value[0])
	}
	if mode, ok := b.frame.First(0x27); ok && len(mode.Value) > 0 {
		b.baseMsg.Data["card_mode"] = int(mode.Value[0])
	}
	if reason, ok := pickupFinishReason(b.frame); ok {
		b.baseMsg.Data["finish_reason"] = reason
	}
}

func (b *messageBuilder) appendParamResponse() {
	keys := map[uint16]string{
		0x1e: "report_cycle_min",
		0x20: "heartbeat_sec",
		0x21: "full_charge_delay_sec",
		0x22: "no_load_delay_sec",
		0x23: "full_power_thresh_0_1w",
		0x24: "no_load_power_thresh_0_1w",
		0x25: "temp_threshold_c",
		0x59: "max_charge_time_min",
		0x60: "trickle_threshold_pct",
		0x10: "overcurrent_ma3",
		0x11: "power_limit_0_1w",
		0x68: "single_amount",
	}
	for key, name := range keys {
		if f, ok := b.frame.First(key); ok {
			if val, ok := toUintBE(f.Value); ok {
				b.baseMsg.Data[name] = val
			}
		}
	}
	if ack, ok := b.frame.First(0x0f); ok && len(ack.Value) > 0 {
		b.baseMsg.Data["ack"] = int(ack.Value[0])
	}
}

func (b *messageBuilder) appendThresholdConfig() {
	if plug, ok := b.frame.First(0x08); ok && len(plug.Value) > 0 {
		b.baseMsg.Data["plug_num"] = int(plug.Value[0])
	}
	fields := map[uint16]string{
		0x10: "overcurrent_ma3",
		0x11: "power_limit_0_1w",
		0x14: "set_charge_time_min",
		0x15: "set_charge_energy_wh",
		0x12: "charge_mode",
	}
	for key, name := range fields {
		if f, ok := b.frame.First(key); ok {
			if val, ok := toUintBE(f.Value); ok {
				b.baseMsg.Data[name] = val
			}
		}
	}
	if ack, ok := b.frame.First(0x0f); ok && len(ack.Value) > 0 {
		b.baseMsg.Data["ack"] = int(ack.Value[0])
	}
}

func (b *messageBuilder) appendAckOnly() {
	if ack, ok := b.frame.First(0x0f); ok && len(ack.Value) > 0 {
		b.baseMsg.Data["ack"] = int(ack.Value[0])
	}
}

func (b *messageBuilder) appendControlResponse() {
	if plug, ok := b.frame.First(0x08); ok && len(plug.Value) > 0 {
		b.baseMsg.Data["plug_num"] = int(plug.Value[0])
	}
	if order, ok := b.frame.First(0x0a); ok {
		if val, ok := toUintBE(order.Value); ok {
			b.baseMsg.Data["order"] = val
		}
	}
	if code, ok := b.frame.First(0x97); ok && len(code.Value) > 0 {
		b.baseMsg.Data["control_error_code"] = int(code.Value[0])
	}
	b.appendAckOnly()
}

func (b *messageBuilder) appendNFCBalance() {
	if card, ok := b.frame.First(0x16); ok {
		b.baseMsg.Data["nfc_id"] = normalizeHex(card.Value)
	}
	if balance, ok := b.frame.First(0x18); ok {
		if val, ok := toUintBE(balance.Value); ok {
			b.baseMsg.Data["nfc_cash_cent"] = val
		}
	}
	if plug, ok := b.frame.First(0x08); ok && len(plug.Value) > 0 {
		b.baseMsg.Data["plug_num"] = int(plug.Value[0])
	}
	b.appendAckOnly()
}

func (b *messageBuilder) appendQuietTime() {
	if switchField, ok := b.frame.First(0x50); ok && len(switchField.Value) > 0 {
		b.baseMsg.Data["speech_switch"] = int(switchField.Value[0])
	}
	if numField, ok := b.frame.First(0x51); ok && len(numField.Value) > 0 {
		b.baseMsg.Data["quiet_time_num"] = int(numField.Value[0])
	}
	if intervals, ok := b.frame.First(0x52); ok {
		b.baseMsg.Data["quiet_time_hex"] = normalizeHex(intervals.Value)
	}
	b.appendAckOnly()
}

func (b *messageBuilder) appendEvent() {
	if plug, ok := b.frame.First(0x08); ok && len(plug.Value) > 0 {
		b.baseMsg.Data["plug_num"] = int(plug.Value[0])
	}
	if t, ok := b.frame.First(0x06); ok {
		if ts, err := parseBCDDateTime(t.Value); err == nil {
			b.baseMsg.Data["event_time"] = ts.Format(timeLayout)
		}
	}
	if event, ok := b.frame.First(0x5a); ok {
		b.baseMsg.Data["event_code"] = normalizeHex(event.Value)
	}
	if voltage, ok := b.frame.First(0x55); ok {
		if val, ok := toUintBE(voltage.Value); ok {
			b.baseMsg.Data["voltage_0_1v"] = val
		}
	}
	if order, ok := b.frame.First(0xda); ok {
		b.baseMsg.Data["order_id"] = string(order.Value)
	}
}

func appendCommonCharge(msg *protocol.Message, frame *Frame) {
	fields := map[string]uint16{
		"plug_num":               0x08,
		"plug_status":            0x09,
		"order":                  0x0a,
		"power_0_1w":             0x0b,
		"current_ma":             0x0c,
		"electricity_wh":         0x0d,
		"charged_minutes":        0x0e,
		"charge_mode":            0x12,
		"finish_time_bcd":        0x2e,
		"used_cash":              0x30,
		"settle_power_0_1w":      0x31,
		"segment_minutes_hex":    0x32,
		"order_id":               0xda,
		"service_cash_used_cent": 0x87,
		"service_charge_num":     0x89,
	}
	for name, key := range fields {
		if f, ok := frame.First(key); ok {
			switch name {
			case "finish_time_bcd":
				if ts, err := parseBCDDateTime(f.Value); err == nil {
					msg.Data["finish_time"] = ts.Format(timeLayout)
				} else {
					msg.Data[name] = normalizeHex(f.Value)
				}
			case "segment_minutes_hex":
				msg.Data[name] = normalizeHex(f.Value)
			case "order_id":
				msg.Data[name] = string(f.Value)
			default:
				if val, ok := toUintBE(f.Value); ok {
					msg.Data[name] = val
				}
			}
		}
	}
	if temp, ok := frame.First(0x07); ok && len(temp.Value) > 0 {
		msg.Data["mcu_temp"] = int(temp.Value[0])
	}
}

func extractPlugInfos(frame *Frame) []map[string]interface{} {
	plugs := make([]map[string]interface{}, 0)
	plugKeys := []uint16{0x1c, 0x1d, 0x49, 0x4a, 0x4b, 0x4c, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0xa6, 0xa7, 0xa8, 0xaa, 0xab, 0xac, 0xad, 0xae}
	for _, key := range plugKeys {
		if plugField, ok := frame.First(key); ok {
			info := parsePlug(plugField.Value)
			if len(info) > 0 {
				plugs = append(plugs, info)
			}
		}
	}
	return plugs
}

func parsePlug(data []byte) map[string]interface{} {
	fields, err := parseFields(data)
	if err != nil {
		logrus.WithError(err).Warn("解析插孔信息失败")
		return nil
	}
	idx := make(map[uint16]Field)
	for _, f := range fields {
		idx[f.Key] = f
	}

	plug := make(map[string]interface{})
	if f, ok := idx[0x08]; ok && len(f.Value) > 0 {
		plug["plug_num"] = int(f.Value[0])
	}
	if f, ok := idx[0x09]; ok && len(f.Value) > 0 {
		plug["status"] = int(f.Value[0])
	}
	if f, ok := idx[0x0a]; ok {
		if val, ok := toUintBE(f.Value); ok {
			plug["order"] = val
		}
	}
	if f, ok := idx[0x0b]; ok {
		if val, ok := toUintBE(f.Value); ok {
			plug["power_0_1w"] = val
		}
	}
	if f, ok := idx[0x0c]; ok {
		if val, ok := toUintBE(f.Value); ok {
			plug["current_ma"] = val
		}
	}
	if f, ok := idx[0x0d]; ok {
		if val, ok := toUintBE(f.Value); ok {
			plug["electricity_wh"] = val
		}
	}
	if f, ok := idx[0x0e]; ok {
		if val, ok := toUintBE(f.Value); ok {
			plug["charged_minutes"] = val
		}
	}
	if f, ok := idx[0x55]; ok {
		if val, ok := toUintBE(f.Value); ok {
			plug["voltage_0_1v"] = val
		}
	}
	if f, ok := idx[0xe3]; ok {
		plug["plug_error_hex"] = normalizeHex(f.Value)
	}

	return plug
}

func pickupFinishReason(frame *Frame) (int, bool) {
	if reason, ok := frame.First(0x2f); ok && len(reason.Value) > 0 {
		return int(reason.Value[0]), true
	}
	if reason, ok := frame.First(0x78); ok && len(reason.Value) > 0 {
		return int(reason.Value[0]), true
	}
	return 0, false
}

func firstAny(frame *Frame, keys ...uint16) (Field, bool) {
	for _, key := range keys {
		if f, ok := frame.First(key); ok {
			return f, true
		}
	}
	return Field{}, false
}

const timeLayout = "2006-01-02 15:04:05"
