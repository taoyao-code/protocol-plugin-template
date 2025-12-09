package bkv

import (
	"errors"
	"fmt"
	"time"
	"tp-plugin/internal/protocol"
)

// EncodeCommand 支持两类操作：
// 1. action="raw"    : Parameters为16进制字符串，直接下发
// 2. action="ack"    : Parameters为AckParams结构体或map，按协议组帧
func (h *Handler) EncodeCommand(cmd *protocol.Command) ([]byte, error) {
	switch cmd.Action {
	case "raw":
		hexStr, ok := cmd.Parameters.(string)
		if !ok {
			return nil, errors.New("raw指令参数必须为16进制字符串")
		}
		return hexStringToBytes(hexStr)
	case "ack":
		params, err := parseAckParams(cmd.Parameters)
		if err != nil {
			return nil, err
		}
		return buildAckFrame(params)
	default:
		return nil, fmt.Errorf("不支持的指令类型: %s", cmd.Action)
	}
}

// AckParams 用于构建平台下发的应答帧
// - Cmd: 必填，目标命令号，如0x1001
// - RequestID: 必填，对应上行帧的Request_ID(8字节)
// - DeviceMac: 必填，设备MAC(6字节)
// - PlugNum: 可选，针对插孔相关命令
// - Ack: 可选，默认1-OK
// - ReplyTime: 可选，为0x1001心跳应答设置设备时间
// - ExtraFields: 可选，额外BKV字段，key为uint16
type AckParams struct {
	Cmd         uint16
	RequestID   []byte
	DeviceMac   []byte
	PlugNum     *byte
	Ack         byte
	ReplyTime   *time.Time
	ExtraFields map[uint16][]byte
}

func parseAckParams(v interface{}) (*AckParams, error) {
	if p, ok := v.(*AckParams); ok {
		return p, nil
	}
	params := &AckParams{Ack: 1, ExtraFields: make(map[uint16][]byte)}

	switch val := v.(type) {
	case map[string]interface{}:
		if cmdRaw, ok := val["cmd"]; ok {
			if cmdUint, ok := cmdRaw.(uint16); ok {
				params.Cmd = cmdUint
			}
		}
		if ridRaw, ok := val["request_id"]; ok {
			switch rid := ridRaw.(type) {
			case []byte:
				params.RequestID = rid
			case string:
				parsed, err := hexStringToBytes(rid)
				if err != nil {
					return nil, fmt.Errorf("request_id解析失败: %w", err)
				}
				params.RequestID = parsed
			}
		}
		if macRaw, ok := val["device_mac"]; ok {
			switch mac := macRaw.(type) {
			case []byte:
				params.DeviceMac = mac
			case string:
				parsed, err := hexStringToBytes(mac)
				if err != nil {
					return nil, fmt.Errorf("device_mac解析失败: %w", err)
				}
				params.DeviceMac = parsed
			}
		}
		if plugRaw, ok := val["plug_num"]; ok {
			switch plug := plugRaw.(type) {
			case int:
				p := byte(plug)
				params.PlugNum = &p
			case byte:
				p := plug
				params.PlugNum = &p
			}
		}
		if ackRaw, ok := val["ack"]; ok {
			switch ack := ackRaw.(type) {
			case int:
				params.Ack = byte(ack)
			case byte:
				params.Ack = ack
			}
		}
	default:
		return nil, errors.New("ack参数必须是AckParams或map[string]interface{}")
	}

	if params.Cmd == 0 {
		return nil, errors.New("cmd为必填字段")
	}
	if len(params.RequestID) != 8 {
		return nil, errors.New("request_id必须是8字节")
	}
	if len(params.DeviceMac) == 0 {
		return nil, errors.New("device_mac为必填字段")
	}
	return params, nil
}

func buildAckFrame(p *AckParams) ([]byte, error) {
	fields := []Field{
		newFieldUint16(0x01, p.Cmd),
		newFieldBytes(0x02, p.RequestID),
		newFieldBytes(0x03, p.DeviceMac),
	}
	if p.ReplyTime != nil {
		fields = append(fields, newFieldBytes(0x06, encodeBCDFromTime(*p.ReplyTime)))
	}
	if p.PlugNum != nil {
		fields = append(fields, Field{Key: 0x08, Type: 0x01, Value: []byte{*p.PlugNum}})
	}
	fields = append(fields, Field{Key: 0x0f, Type: 0x01, Value: []byte{p.Ack}})

	for k, v := range p.ExtraFields {
		fields = append(fields, newFieldBytes(k, v))
	}

	return buildFrame(true, fields)
}
