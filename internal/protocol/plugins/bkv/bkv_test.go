package bkv

import (
	"encoding/hex"
	"testing"
	"time"
)

func TestParseFrameHeartbeat(t *testing.T) {
	payload := []Field{
		newFieldUint16(0x01, 0x1001),
		newFieldBytes(0x02, []byte{0, 0, 0, 0, 0, 0, 0, 0}),
		newFieldBytes(0x03, []byte{0x61, 0x00, 0x62, 0x90, 0x00, 0x01}),
		newFieldBytes(0x04, []byte("GV.4r44")),
		{Key: 0x05, Type: 0x01, Value: []byte{0x1a}},
		newFieldBytes(0x48, []byte("893860416141871899109")),
	}

	data, err := buildFrame(false, payload)
	if err != nil {
		t.Fatalf("buildFrame: %v", err)
	}

	frame, err := ParseFrame(data)
	if err != nil {
		t.Fatalf("ParseFrame failed: %v", err)
	}
	if !frame.IsUplink {
		t.Fatalf("expected uplink frame")
	}

	mac, ok := frame.First(0x03)
	if !ok {
		t.Fatalf("missing mac field")
	}
	if got := normalizeHex(mac.Value); got != "610062900001" {
		t.Fatalf("unexpected mac: %s", got)
	}
}

func TestMessageBuilderStatus(t *testing.T) {
	rawHex := "fcfe00f804010110020a010200000000000000000801036100629000010301072023011c030108000301098004010a000004010b000004010c000504010d000004010e000023011d030108010301098004010a000004010b000004010c000304010d000004010e0000230149030108020301098004010a000004010b000104010c000304010d000004010e000023014a030108030301098004010a000004010b000104010c000304010d000004010e000023014b030108040301098004010a000004010b000004010c000304010d000004010e000023014c030108050301098004010a000004010b000104010c000304010d000004010e00009dfcee"
	data, _ := hex.DecodeString(rawHex)
	frame, err := ParseFrame(data)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	builder, err := newMessageBuilder(frame)
	if err != nil {
		t.Fatalf("newMessageBuilder: %v", err)
	}
	msg, err := builder.build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if msg.MessageType != "status" {
		t.Fatalf("unexpected message type: %s", msg.MessageType)
	}
	plugs, ok := msg.Data["plugs"].([]map[string]interface{})
	if !ok || len(plugs) == 0 {
		t.Fatalf("plugs not parsed")
	}
	if plugs[0]["plug_num"].(int) != 0 {
		t.Fatalf("first plug num unexpected: %v", plugs[0]["plug_num"])
	}
}

func TestAckEncoding(t *testing.T) {
	plug := byte(1)
	now := time.Date(2024, 8, 26, 20, 14, 37, 0, time.Local)
	params := &AckParams{
		Cmd:       0x1001,
		RequestID: []byte{0, 0, 0, 0, 0, 0, 0, 0},
		DeviceMac: []byte{0x61, 0x00, 0x62, 0x90, 0x00, 0x01},
		PlugNum:   &plug,
		ReplyTime: &now,
	}

	frame, err := buildAckFrame(params)
	if err != nil {
		t.Fatalf("buildAckFrame: %v", err)
	}

	parsed, err := ParseFrame(frame)
	if err != nil {
		t.Fatalf("ParseFrame round-trip: %v", err)
	}
	if parsed.IsUplink {
		t.Fatalf("ack should be downlink so IsUplink=false")
	}
	plugField, ok := parsed.First(0x08)
	if !ok || len(plugField.Value) != 1 || plugField.Value[0] != plug {
		t.Fatalf("plug field mismatch: %v", plugField.Value)
	}
}

func TestChecksumValidation(t *testing.T) {
	raw := []byte{0xfc, 0xfe, 0x00, 0x07, 0x01, 0x01, 0x10, 0x01, 0x0f, 0x00, 0xfc, 0xee}
	if _, err := ParseFrame(raw); err == nil {
		t.Fatalf("expected checksum error")
	}
}

func TestParsePlugSupportsUint32Values(t *testing.T) {
	plugPayload := []byte{
		0x03, 0x01, 0x08, 0x00, // plug num
		0x03, 0x01, 0x09, 0x80, // status
		0x06, 0x01, 0x0b, 0x00, 0x0f, 0x42, 0x40, // power 0x000f4240
		0x06, 0x01, 0x0c, 0x00, 0x00, 0x27, 0x10, // current 0x2710
		0x06, 0x01, 0x0d, 0x00, 0x00, 0x00, 0x64, // electricity 0x64
		0x04, 0x01, 0x0e, 0x03, 0xe8, // charged minutes 1000
		0x04, 0x01, 0x55, 0x01, 0xf4, // voltage 500
	}

	fields := []Field{
		newFieldUint16(0x01, 0x1002),
		newFieldBytes(0x02, []byte{0, 0, 0, 0, 0, 0, 0, 0}),
		newFieldBytes(0x03, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}),
		{Key: 0x1c, Type: 0x03, Value: plugPayload},
	}

	frameBytes, err := buildFrame(false, fields)
	if err != nil {
		t.Fatalf("buildFrame: %v", err)
	}

	frame, err := ParseFrame(frameBytes)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}

	builder, err := newMessageBuilder(frame)
	if err != nil {
		t.Fatalf("newMessageBuilder: %v", err)
	}

	msg, err := builder.build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	plugs, ok := msg.Data["plugs"].([]map[string]interface{})
	if !ok || len(plugs) != 1 {
		t.Fatalf("unexpected plugs parsed: %#v", msg.Data["plugs"])
	}

	plug := plugs[0]
	if plug["power_0_1w"].(uint32) != 0x000f4240 {
		t.Fatalf("power parse failed: %v", plug["power_0_1w"])
	}
	if plug["current_ma"].(uint32) != 0x2710 {
		t.Fatalf("current parse failed: %v", plug["current_ma"])
	}
	if plug["electricity_wh"].(uint32) != 0x64 {
		t.Fatalf("electricity parse failed: %v", plug["electricity_wh"])
	}
}

func TestThresholdQueryParsing(t *testing.T) {
	fields := []Field{
		newFieldUint16(0x01, 0x1006),
		newFieldBytes(0x02, []byte{0, 0, 0, 0, 0, 0, 0, 1}),
		newFieldBytes(0x03, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02}),
		{Key: 0x08, Type: 0x01, Value: []byte{0x02}},
		newFieldUint16(0x10, 0x1388),
		newFieldUint16(0x11, 0x03e8),
		newFieldUint16(0x14, 0x00c8),
		newFieldUint16(0x15, 0x0100),
	}

	frameBytes, err := buildFrame(false, fields)
	if err != nil {
		t.Fatalf("buildFrame: %v", err)
	}

	frame, err := ParseFrame(frameBytes)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}

	msg, err := newMessageBuilder(frame)
	if err != nil {
		t.Fatalf("newMessageBuilder: %v", err)
	}

	res, err := msg.build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	if res.MessageType != "threshold_query_response" {
		t.Fatalf("unexpected message type: %s", res.MessageType)
	}
	if res.Data["plug_num"].(int) != 2 {
		t.Fatalf("plug_num parse failed: %v", res.Data["plug_num"])
	}
	if res.Data["overcurrent_ma3"].(uint32) != 0x1388 {
		t.Fatalf("overcurrent parse failed: %v", res.Data["overcurrent_ma3"])
	}
	if res.Data["power_limit_0_1w"].(uint32) != 0x03e8 {
		t.Fatalf("power limit parse failed: %v", res.Data["power_limit_0_1w"])
	}
}

func TestQuietTimeParsing(t *testing.T) {
	fields := []Field{
		newFieldUint16(0x01, 0x1011),
		newFieldBytes(0x02, []byte{0, 0, 0, 0, 0, 0, 0, 2}),
		newFieldBytes(0x03, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x03}),
		{Key: 0x50, Type: 0x01, Value: []byte{0x01}},
		{Key: 0x51, Type: 0x01, Value: []byte{0x02}},
		{Key: 0x52, Type: 0x01, Value: []byte{0x07, 0x00, 0x0a, 0x00}},
		{Key: 0x0f, Type: 0x01, Value: []byte{0x01}},
	}

	frameBytes, err := buildFrame(false, fields)
	if err != nil {
		t.Fatalf("buildFrame: %v", err)
	}

	frame, err := ParseFrame(frameBytes)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}

	msg, err := newMessageBuilder(frame)
	if err != nil {
		t.Fatalf("newMessageBuilder: %v", err)
	}

	res, err := msg.build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	if res.MessageType != "quiet_time_response" {
		t.Fatalf("message type mismatch: %s", res.MessageType)
	}
	if res.Data["ack"].(int) != 1 {
		t.Fatalf("ack parse failed: %v", res.Data["ack"])
	}
	if res.Data["quiet_time_hex"].(string) != "07000A00" {
		t.Fatalf("quiet intervals parse failed: %v", res.Data["quiet_time_hex"])
	}
}
