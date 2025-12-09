package bkv

import (
	"fmt"
	"tp-plugin/internal/protocol"

	"github.com/sirupsen/logrus"
)

// Handler 处理BKV协议设备报文
// 帧格式: [2字节帧头][2字节长度][BKV负载][1字节校验和][2字节帧尾]
// BKV负载由若干TLV组成，每个字段格式为[length][type][key][value...]
// 本实现覆盖心跳、状态、充电/NFC流程、事件及参数查询等核心流程。
type Handler struct {
	port   int
	logger *logrus.Entry
}

// NewHandler 创建BKV协议处理器
func NewHandler(port int) *Handler {
	return &Handler{port: port, logger: logrus.WithField("protocol", "bkv")}
}

func (h *Handler) Name() string    { return "BKV" }
func (h *Handler) Version() string { return "1.1.0" }
func (h *Handler) Port() int       { return h.port }

func (h *Handler) Start() error {
	h.logger.Infof("BKV协议启动，端口: %d", h.port)
	return nil
}

func (h *Handler) Stop() error {
	h.logger.Info("BKV协议停止")
	return nil
}

// ExtractDeviceNumber 从报文中提取设备编号（设备MAC）
func (h *Handler) ExtractDeviceNumber(data []byte) (string, error) {
	frame, err := ParseFrame(data)
	if err != nil {
		return "", err
	}
	mac, ok := frame.First(0x03)
	if !ok || len(mac.Value) == 0 {
		return "", fmt.Errorf("报文缺少设备MAC字段")
	}
	return normalizeHex(mac.Value), nil
}

// ParseData 解析设备数据
func (h *Handler) ParseData(data []byte) (*protocol.Message, error) {
	frame, err := ParseFrame(data)
	if err != nil {
		return nil, err
	}

	builder, err := newMessageBuilder(frame)
	if err != nil {
		return nil, err
	}
	return builder.build()
}
