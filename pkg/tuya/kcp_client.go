package tuya

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
	"tuya-ipc-terminal/pkg/core"

	pionice "github.com/pion/ice/v4"
	"github.com/pion/rtp"
	"github.com/pion/stun/v3"
	"golang.org/x/sys/unix"
)

// TuyaKCPClient handles KCP communication over a direct UDP socket to the camera
type TuyaKCPClient struct {
	// Network
	cameraAddr string       // e.g., "192.168.1.50:42941"
	localAddr  string       // e.g., "192.168.1.10:51633"
	conn       net.Conn     // UDP connection
	aesKey     []byte       // AES-128 key for encryption
	block      cipher.Block // AES cipher block
	closed     bool
	mu         sync.Mutex
	stopChan   chan struct{}

	// KCP media-start state
	handshakeComplete bool
	handshakePackets  [][]byte
	handshakeRTO      time.Duration
	nextHandshakeSend time.Time
	lastAckTime       time.Time
	cameraPassword    string
	localKey          string
	ice               DirectICEParams
	iceControlling    bool
	iceTiebreaker     uint64
	channels          map[uint32]*kcpReceiveChannel

	// Philips video IMM timestamps are microseconds, while RTSP advertises the
	// standard 90 kHz video clock. Keep an unwrapped converter so the camera's
	// 32-bit microsecond counter can cross its roughly 71-minute rollover
	// without creating a backwards RTP timestamp.
	videoTimestampInitialized bool
	videoTimestampRaw         uint32
	videoTimestampRTP         uint32
	videoTimestampRemainder   uint64

	// Callbacks
	OnVideoData func(data []byte)
	OnAudioData func(data []byte)
	OnVideoRTP  func(packet *rtp.Packet)
	OnAudioRTP  func(packet *rtp.Packet)
	OnError     func(error)
}

// kcpReceiveChannel tracks the contiguous receive cursor and fragments for one
// KCP conv. Tuya uses conv=1 for video and conv=2 for camera audio.
type kcpReceiveChannel struct {
	nextSN    uint32
	pending   map[uint32]kcpReceivedSegment
	fragments []byte
}

type kcpReceivedSegment struct {
	frg  byte
	data []byte
}

// NewTuyaKCPClient creates a new KCP client for direct UDP communication with the camera
// cameraAddr: e.g., "192.168.1.50:42941"
// localAddr: e.g., "192.168.1.10:51633" (optional, can be "")
// aesKeyHex: hex-encoded 16-byte AES key
func NewTuyaKCPClient(cameraAddr, localAddr, aesKeyHex, cameraPassword, localKey string, iceParams DirectICEParams) (*TuyaKCPClient, error) {
	// Parse AES key from hex string
	aesKey, err := hex.DecodeString(aesKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid AES key hex: %v", err)
	}

	if len(aesKey) != 16 {
		return nil, fmt.Errorf("AES key must be 16 bytes, got %d", len(aesKey))
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	client := &TuyaKCPClient{
		cameraAddr:     cameraAddr,
		localAddr:      localAddr,
		aesKey:         aesKey,
		block:          block,
		cameraPassword: cameraPassword,
		localKey:       localKey,
		ice:            iceParams,
		// The Philips native client is the controlled ICE agent on the media
		// tuple (live capture attribute 0x8029); the camera remains controlling.
		iceControlling: false,
		channels:       make(map[uint32]*kcpReceiveChannel),
		stopChan:       make(chan struct{}),
	}

	return client, nil
}

// Start opens the UDP connection and initiates the KCP handshake
func (c *TuyaKCPClient) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return fmt.Errorf("client is closed")
	}

	// Resolve camera address
	cameraUDPAddr, err := net.ResolveUDPAddr("udp", c.cameraAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve camera address: %v", err)
	}

	var localUDPAddr *net.UDPAddr
	if c.localAddr != "" {
		localUDPAddr, err = net.ResolveUDPAddr("udp", c.localAddr)
		if err != nil {
			return fmt.Errorf("failed to resolve local address: %v", err)
		}
	}

	// The ICE agent owned the advertised local port while gathering candidates.
	// Its Close is asynchronous on some platforms, so wait briefly before taking
	// over that exact tuple for direct AES/KCP.
	var conn *net.UDPConn
	for attempt := 0; attempt < 25; attempt++ {
		conn, err = net.DialUDP("udp", localUDPAddr, cameraUDPAddr)
		if err == nil {
			break
		}
		if localUDPAddr == nil || !strings.Contains(err.Error(), "address already in use") {
			return fmt.Errorf("failed to connect to camera: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		return fmt.Errorf("failed to take over ICE-advertised UDP port: %v", err)
	}
	c.conn = conn
	c.localAddr = conn.LocalAddr().String()
	c.cameraAddr = conn.RemoteAddr().String()

	core.Logger.Info().Msgf("KCP UDP connection established: %s -> %s", c.localAddr, c.cameraAddr)
	if err := c.performConnectivityCheck(); err != nil {
		conn.Close()
		return fmt.Errorf("direct ICE connectivity check failed: %v", err)
	}

	// Start handshake
	if err := c.performHandshake(); err != nil {
		conn.Close()
		return fmt.Errorf("KCP handshake failed: %v", err)
	}

	// Start reading loop
	go c.readLoop()

	core.Logger.Info().Msg("KCP client started successfully")
	return nil
}

func (c *TuyaKCPClient) buildConnectivityCheck(txID [stun.TransactionIDSize]byte) (*stun.Message, error) {
	if c.ice.LocalUfrag == "" || c.ice.RemoteUfrag == "" || c.ice.RemotePwd == "" {
		return nil, fmt.Errorf("direct ICE credentials unavailable")
	}
	if c.iceTiebreaker == 0 {
		var tieBytes [8]byte
		if _, err := rand.Read(tieBytes[:]); err != nil {
			return nil, fmt.Errorf("generate ICE tiebreaker: %w", err)
		}
		c.iceTiebreaker = binary.BigEndian.Uint64(tieBytes[:])
	}
	role := stun.Setter(pionice.AttrControlled(c.iceTiebreaker))
	if c.iceControlling {
		role = pionice.AttrControlling(c.iceTiebreaker)
	}
	return stun.Build(
		stun.BindingRequest,
		stun.NewTransactionIDSetter(txID),
		pionice.PriorityAttr(c.ice.Priority),
		role,
		stun.NewSoftware("pion/ice"),
		stun.NewUsername(c.ice.RemoteUfrag+":"+c.ice.LocalUfrag),
		stun.NewShortTermIntegrity(c.ice.RemotePwd),
		stun.Fingerprint,
	)
}

// performConnectivityCheck validates the host candidate pair before sending
// Tuya media control. This camera uses regular/full ICE and ignores aggressive
// USE-CANDIDATE checks, so the request intentionally omits that attribute.
func (c *TuyaKCPClient) performConnectivityCheck() error {
	c.iceControlling = false
	err := c.performConnectivityCheckForRole()
	if errors.Is(err, errICERoleConflict) {
		core.Logger.Info().Msg("Direct ICE role conflict as controlled agent; retrying as controlling")
		c.iceControlling = true
		c.iceTiebreaker = ^uint64(0)
		err = c.performConnectivityCheckForRole()
	}
	return err
}

var errICERoleConflict = errors.New("ICE role conflict")

func (c *TuyaKCPClient) performConnectivityCheckForRole() error {
	txID := stun.NewTransactionID()
	request, err := c.buildConnectivityCheck(txID)
	if err != nil {
		return err
	}
	buf := make([]byte, 2048)
	outboundValidated := false
	inboundAnswered := false
	for _, rto := range []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second, 4 * time.Second} {
		if _, err := c.conn.Write(request.Raw); err != nil && !isTransientUDPError(err) {
			return fmt.Errorf("send STUN Binding request: %w", err)
		}
		deadline := time.Now().Add(rto)
		for time.Now().Before(deadline) {
			if err := c.conn.SetReadDeadline(deadline); err != nil {
				return err
			}
			n, err := c.conn.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					break
				}
				if isTransientUDPError(err) {
					break
				}
				return fmt.Errorf("read STUN response: %w", err)
			}
			if !stun.IsMessage(buf[:n]) {
				continue
			}
			message := new(stun.Message)
			if err := stun.Decode(buf[:n], message); err != nil {
				continue
			}
			if message.Type == stun.BindingSuccess && message.TransactionID == txID {
				if err := message.Check(stun.NewShortTermIntegrity(c.ice.RemotePwd), stun.Fingerprint); err != nil {
					continue
				}
				outboundValidated = true
			}
			if message.Type == stun.BindingError && message.TransactionID == txID {
				var code stun.ErrorCodeAttribute
				if err := code.GetFrom(message); err == nil && code.Code == stun.CodeRoleConflict {
					return errICERoleConflict
				}
			}
			if message.Type == stun.BindingRequest {
				if err := c.answerBindingRequest(message); err != nil {
					core.Logger.Trace().Err(err).Msg("Ignored invalid inbound ICE check")
				} else {
					inboundAnswered = true
				}
			}
			if outboundValidated && inboundAnswered {
				_ = c.conn.SetReadDeadline(time.Time{})
				core.Logger.Info().Msg("Direct bidirectional ICE connectivity validated")
				return nil
			}
		}
	}
	return fmt.Errorf("ICE validation incomplete (outbound=%t inbound=%t)", outboundValidated, inboundAnswered)
}

func isTransientUDPError(err error) bool {
	return errors.Is(err, unix.ECONNREFUSED) || errors.Is(err, unix.EHOSTUNREACH) || errors.Is(err, unix.ENETUNREACH)
}

func (c *TuyaKCPClient) answerBindingRequest(message *stun.Message) error {
	if message.Type != stun.BindingRequest {
		return nil
	}
	integrity := stun.NewShortTermIntegrity(c.ice.LocalPwd)
	if err := message.Check(integrity); err != nil {
		return fmt.Errorf("inbound ICE integrity: %w", err)
	}
	remote, ok := c.conn.RemoteAddr().(*net.UDPAddr)
	if !ok {
		return fmt.Errorf("ICE peer is not UDP")
	}
	response, err := stun.Build(
		stun.BindingSuccess,
		stun.NewTransactionIDSetter(message.TransactionID),
		&stun.XORMappedAddress{IP: remote.IP, Port: remote.Port},
		stun.NewSoftware("pion/ice"),
		integrity,
		stun.Fingerprint,
	)
	if err != nil {
		return fmt.Errorf("build ICE Binding success: %w", err)
	}
	if _, err := c.conn.Write(response.Raw); err != nil {
		return fmt.Errorf("send ICE Binding success: %w", err)
	}
	return nil
}

func (c *TuyaKCPClient) sendConsentCheck() error {
	request, err := c.buildConnectivityCheck(stun.NewTransactionID())
	if err != nil {
		return err
	}
	_, err = c.conn.Write(request.Raw)
	return err
}

// performHandshake starts Tuya's IMM media channel. Unlike ordinary KCP, the
// camera does not accept a speculative ACK/WASK probe: it requires encrypted
// conv=0 PUSH PDUs beginning with application-level authorization.
func (c *TuyaKCPClient) performHandshake() error {
	if c.cameraPassword == "" || c.localKey == "" {
		return fmt.Errorf("media-start authorization credentials unavailable")
	}

	core.Logger.Info().Msg("Starting authenticated KCP media channel")
	auth := make([]byte, 104)
	binary.LittleEndian.PutUint32(auth[0:4], 0x12345678)
	copy(auth[8:8+len("admin")], "admin")
	digest := md5.Sum([]byte(c.cameraPassword + "||" + c.localKey))
	password := hex.EncodeToString(digest[:])
	copy(auth[0x28:0x28+len(password)], password)

	version := []byte{
		0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0, 0, 0, 0, 0,
		0x0a, 0, 0, 0, 0x04, 0, 0, 0, 0, 0, 1, 0,
	}
	commands := [][]byte{
		{0x78, 0x56, 0x34, 0x12, 0x04, 0, 0x01, 0, 0, 0, 0, 0, 0x09, 0, 0, 0, 0x08, 0, 0, 0, 0, 0, 0, 0, 0x04, 0, 0, 0},
		{0x78, 0x56, 0x34, 0x12, 0x03, 0, 0x01, 0, 0, 0, 0, 0, 0x06, 0, 0, 0, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{0x78, 0x56, 0x34, 0x12, 0x05, 0, 0x01, 0, 0, 0, 0, 0, 0x06, 0, 0x04, 0, 0x08, 0, 0, 0, 0, 0, 0, 0, 0x04, 0, 0, 0},
	}
	pdus := append([][]byte{auth, version}, commands...)
	ts := monotonicMilliseconds()
	for sn, pdu := range pdus {
		packet, err := c.buildEncryptedPush(0, uint32(sn), ts, pdu)
		if err != nil {
			return fmt.Errorf("send media-start PDU %d: %w", sn, err)
		}
		if _, err := c.conn.Write(packet); err != nil {
			return fmt.Errorf("send media-start PDU %d: %w", sn, err)
		}
		c.handshakePackets = append(c.handshakePackets, packet)
	}

	c.handshakeComplete = true
	c.handshakeRTO = 500 * time.Millisecond
	c.nextHandshakeSend = time.Now().Add(c.handshakeRTO)
	c.lastAckTime = time.Now()
	core.Logger.Info().Msg("Authenticated KCP media-start sent")
	return nil
}

func (c *TuyaKCPClient) buildEncryptedPush(conv, sn, ts uint32, plaintext []byte) ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("generate CBC IV: %w", err)
	}
	padLen := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := make([]byte, len(plaintext)+padLen)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(c.block, iv).CryptBlocks(ciphertext, padded)
	return c.buildAuthenticatedPacket(conv, 0x51, 0, 512, ts, sn, 0, append(iv, ciphertext...)), nil
}

func (c *TuyaKCPClient) buildAuthenticatedPacket(conv uint32, cmd, frg byte, wnd uint16, ts, sn, una uint32, payload []byte) []byte {
	packet := make([]byte, 24+len(payload)+sha1.Size)
	binary.LittleEndian.PutUint32(packet[0:4], conv)
	packet[4] = cmd
	packet[5] = frg
	binary.LittleEndian.PutUint16(packet[6:8], wnd)
	binary.LittleEndian.PutUint32(packet[8:12], ts)
	binary.LittleEndian.PutUint32(packet[12:16], sn)
	binary.LittleEndian.PutUint32(packet[16:20], una)
	binary.LittleEndian.PutUint32(packet[20:24], uint32(len(payload)))
	copy(packet[24:], payload)
	mac := hmac.New(sha1.New, c.aesKey)
	mac.Write(packet[:24+len(payload)])
	copy(packet[24+len(payload):], mac.Sum(nil))
	return packet
}

func (c *TuyaKCPClient) writeAuthenticatedPacket(conv uint32, cmd, frg byte, wnd uint16, ts, sn, una uint32, payload []byte) error {
	packet := c.buildAuthenticatedPacket(conv, cmd, frg, wnd, ts, sn, una, payload)
	_, err := c.conn.Write(packet)
	return err
}

func (c *TuyaKCPClient) retransmitMediaStart() error {
	if len(c.handshakePackets) == 0 || time.Now().Before(c.nextHandshakeSend) {
		return nil
	}
	for _, packet := range c.handshakePackets {
		if _, err := c.conn.Write(packet); err != nil {
			return err
		}
	}
	c.nextHandshakeSend = time.Now().Add(c.handshakeRTO)
	c.handshakeRTO *= 2
	if c.handshakeRTO > 4*time.Second {
		c.handshakeRTO = 4 * time.Second
	}
	core.Logger.Debug().Msg("Retransmitted unacknowledged KCP media-start")
	return nil
}

func (c *TuyaKCPClient) validAuthenticator(packet []byte) bool {
	if len(packet) < 24+sha1.Size {
		return false
	}
	body := packet[:len(packet)-sha1.Size]
	mac := hmac.New(sha1.New, c.aesKey)
	mac.Write(body)
	return hmac.Equal(packet[len(body):], mac.Sum(nil))
}

// monotonicMilliseconds matches the native SDK's KCP timestamp epoch. KCP's
// ts field is based on CLOCK_MONOTONIC, not wall-clock Unix milliseconds.
func monotonicMilliseconds() uint32 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return uint32(time.Now().UnixMilli())
	}
	return uint32(ts.Sec*1000 + ts.Nsec/1_000_000)
}

// readLoop continuously reads from the UDP connection and processes KCP packets
func (c *TuyaKCPClient) readLoop() {
	buf := make([]byte, 65536) // Large buffer for video data

	for {
		select {
		case <-c.stopChan:
			return
		default:
		}

		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()
		// ICE consent traffic can keep Read continuously active, so drive the
		// media-start retransmit timer independently of socket timeouts.
		if err := c.retransmitMediaStart(); err != nil && !isTransientUDPError(err) {
			core.Logger.Trace().Err(err).Msg("KCP media-start retransmit failed")
		}

		// A short deadline provides a flush cadence for ICE consent freshness even
		// while the camera is between media frames.
		c.conn.SetReadDeadline(time.Now().Add(time.Second))

		n, err := c.conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				core.Logger.Info().Msg("KCP connection closed")
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if err := c.retransmitMediaStart(); err != nil && !isTransientUDPError(err) {
					core.Logger.Trace().Err(err).Msg("KCP media-start retransmit failed")
				}
				if time.Since(c.lastAckTime) >= 5*time.Second {
					if err := c.sendConsentCheck(); err != nil && !isTransientUDPError(err) {
						core.Logger.Trace().Err(err).Msg("ICE consent refresh failed")
					}
					c.lastAckTime = time.Now()
				}
				continue // Timeout, try again
			}
			core.Logger.Error().Err(err).Msg("Error reading from KCP connection")
			if c.OnError != nil {
				c.OnError(err)
			}
			return
		}

		if n > 0 {
			if stun.IsMessage(buf[:n]) {
				message := new(stun.Message)
				if err := stun.Decode(buf[:n], message); err == nil {
					if err := c.answerBindingRequest(message); err != nil {
						core.Logger.Trace().Err(err).Msg("Ignored invalid inbound ICE check")
					}
				}
				continue
			}
			c.processPacket(buf[:n])
		}
	}
}

// processPacket validates Tuya's datagram HMAC then feeds every coalesced KCP
// segment to the channel receiver. The AES-CBC layer is per segment, not per
// datagram: each PUSH payload starts with its own clear 16-byte IV.
func (c *TuyaKCPClient) processPacket(data []byte) {
	if len(data) < 24+sha1.Size || !c.validAuthenticator(data) {
		return
	}
	body := data[:len(data)-sha1.Size]
	for offset := 0; offset < len(body); {
		if len(body)-offset < 24 {
			return
		}
		segment := body[offset:]
		conv := binary.LittleEndian.Uint32(segment[0:4])
		cmd := segment[4]
		frg := segment[5]
		wnd := binary.LittleEndian.Uint16(segment[6:8])
		_ = wnd
		ts := binary.LittleEndian.Uint32(segment[8:12])
		sn := binary.LittleEndian.Uint32(segment[12:16])
		una := binary.LittleEndian.Uint32(segment[16:20])
		payloadLen := int(binary.LittleEndian.Uint32(segment[20:24]))
		if payloadLen < 0 || payloadLen > len(segment)-24 {
			return
		}
		payload := segment[24 : 24+payloadLen]
		offset += 24 + payloadLen

		switch cmd {
		case 0x51: // PUSH
			if conv == 1 || conv == 2 {
				c.handshakePackets = nil
			}
			if err := c.receivePush(conv, frg, ts, sn, payload); err != nil {
				core.Logger.Trace().Err(err).Msg("Rejected KCP PUSH")
			}
		case 0x52, 0x53, 0x54:
			if conv == 0 && una >= 5 {
				c.handshakePackets = nil
				core.Logger.Debug().Msgf("Camera acknowledged complete KCP media-start (una=%d)", una)
			}
			c.lastAckTime = time.Now()
		default:
			return
		}
	}
}

func (c *TuyaKCPClient) receivePush(conv uint32, frg byte, ts, sn uint32, encryptedPayload []byte) error {
	plaintext, err := c.decryptSegment(encryptedPayload)
	if err != nil {
		return err
	}

	c.mu.Lock()
	channel := c.channels[conv]
	if channel == nil {
		channel = &kcpReceiveChannel{pending: make(map[uint32]kcpReceivedSegment)}
		c.channels[conv] = channel
	}
	if sn >= channel.nextSN {
		if _, exists := channel.pending[sn]; !exists {
			channel.pending[sn] = kcpReceivedSegment{frg: frg, data: plaintext}
		}
	}
	var messages [][]byte
	for {
		segment, ok := channel.pending[channel.nextSN]
		if !ok {
			break
		}
		delete(channel.pending, channel.nextSN)
		channel.nextSN++
		channel.fragments = append(channel.fragments, segment.data...)
		if segment.frg == 0 {
			message := append([]byte(nil), channel.fragments...)
			channel.fragments = channel.fragments[:0]
			messages = append(messages, message)
		}
	}
	una := channel.nextSN
	c.mu.Unlock()

	// ACK every valid PUSH, including duplicates, using the cursor after any
	// newly contiguous segments have been consumed. A lost or stale ACK can
	// otherwise exhaust the camera's initial KCP send window.
	if err := c.writeAuthenticatedPacket(conv, 0x52, 0, 512, ts, sn, una, nil); err != nil {
		return fmt.Errorf("write KCP ACK: %w", err)
	}
	for _, message := range messages {
		c.handleMediaMessage(conv, message)
	}
	return nil
}

func (c *TuyaKCPClient) handleMediaMessage(conv uint32, message []byte) {
	if conv == 0 { // media-start/control replies are authenticated but not media
		if len(message) >= 20 {
			var payload0, payload1 uint32
			if len(message) >= 24 {
				payload0 = binary.LittleEndian.Uint32(message[20:24])
			}
			if len(message) >= 28 {
				payload1 = binary.LittleEndian.Uint32(message[24:28])
			}
			core.Logger.Debug().Msgf(
				"Camera control reply len=%d magic=%#x id=%#x direction=%d command=%#x payload_len=%d payload0=%#x payload1=%#x",
				len(message),
				binary.LittleEndian.Uint32(message[0:4]),
				binary.LittleEndian.Uint32(message[4:8]),
				binary.LittleEndian.Uint32(message[8:12]),
				binary.LittleEndian.Uint32(message[12:16]),
				binary.LittleEndian.Uint32(message[16:20]),
				payload0,
				payload1,
			)
		}
		return
	}
	packet, err := parseIMMMediaFrame(message)
	if err != nil {
		core.Logger.Trace().Err(err).Msgf("Invalid IMM media frame on KCP conv=%d", conv)
		return
	}
	switch conv {
	case 1:
		// The camera's IMM header uses its internal PT 95 for HEVC. The RTSP
		// endpoint declares dynamic PT 96, so normalize at the protocol boundary.
		packet.PayloadType = 96
		packet.Timestamp = c.normalizeVideoTimestamp(packet.Timestamp)
		if c.OnVideoRTP != nil {
			c.OnVideoRTP(packet)
		}
	case 2:
		// PATH-A downstream audio is raw 16 kHz mono S16LE (conv=2), not
		// G.711. RTP L16 uses signed 16-bit network byte order, so convert each
		// sample at the RTSP boundary and advertise a dynamic payload type.
		packet.PayloadType = 97
		// Philips audio uses a 4 kHz IMM timestamp clock. L16/16000 requires a
		// 16 kHz RTP clock, so scale it by four (uint32 arithmetic preserves
		// normal RTP rollover semantics).
		packet.Timestamp *= 4
		for i := 0; i+1 < len(packet.Payload); i += 2 {
			packet.Payload[i], packet.Payload[i+1] = packet.Payload[i+1], packet.Payload[i]
		}
		if c.OnAudioRTP != nil {
			c.OnAudioRTP(packet)
		}
	}
}

func (c *TuyaKCPClient) normalizeVideoTimestamp(raw uint32) uint32 {
	if !c.videoTimestampInitialized {
		c.videoTimestampInitialized = true
		c.videoTimestampRaw = raw
		// Preserve a deterministic offset while converting microseconds to
		// 90 kHz ticks. Only deltas matter to RTP consumers.
		c.videoTimestampRTP = uint32((uint64(raw) * 9) / 100)
		c.videoTimestampRemainder = (uint64(raw) * 9) % 100
		return c.videoTimestampRTP
	}

	// Unsigned subtraction unwraps a single uint32 rollover. At 15 fps there
	// are thousands of samples between rollovers, so more than one rollover
	// between packets is not a realistic ambiguity.
	deltaMicros := uint32(raw - c.videoTimestampRaw)
	scaled := uint64(deltaMicros)*9 + c.videoTimestampRemainder
	c.videoTimestampRTP += uint32(scaled / 100)
	c.videoTimestampRemainder = scaled % 100
	c.videoTimestampRaw = raw
	return c.videoTimestampRTP
}

// parseIMMMediaFrame removes the PATH-A IMM wrapper and decodes its fixed
// 12-byte RTP-like header. byte0 is an IMM marker (commonly 0x80/0xb8), not a
// stock RTP flags byte, so rtp.Packet.Unmarshal would incorrectly skip CSRCs.
func parseIMMMediaFrame(message []byte) (*rtp.Packet, error) {
	const fixedHeader = 12
	if len(message) < 28+fixedHeader {
		return nil, fmt.Errorf("IMM media frame too short: %d", len(message))
	}
	readLen := func(offset int) uint32 {
		return binary.LittleEndian.Uint32(message[offset-4 : offset])
	}
	valid := func(offset int) bool {
		return offset >= 4 && len(message) >= offset+fixedHeader &&
			(message[offset]&0xc0) == 0x80 &&
			readLen(offset) == uint32(len(message)-offset)
	}

	offset := 28
	if binary.LittleEndian.Uint32(message[16:20]) == 8 {
		offset = 36
	}
	if !valid(offset) {
		offset = 0
		scanEnd := minInt(60, len(message)-fixedHeader)
		for candidate := 4; candidate < scanEnd; candidate++ {
			if valid(candidate) {
				offset = candidate
				break
			}
		}
		if offset == 0 {
			return nil, errors.New("IMM wrapper has no self-describing RTP offset")
		}
	}

	header := message[offset : offset+fixedHeader]
	return &rtp.Packet{
		Header: rtp.Header{
			Version:        2,
			Marker:         header[1]&0x80 != 0,
			PayloadType:    header[1] & 0x7f,
			SequenceNumber: binary.BigEndian.Uint16(header[2:4]),
			Timestamp:      binary.BigEndian.Uint32(header[4:8]),
			SSRC:           binary.BigEndian.Uint32(header[8:12]),
		},
		Payload: message[offset+fixedHeader:],
	}, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// decryptSegment implements the negotiated AES/KCP suite: IV is cleartext at
// the start of each KCP PUSH payload, ciphertext is AES-128-CBC with PKCS#7.
func (c *TuyaKCPClient) decryptSegment(payload []byte) ([]byte, error) {
	if len(payload) < aes.BlockSize*2 {
		return nil, fmt.Errorf("AES/KCP segment too short: %d", len(payload))
	}
	iv := payload[:aes.BlockSize]
	ciphertext := payload[aes.BlockSize:]
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("AES/KCP ciphertext is not block aligned: %d", len(ciphertext))
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(c.block, iv).CryptBlocks(plaintext, ciphertext)
	padLen := int(plaintext[len(plaintext)-1])
	if padLen == 0 || padLen > aes.BlockSize || padLen > len(plaintext) {
		return nil, fmt.Errorf("invalid AES/KCP padding")
	}
	for _, b := range plaintext[len(plaintext)-padLen:] {
		if int(b) != padLen {
			return nil, fmt.Errorf("invalid AES/KCP padding bytes")
		}
	}
	return plaintext[:len(plaintext)-padLen], nil
}

// Close closes the KCP client
func (c *TuyaKCPClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true
	close(c.stopChan)

	if c.conn != nil {
		c.conn.Close()
	}

	return nil
}
