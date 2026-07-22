package tuya

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/stun/v3"
)

const syntheticMediaKey = "30313233343536373839616263646566"

type recordingConn struct {
	writes [][]byte
}

func (c *recordingConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *recordingConn) Close() error                     { return nil }
func (c *recordingConn) LocalAddr() net.Addr              { return testAddr("local") }
func (c *recordingConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (c *recordingConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(time.Time) error { return nil }
func (c *recordingConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}

type testAddr string

func (a testAddr) Network() string { return "test" }
func (a testAddr) String() string  { return string(a) }

func newTestKCPClient(t *testing.T) *TuyaKCPClient {
	t.Helper()
	c, err := NewTuyaKCPClient("camera", "", syntheticMediaKey, "password", "local-key", DirectICEParams{})
	if err != nil {
		t.Fatal(err)
	}
	c.conn = &recordingConn{}
	return c
}

func encryptTestSegment(t *testing.T, block cipher.Block, plaintext []byte) []byte {
	t.Helper()
	iv := bytes.Repeat([]byte{0x5a}, aes.BlockSize)
	padLen := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := append(append([]byte(nil), plaintext...), bytes.Repeat([]byte{byte(padLen)}, padLen)...)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	return append(iv, ciphertext...)
}

func TestValidAuthenticatorAcceptsCoalescedSegments(t *testing.T) {
	c := newTestKCPClient(t)
	body := make([]byte, 48)
	binary.LittleEndian.PutUint32(body[20:24], 0)
	binary.LittleEndian.PutUint32(body[24+20:24+24], 0)
	mac := hmac.New(sha1.New, c.aesKey)
	_, _ = mac.Write(body)
	packet := append(body, mac.Sum(nil)...)

	if !c.validAuthenticator(packet) {
		t.Fatal("valid HMAC over two coalesced KCP headers was rejected")
	}
	packet[7] ^= 1
	if c.validAuthenticator(packet) {
		t.Fatal("tampered datagram passed HMAC validation")
	}
}

func TestConnectivityCheckUsesFullICEWithoutUseCandidate(t *testing.T) {
	c := newTestKCPClient(t)
	c.ice = DirectICEParams{
		LocalUfrag:  "local",
		LocalPwd:    "local-password",
		RemoteUfrag: "camera",
		RemotePwd:   "camera-password",
		Priority:    1234,
	}
	txID := [stun.TransactionIDSize]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	message, err := c.buildConnectivityCheck(txID)
	if err != nil {
		t.Fatal(err)
	}
	if message.Type != stun.BindingRequest || message.TransactionID != txID {
		t.Fatalf("unexpected STUN request identity: type=%v txid=%x", message.Type, message.TransactionID)
	}
	if message.Contains(stun.AttrUseCandidate) {
		t.Fatal("camera rejects aggressive ICE checks carrying USE-CANDIDATE")
	}
	var username stun.Username
	if err := username.GetFrom(message); err != nil {
		t.Fatal(err)
	}
	if got, want := username.String(), "camera:local"; got != want {
		t.Fatalf("ICE username = %q, want %q", got, want)
	}
	if !message.Contains(stun.AttrPriority) || !message.Contains(stun.AttrICEControlled) {
		t.Fatal("ICE check is missing PRIORITY or ICE-CONTROLLED")
	}
	if err := message.Check(stun.NewShortTermIntegrity(c.ice.RemotePwd), stun.Fingerprint); err != nil {
		t.Fatalf("ICE integrity/fingerprint check failed: %v", err)
	}

	c.iceControlling = true
	controlling, err := c.buildConnectivityCheck(stun.NewTransactionID())
	if err != nil {
		t.Fatal(err)
	}
	if !controlling.Contains(stun.AttrICEControlling) || controlling.Contains(stun.AttrICEControlled) {
		t.Fatal("role-conflict fallback did not switch from ICE-CONTROLLED to ICE-CONTROLLING")
	}
}

func TestParseMediaAESKeyFromAnswerSDP(t *testing.T) {
	const key = syntheticMediaKey
	got, err := ParseMediaAESKeyFromSDP("v=0\r\na=ice-ufrag:test\r\na=aes-key:" + key + "\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if got != key {
		t.Fatalf("parsed media key does not match the answer SDP")
	}
	for _, invalid := range []string{"v=0\r\n", "a=aes-key:short\r\n", "a=aes-key:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\r\n"} {
		if _, err := ParseMediaAESKeyFromSDP(invalid); err == nil {
			t.Fatalf("invalid answer SDP key accepted: %q", invalid)
		}
	}
}

func TestBuildProtocol22FrameMatchesCameraCRCLayout(t *testing.T) {
	ciphertext := make([]byte, 32)
	for i := range ciphertext {
		ciphertext[i] = byte(i)
	}
	frame := BuildProtocol22Frame("2.2", 4, 588790, ciphertext)
	if got, want := frame[:15], []byte{
		'2', '.', '2',
		0xf7, 0xd0, 0x7a, 0x95,
		0, 0, 0, 4,
		0, 0x08, 0xfb, 0xf6,
	}; !bytes.Equal(got, want) {
		t.Fatalf("message-2.2 header = %x, want %x", got, want)
	}
	if !bytes.Equal(frame[15:], ciphertext) {
		t.Fatal("message-2.2 ciphertext was altered")
	}
}

func TestSignalingTopicsAreDeviceAddressed(t *testing.T) {
	pub, sub := signalingTopics("camera-device")
	if pub != "smart/mb/out/camera-device" {
		t.Fatalf("publish topic = %q", pub)
	}
	if sub != "smart/mb/in/camera-device" {
		t.Fatalf("subscribe topic = %q", sub)
	}
}

func TestReceivePushReordersBeforeRTPDelivery(t *testing.T) {
	c := newTestKCPClient(t)
	var got []uint16
	c.OnVideoRTP = func(packet *rtp.Packet) {
		got = append(got, packet.SequenceNumber)
	}

	makeRTP := func(seq uint16) []byte {
		packet := &rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 96, SequenceNumber: seq}, Payload: []byte{1}}
		data, err := packet.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return buildIMMTestFrame(28, 0, data)
	}
	if err := c.receivePush(1, 0, 10, 1, encryptTestSegment(t, c.block, makeRTP(11))); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("out-of-order segment delivered early: %v", got)
	}
	if err := c.receivePush(1, 0, 9, 0, encryptTestSegment(t, c.block, makeRTP(10))); err != nil {
		t.Fatal(err)
	}
	if want := []uint16{10, 11}; !slices.Equal(got, want) {
		t.Fatalf("delivery order = %v, want %v", got, want)
	}

	writes := c.conn.(*recordingConn).writes
	if len(writes) != 2 {
		t.Fatalf("ACK writes = %d, want 2", len(writes))
	}
	if una := binary.LittleEndian.Uint32(writes[1][16:20]); una != 2 {
		t.Fatalf("cumulative ACK una = %d, want 2", una)
	}
}

func TestParseIMMMediaFrame(t *testing.T) {
	for _, tc := range []struct {
		name       string
		wrapperLen int
		flags      uint32
		markerByte byte
	}{
		{name: "base", wrapperLen: 28, markerByte: 0xb8},
		{name: "metadata", wrapperLen: 36, flags: 8, markerByte: 0x80},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header := make([]byte, 12)
			header[0] = tc.markerByte
			header[1] = 0x80 | 96
			binary.BigEndian.PutUint16(header[2:4], 0x1234)
			binary.BigEndian.PutUint32(header[4:8], 0x10203040)
			binary.BigEndian.PutUint32(header[8:12], 0x55667788)
			message := buildIMMTestFrame(tc.wrapperLen, tc.flags, append(header, 0x65, 0x01, 0x02))

			packet, err := parseIMMMediaFrame(message)
			if err != nil {
				t.Fatal(err)
			}
			if packet.PayloadType != 96 || !packet.Marker || packet.SequenceNumber != 0x1234 ||
				packet.Timestamp != 0x10203040 || packet.SSRC != 0x55667788 {
				t.Fatalf("unexpected parsed header: %+v", packet.Header)
			}
			if !bytes.Equal(packet.Payload, []byte{0x65, 0x01, 0x02}) {
				t.Fatalf("payload = %x", packet.Payload)
			}
		})
	}
}

func TestDownstreamAudioConvertsS16LEToRTPNetworkOrder(t *testing.T) {
	client := &TuyaKCPClient{}
	var got *rtp.Packet
	client.OnAudioRTP = func(packet *rtp.Packet) {
		got = packet
	}

	header := make([]byte, 12)
	header[0] = 0x80
	header[1] = 99
	binary.BigEndian.PutUint32(header[4:8], 32)
	message := buildIMMTestFrame(28, 0, append(header, 0x34, 0x12, 0xfe, 0xff))
	client.handleMediaMessage(2, message)

	if got == nil {
		t.Fatal("audio callback was not invoked")
	}
	if got.PayloadType != 97 {
		t.Fatalf("payload type = %d, want 97", got.PayloadType)
	}
	if got.Timestamp != 128 {
		t.Fatalf("timestamp = %d, want 128", got.Timestamp)
	}
	if want := []byte{0x12, 0x34, 0xff, 0xfe}; !bytes.Equal(got.Payload, want) {
		t.Fatalf("payload = %x, want %x", got.Payload, want)
	}
}

func TestVideoTimestampConvertsMicrosecondsTo90kHzAcrossRollover(t *testing.T) {
	client := &TuyaKCPClient{}
	first := client.normalizeVideoTimestamp(0xffff0000)
	second := client.normalizeVideoTimestamp(0x0000046a) // +66,666 us after rollover
	third := client.normalizeVideoTimestamp(0x000108d4)  // another +66,666 us

	if delta := second - first; delta != 6000 {
		t.Fatalf("first timestamp delta = %d, want 6000", delta)
	}
	if delta := third - second; delta != 6000 {
		t.Fatalf("second timestamp delta = %d, want 6000", delta)
	}
}

func buildIMMTestFrame(wrapperLen int, flags uint32, rtpData []byte) []byte {
	message := make([]byte, wrapperLen+len(rtpData))
	binary.LittleEndian.PutUint32(message[16:20], flags)
	binary.LittleEndian.PutUint32(message[wrapperLen-4:wrapperLen], uint32(len(rtpData)))
	copy(message[wrapperLen:], rtpData)
	return message
}
