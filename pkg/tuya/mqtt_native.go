package tuya

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync/atomic"
	"time"
	"tuya-ipc-terminal/pkg/core"
	"tuya-ipc-terminal/pkg/utils"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/google/uuid"
)

// #region agent log - Debug logging helper (disabled)
// All debug logging now goes through core.Logger only.
// #endregion

// NativeMQTTClient is an MQTT client using SSL (native app protocol) instead of WebSocket
type NativeMQTTClient struct {
	mqtt           mqtt.Client
	uid            string
	deviceId       string
	localKey       []byte // Store as bytes for crypto
	subscribeTopic string
	publishTopic   string
	cameras        map[string]*MQTTCameraClient // sessionId -> camera
	closed         bool
	Connected      utils.Waiter
	seqS           int32
	randomO        int32
	currentSID     string
	currentTraceID string
	deviceDevID    string // Original device ID

	// Tuya KCP ICE credentials (generated in SendOffer)
	TuyaIceUfrag string
	TuyaIcePwd   string
	TuyaAesKey   string

	// Callbacks for signaling (since we bypass MQTTCameraClient for hardcoded)
	HandleAnswer     func(answer AnswerFrame)
	HandleCandidate  func(candidate CandidateFrame)
	HandleDisconnect func()
}

// NewNativeMqttClient creates an MQTT client using SSL with hardcoded credentials
func NewNativeMqttClient(deviceID string) (*NativeMQTTClient, error) {
	creds := ActiveMQTTCredentials()
	return NewNativeMqttClientWithCreds(deviceID, creds)
}

// NewNativeMqttClientWithCreds creates an MQTT client using SSL with provided credentials
func NewNativeMqttClientWithCreds(deviceID string, creds *MQTTCredentials) (*NativeMQTTClient, error) {
	if creds == nil {
		// Fallback to hardcoded
		creds = &MQTTCredentials{
			Broker:   HardcodedMQTTBroker,
			ClientID: HardcodedMQTTClientID,
			Username: HardcodedMQTTUsername,
			Password: HardcodedMQTTPassword,
			UID:      HardcodedUID,
		}
	}

	signalingUID := creds.UID
	if rtcUID := GetHardcodedWebRTCConfig().P2PConfig.Session.UID; rtcUID != "" {
		signalingUID = rtcUID
	}

	client := &NativeMQTTClient{
		uid:      signalingUID,
		deviceId: deviceID,
		localKey: []byte(ActiveLocalKey()),
		// Use provided topics, or generate defaults
		subscribeTopic: creds.SubscribeTopic,
		publishTopic:   creds.PublishTopic,
		Connected:      utils.Waiter{},
		cameras:        make(map[string]*MQTTCameraClient),
		seqS:           2,                                  // Starts at 2, first SAdd makes it 3
		randomO:        int32(rand.Int31n(1000000) + 1000), // Match SandO.java range (1000 - 1,001,000)
		deviceDevID:    deviceID,
	}

	// Set defaults if topics not provided
	if client.subscribeTopic == "" {
		client.subscribeTopic = fmt.Sprintf("smart/mb/in/%s", deviceID)
	}
	if client.publishTopic == "" {
		client.publishTopic = fmt.Sprintf("smart/mb/out/%s", deviceID)
	}

	// Mobile app authentication uses different format than standard device auth
	// The sidecar derives the rotating MQTT password from the live Tuya session.
	// This should be used AS A PLAIN STRING, not decoded from hex!
	// The password provider returns the actual password string to use

	// Use the password directly as a string
	passwordStr := creds.Password

	opts := mqtt.NewClientOptions()
	opts.AddBroker(creds.Broker)
	opts.SetClientID(creds.ClientID)
	opts.SetUsername(creds.Username)
	opts.SetPassword(passwordStr)
	opts.SetOnConnectHandler(client.onConnect)
	opts.SetConnectionLostHandler(client.onDisconnect)
	opts.SetAutoReconnect(true)
	opts.SetConnectTimeout(30 * time.Second)
	opts.SetKeepAlive(60 * time.Second)
	opts.SetCleanSession(true)

	// TLS config for SSL connection
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // Skip certificate verification for Tuya's broker
	}
	opts.SetTLSConfig(tlsConfig)

	client.mqtt = mqtt.NewClient(opts)
	core.Logger.Info().Msgf("Connecting to native MQTT broker: %s", creds.Broker)
	core.Logger.Debug().Msgf("MQTT credentials loaded (client_id_len=%d username_len=%d password_len=%d)",
		len(creds.ClientID), len(creds.Username), len(passwordStr))

	if token := client.mqtt.Connect(); token.Wait() && token.Error() != nil {
		return nil, fmt.Errorf("native MQTT connection failed: %v", token.Error())
	}

	return client, nil
}

func (c *NativeMQTTClient) Stop() {
	if c.mqtt != nil {
		c.mqtt.Disconnect(250)
		c.closed = true
	}
}

func (c *NativeMQTTClient) AddCameraClient(sessionId string, cameraClient *MQTTCameraClient) {
	c.cameras[sessionId] = cameraClient
}

func (c *NativeMQTTClient) RemoveCameraClient(sessionId string) {
	delete(c.cameras, sessionId)
}

func (c *NativeMQTTClient) GetUID() string {
	return c.uid
}

func (c *NativeMQTTClient) Publish(topic string, payload []byte) error {
	core.Logger.Debug().Msgf("Publish() called - Topic: %s, Payload: %d bytes", topic, len(payload))

	if c.mqtt == nil {
		core.Logger.Error().Msg("❌ MQTT client is nil")
		return errors.New("MQTT client not initialized")
	}

	if !c.mqtt.IsConnected() {
		core.Logger.Error().Msg("❌ MQTT client not connected")
		return errors.New("MQTT client not connected")
	}

	core.Logger.Debug().Msgf("Calling mqtt.Publish() with QoS=1, retained=false")
	token := c.mqtt.Publish(topic, 1, false, payload)
	core.Logger.Debug().Msgf("Waiting for publish token...")
	token.Wait()

	if token.Error() != nil {
		core.Logger.Error().Err(token.Error()).Msg("❌ Publish token error")
		return token.Error()
	}

	core.Logger.Debug().Msgf("✅ Publish token completed successfully")
	return nil
}

func (c *NativeMQTTClient) onConnect(client mqtt.Client) {
	creds := ActiveMQTTCredentials()
	core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")
	core.Logger.Info().Msgf("🔌 MQTT CONNECTION ESTABLISHED")
	core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")
	core.Logger.Info().Msgf("Broker: %s", creds.Broker)
	core.Logger.Info().Msgf("ClientID: %s", creds.ClientID)
	core.Logger.Info().Msgf("DeviceID: %s", c.deviceId)
	core.Logger.Info().Msgf("UID: %s", c.uid)
	core.Logger.Info().Msgf("Publish topic: %s", c.publishTopic)
	core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")
	core.Logger.Info().Msgf("Using 'mqtt' path over broker (matches the app's by_lan=0 frames)")
	core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")

	// 1. Subscribe to camera response topic
	inTopic := fmt.Sprintf("smart/mb/in/%s", c.deviceId)
	core.Logger.Info().Msgf("📡 Subscribing to Camera IN topic: %s (QoS=1)", inTopic)
	if token := client.Subscribe(inTopic, 1, c.consume); token.Wait() && token.Error() != nil {
		core.Logger.Error().Err(token.Error()).Msgf("❌ Failed to subscribe to Camera IN topic: %s", inTopic)
	} else {
		core.Logger.Info().Msgf("✅ Successfully subscribed to Camera IN topic: %s", inTopic)
	}

	// 2. Subscribe to user personal topic
	personalTopic := fmt.Sprintf("smart/mb/in/%s", c.uid)
	core.Logger.Info().Msgf("📡 Subscribing to Personal IN topic: %s (QoS=1)", personalTopic)
	if token := client.Subscribe(personalTopic, 1, c.consume); token.Wait() && token.Error() != nil {
		core.Logger.Error().Err(token.Error()).Msgf("❌ Failed to subscribe to Personal IN topic: %s", personalTopic)
	} else {
		core.Logger.Info().Msgf("✅ Successfully subscribed to Personal IN topic: %s", personalTopic)
	}

	// 3. Subscribe to partner-specific topic
	partnerTopic := fmt.Sprintf("p2065237/mb/%s", c.uid)
	core.Logger.Info().Msgf("📡 Subscribing to Partner topic: %s (QoS=1)", partnerTopic)
	if token := client.Subscribe(partnerTopic, 1, c.consume); token.Wait() && token.Error() != nil {
		core.Logger.Error().Err(token.Error()).Msgf("❌ Failed to subscribe to Partner topic: %s", partnerTopic)
	} else {
		core.Logger.Info().Msgf("✅ Successfully subscribed to Partner topic: %s", partnerTopic)
	}

	// Also subscribe to the partner topic with /in/ path (some cameras use this)
	partnerInTopic := fmt.Sprintf("p2065237/mb/in/%s", c.uid)
	core.Logger.Info().Msgf("📡 Subscribing to Partner IN topic: %s (QoS=1)", partnerInTopic)
	if token := client.Subscribe(partnerInTopic, 1, c.consume); token.Wait() && token.Error() != nil {
		core.Logger.Error().Err(token.Error()).Msgf("❌ Failed to subscribe to Partner IN topic: %s", partnerInTopic)
	} else {
		core.Logger.Info().Msgf("✅ Successfully subscribed to Partner IN topic: %s", partnerInTopic)
	}

	core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")
	core.Logger.Info().Msgf("✅ All subscriptions completed. Waiting for camera responses...")
	core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")
	c.Connected.Done(nil)
}

func (c *NativeMQTTClient) onDisconnect(client mqtt.Client, err error) {
	if err != nil {
		core.Logger.Error().Msgf("Native MQTT disconnected with error: %v", err)
		c.Connected.Done(err)
	} else {
		c.Connected.Done(errors.New("mqtt client disconnected"))
	}
	c.closed = true
}

func (c *NativeMQTTClient) consume(client mqtt.Client, msg mqtt.Message) {
	core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")
	core.Logger.Info().Msgf("📥 MQTT MESSAGE RECEIVED")
	core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")

	payload := msg.Payload()
	prefixLen := len(payload)
	if prefixLen > 32 {
		prefixLen = 32
	}
	core.Logger.Info().Msgf("Topic: %s", msg.Topic())
	core.Logger.Info().Msgf("Payload length: %d bytes", len(payload))

	// Try to decrypt if it looks like Protocol 2.2
	if len(payload) > 15 && string(payload[:3]) == "2.2" {
		core.Logger.Info().Msgf("✅ Detected Protocol 2.2 message (starts with '2.2')")
		core.Logger.Debug().Msgf("Attempting decryption with localKey...")

		// Header is variable length, but typically:
		// "2.2" (3) + random (4) + seq (4) + protocol (2) = 13 bytes
		// But in Python we saw it could be slightly different?
		// Let's assume standard offset 15 for now based on header structure
		// 3 + 4 + 4 + 4(length?) or direct?
		// Python: header = version(3) + random(4) + seq(4) + proto(2) = 13 bytes
		// Let's try offset 15 first (maybe some padding?)
		// Actually let's try the loop strategy from Python

		var decrypted []byte
		var err error

		core.Logger.Info().Msgf("Step 1: Trying decryption with different offsets (0-32)...")
		core.Logger.Debug().Msgf("LocalKey loaded (len=%d)", len(c.localKey))

		// Try offsets 0 to 32 (more aggressive)
		for offset := 0; offset <= 32; offset++ {
			if offset >= len(payload) {
				core.Logger.Debug().Msgf("  Offset %d: Skipping (>= payload length)", offset)
				continue
			}

			encryptedData := payload[offset:]

			// Must be multiple of 16 for AES-ECB
			if len(encryptedData)%16 != 0 {
				core.Logger.Debug().Msgf("  Offset %d: Skipping (encrypted length %d not multiple of 16)", offset, len(encryptedData))
				continue
			}

			core.Logger.Debug().Msgf("  Offset %d: Attempting decryption (%d bytes)...", offset, len(encryptedData))
			decrypted, err = AesDecryptECB(encryptedData, c.localKey)
			if err == nil && len(decrypted) > 0 {
				// Check if it's valid JSON (look for '{' and '}')
				cleanStr := strings.TrimSpace(string(decrypted))
				if len(cleanStr) > 0 && cleanStr[0] == '{' {
					core.Logger.Info().Msgf("✅ SUCCESS! Decrypted with offset %d", offset)
					var jsonMsg map[string]interface{}
					if err := json.Unmarshal([]byte(cleanStr), &jsonMsg); err == nil {
						core.Logger.Info().Msgf("✅ JSON parsed successfully")
						c.handleDecryptedMessage(jsonMsg)
						return
					} else {
						core.Logger.Warn().Err(err).Msgf("Failed to parse decrypted data as JSON at offset %d", offset)
					}
				} else {
					core.Logger.Debug().Msgf("  Offset %d: Decrypted but not valid JSON (first char: '%c')", offset,
						func() byte {
							if len(cleanStr) > 0 {
								return cleanStr[0]
							}
							return 0
						}())
				}
			} else {
				if err != nil {
					core.Logger.Debug().Msgf("  Offset %d: Decryption error: %v", offset, err)
				} else {
					core.Logger.Debug().Msgf("  Offset %d: Decryption returned empty result", offset)
				}
			}
		}

		core.Logger.Warn().Msgf("❌ Failed to decrypt Protocol 2.2 message (len %d, hex prefix: %X). Tried offsets 0-32", len(payload), payload[:prefixLen])
		return
	}

	// Try to parse as plain JSON (unlikely for native protocol but possible)
	core.Logger.Debug().Msgf("Message doesn't start with '2.2', trying plain JSON parse...")
	var rmqtt MqttMessage
	if err := json.Unmarshal(msg.Payload(), &rmqtt); err == nil {
		core.Logger.Info().Msgf("✅ Parsed as plain JSON message")
		// Handle plain message
		return
	} else {
		core.Logger.Warn().Msgf("❌ Failed to parse as plain JSON: %v", err)
	}
}

func (c *NativeMQTTClient) handleDecryptedMessage(msg map[string]interface{}) {
	core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")
	core.Logger.Info().Msgf("📋 PROCESSING DECRYPTED MESSAGE")
	core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")

	// #region agent log - Hypothesis C: Log decrypted message meta (no secrets)
	keys := make([]string, 0, len(msg))
	for k := range msg {
		keys = append(keys, k)
	}
	core.Logger.Info().Msgf("Message keys: %s", strings.Join(keys, ", "))
	protocolVal, ok := msg["protocol"]
	if !ok {
		core.Logger.Warn().Msg("⚠️ Message missing 'protocol' field - ignoring")
		return
	}
	core.Logger.Info().Msgf("Protocol: %v", protocolVal)

	// Check protocol type - Protocol 4 is device status, Protocol 302 is WebRTC signaling
	protocolNum, ok := protocolVal.(float64)
	if !ok {
		core.Logger.Warn().Msgf("⚠️ Protocol is not a number (type: %T) - ignoring", protocolVal)
		return
	}

	if protocolNum == 4 {
		core.Logger.Info().Msgf("ℹ️ Received Protocol 4 message (device status) - camera is online! Ignoring, waiting for Protocol 302 WebRTC answer...")
		return
	}

	if protocolNum != 302 {
		core.Logger.Warn().Msgf("⚠️ Unexpected protocol: %v (expected 302 for WebRTC). Ignoring message.", protocolNum)
		return
	}

	core.Logger.Info().Msgf("✅ Received Protocol 302 message (WebRTC signaling) - processing...")

	// #endregion

	// Parse the inner "data" which contains header and msg
	// The structure is { "protocol": 302, "data": { "header": {...}, "msg": {...} } }
	core.Logger.Debug().Msgf("Step 1: Extracting 'data' field...")

	dataVal, ok := msg["data"]
	if !ok {
		core.Logger.Error().Msg("❌ Message missing 'data' field")
		return
	}

	// Data might be map or string? usually map
	dataMap, ok := dataVal.(map[string]interface{})
	if !ok {
		core.Logger.Error().Msgf("❌ 'data' field is not a map (type: %T)", dataVal)
		return
	}
	core.Logger.Debug().Msgf("✅ 'data' field extracted")

	core.Logger.Debug().Msgf("Step 2: Extracting 'header' from data...")
	headerVal, ok := dataMap["header"]
	if !ok {
		core.Logger.Error().Msg("❌ Message missing 'header' field")
		// Log available keys for debugging
		dataKeys := make([]string, 0, len(dataMap))
		for k := range dataMap {
			dataKeys = append(dataKeys, k)
		}
		core.Logger.Debug().Msgf("Available keys in data: %v", strings.Join(dataKeys, ", "))
		return
	}

	headerMap, ok := headerVal.(map[string]interface{})
	if !ok {
		core.Logger.Error().Msgf("❌ 'header' field is not a map (type: %T)", headerVal)
		return
	}
	core.Logger.Debug().Msgf("✅ 'header' extracted")

	if headerJSON, err := json.MarshalIndent(headerMap, "", "  "); err == nil {
		core.Logger.Debug().Msgf("Header content:\n%s", string(headerJSON))
	}

	msgType, ok := headerMap["type"].(string)
	if !ok {
		core.Logger.Error().Msg("❌ Header missing 'type' field or not a string")
		return
	}
	core.Logger.Info().Msgf("✅ Message type: %s", msgType)
	core.Logger.Debug().Msgf("Header fields: from=%v, to=%v, sessionid=%v, trace_id=%v",
		headerMap["from"], headerMap["to"], headerMap["sessionid"], headerMap["trace_id"])
	if msgType == "answer" || msgType == "candidate" || msgType == "disconnect" {
		// Tuya's Java dispatcher keys active P2P state by trace_id. The camera's
		// connect/session identifier is not the authoritative correlation key.
		traceID, _ := headerMap["trace_id"].(string)
		if c.currentTraceID == "" || traceID == "" || traceID != c.currentTraceID {
			core.Logger.Info().Msg("Ignoring signaling message for a different session")
			return
		}
	}

	// Extract message body
	core.Logger.Debug().Msgf("Step 3: Extracting 'msg' from data...")
	msgBodyVal, ok := dataMap["msg"]
	if !ok {
		core.Logger.Error().Msg("❌ Message missing 'msg' field")
		return
	}

	msgBodyJSON, _ := json.Marshal(msgBodyVal)
	core.Logger.Debug().Msgf("✅ Message body extracted: %d bytes", len(msgBodyJSON))
	if len(msgBodyJSON) < 500 {
		core.Logger.Debug().Msgf("Message body:\n%s", string(msgBodyJSON))
	} else {
		core.Logger.Debug().Msgf("Message body (first 500 chars):\n%s", string(msgBodyJSON[:500]))
	}

	// #region agent log - Hypothesis C: Log message type received
	// #endregion

	core.Logger.Info().Msgf("Step 4: Routing to handler for type '%s'...", msgType)
	switch msgType {
	case "answer":
		core.Logger.Info().Msgf("🎯 ANSWER MESSAGE RECEIVED!")
		var answer AnswerFrame
		if err := json.Unmarshal(msgBodyJSON, &answer); err == nil {
			core.Logger.Info().Msgf("✅ Answer frame parsed successfully")
			core.Logger.Info().Msgf("Answer SDP length: %d bytes", len(answer.Sdp))
			core.Logger.Debug().Msgf("Answer mode: %s", answer.Mode)
			answerKey, keyErr := ParseMediaAESKeyFromSDP(answer.Sdp)
			if keyErr != nil {
				core.Logger.Error().Err(keyErr).Msg("Camera answer did not negotiate a usable AES/KCP media key")
				return
			}
			c.TuyaAesKey = answerKey
			core.Logger.Info().Msg("Adopted AES/KCP media key negotiated by camera answer")

			// #region agent log - Answer received
			// #endregion

			if c.HandleAnswer != nil {
				core.Logger.Info().Msgf("Calling HandleAnswer callback...")
				c.HandleAnswer(answer)
				core.Logger.Info().Msgf("✅ HandleAnswer callback completed")
			} else {
				core.Logger.Warn().Msg("⚠️ HandleAnswer callback is nil!")
			}
		} else {
			core.Logger.Error().Err(err).Msg("❌ Failed to unmarshal answer frame")
		}
	case "candidate":
		core.Logger.Info().Msgf("🧊 CANDIDATE MESSAGE RECEIVED!")
		var candidate CandidateFrame
		if err := json.Unmarshal(msgBodyJSON, &candidate); err == nil {
			core.Logger.Info().Msgf("✅ Candidate frame parsed successfully")
			core.Logger.Debug().Msgf("Raw candidate: %s", candidate.Candidate)
			core.Logger.Debug().Msgf("Candidate mode: %s", candidate.Mode)

			// Clean candidate
			originalCandidate := candidate.Candidate
			candidate.Candidate = strings.TrimPrefix(candidate.Candidate, "a=")
			candidate.Candidate = strings.TrimSuffix(candidate.Candidate, "\r")
			core.Logger.Debug().Msgf("Cleaned candidate: %s (was: %s)", candidate.Candidate, originalCandidate)

			// #region agent log - Candidate received
			// #endregion

			if c.HandleCandidate != nil {
				core.Logger.Info().Msgf("Calling HandleCandidate callback...")
				c.HandleCandidate(candidate)
				core.Logger.Info().Msgf("✅ HandleCandidate callback completed")
			} else {
				core.Logger.Warn().Msg("⚠️ HandleCandidate callback is nil!")
			}
		} else {
			core.Logger.Error().Err(err).Msg("❌ Failed to unmarshal candidate frame")
		}
	case "disconnect":
		core.Logger.Info().Msgf("🔌 DISCONNECT MESSAGE RECEIVED!")
		// #region agent log - Disconnect received
		// #endregion
		if c.HandleDisconnect != nil {
			core.Logger.Info().Msgf("Calling HandleDisconnect callback...")
			c.HandleDisconnect()
			core.Logger.Info().Msgf("✅ HandleDisconnect callback completed")
		} else {
			core.Logger.Warn().Msg("⚠️ HandleDisconnect callback is nil!")
		}
	default:
		core.Logger.Warn().Msgf("⚠️ Unknown message type: %s", msgType)
	}
	core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")
}

// TuyaSDPResult contains the generated SDP and ICE credentials
type TuyaSDPResult struct {
	SDP      string
	IceUfrag string
	IcePwd   string
}

// GenerateTuyaSDP creates Tuya-proprietary SDP for KCP/IMM protocol
// CRITICAL: Must use \r\n line endings to match the app's wire format exactly
func GenerateTuyaSDP(uid, sessionId, aesKey string, timestamp int64) TuyaSDPResult {
	iceUfrag := utils.RandString(4, 62) // 4 chars alphanumeric
	icePwd := utils.RandString(24, 62)  // 24 chars

	// Use \r\n line endings to match the app's wire format exactly
	sdp := fmt.Sprintf("v=0\r\n"+
		"o=- %d 1 IN IP4 127.0.0.1\r\n"+
		"s=-\r\n"+
		"t=0 0\r\n"+
		"a=group:BUNDLE imm0\r\n"+
		"a=msid-semantic: WMS %s\r\n"+
		"m=application 9 imm 6001\r\n"+
		"c=IN IP4 0.0.0.0\r\n"+
		"a=rtcp:9 IN IP4 0.0.0.0\r\n"+
		"a=ice-ufrag:%s\r\n"+
		"a=ice-pwd:%s\r\n"+
		"a=ice-options:trickle\r\n"+
		"a=aes-key:%s\r\n"+
		"a=mid:imm0\r\n"+
		"a=rtpmap:6001 AES/KCP 330\r\n"+
		"a=ssrc:0 cname:%s\r\n",
		timestamp, sessionId, iceUfrag, icePwd, aesKey, uid)

	return TuyaSDPResult{
		SDP:      sdp,
		IceUfrag: iceUfrag,
		IcePwd:   icePwd,
	}
}

func (c *NativeMQTTClient) SendOffer(sdp string) error {
	core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")
	core.Logger.Info().Msgf("📤 SEND OFFER - Starting offer generation")
	core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")
	core.Logger.Info().Msgf("Input WebRTC SDP length: %d bytes", len(sdp))
	core.Logger.Debug().Msgf("Input WebRTC SDP (first 500 chars):\n%s", sdp[:min(500, len(sdp))])

	// Construct payload for Tuya KCP/IMM protocol (not standard WebRTC)
	// Protocol 302 - matching the app's offer format
	now := time.Now()
	timestamp := now.Unix()
	timestampMs := now.UnixMilli()
	core.Logger.Info().Msgf("Timestamp: %d (unix), %d (millis)", timestamp, timestampMs)

	hcConfig := GetHardcodedWebRTCConfig()
	core.Logger.Debug().Msgf("Loaded hardcoded WebRTC config")

	// CRITICAL FIX: trace_id format from ACTUAL capture of working system
	// Format: {UUID}_{deviceId}_{timestamp_ms} (NOT ipc_p2p_android_*)
	// Generated UUID matches the actual working protocol
	uuidVal := uuid.New().String()
	traceID := fmt.Sprintf("%s_%s_%d", uuidVal, c.deviceId, timestampMs)
	core.Logger.Info().Msgf("Generated traceID (actual working format): %s", traceID)

	// CRITICAL FIX: sessionid is ALWAYS generated fresh
	// Format: {deviceId}{timestamp}{8-char-random}
	// The app does NOT use tcp_token.sessionId for header.sessionid!
	sid := fmt.Sprintf("%s%d%s", c.deviceId, timestamp, utils.RandString(8, 62))
	core.Logger.Info().Msgf("Generated fresh sessionId: %s (length: %d)", sid, len(sid))

	// CRITICAL FIX: Generate fresh AES key for each session (16 bytes hex = 32 chars)
	// The app generates a new aes-key each time, different from tcp_token
	freshAesKey := fmt.Sprintf("%s", utils.RandString(32, 16))
	core.Logger.Info().Msgf("Generated fresh media key (length=%d)", len(freshAesKey))

	core.Logger.Info().Msgf("Generating Tuya KCP signaling with - SessionID: %s, TraceID: %s", sid, traceID)

	// #region agent log - Offer structure matching the app
	// #endregion

	// Store IDs for candidates
	c.currentSID = sid
	c.currentTraceID = traceID
	core.Logger.Info().Msgf("Stored sessionId=%s, traceID=%s for future candidates", sid, traceID)

	// Generate Tuya-compatible SDP with FRESH aes-key
	core.Logger.Info().Msg("Generating Tuya AES/KCP SDP")
	tuyaResult := GenerateTuyaSDP(c.uid, sid, freshAesKey, timestamp)

	// Store ICE credentials for standalone ICE agent
	c.TuyaIceUfrag = tuyaResult.IceUfrag
	c.TuyaIcePwd = tuyaResult.IcePwd
	c.TuyaAesKey = freshAesKey
	core.Logger.Info().Msgf("Stored ICE and media credentials (ufrag_len=%d pwd_len=%d key_len=%d)",
		len(tuyaResult.IceUfrag), len(tuyaResult.IcePwd), len(freshAesKey))

	// Offer structure matching the app:
	// 1. moto_id is EMPTY (not "signaling14915")
	// 2. p2p_skill is 1635 on the validated AES/KCP offer (not the cloud's
	// capability-only p2p value)
	// 3. sessionid is generated fresh (not from tcp_token)
	// 4. trace_id uses UUID format: {uuid}_{deviceId}_{timestamp_ms}
	// 5. aes-key is generated fresh for each session
	core.Logger.Info().Msgf("Building offer payload structure...")
	core.Logger.Debug().Msgf("Header fields: from=%s, to=%s, sessionid=%s, moto_id='' (empty), type=offer, trace_id=%s, p2p_skill=1635",
		c.uid, c.deviceId, sid, traceID)
	msgBody := map[string]interface{}{
		"sdp":        tuyaResult.SDP,
		"preconnect": true,
		"token":      hcConfig.P2PConfig.Ices,
	}
	if len(hcConfig.P2PConfig.TcpToken) > 0 {
		tcpToken := make(map[string]interface{}, len(hcConfig.P2PConfig.TcpToken))
		for key, value := range hcConfig.P2PConfig.TcpToken {
			tcpToken[key] = value
		}
		// The mobile client remints this independently from header.sessionid,
		// using the same device/timestamp and a distinct random suffix.
		tcpToken["sessionId"] = fmt.Sprintf("%s%d%s", c.deviceId, timestamp, utils.RandString(8, 62))
		msgBody["tcp_token"] = tcpToken
	}
	if len(hcConfig.P2PConfig.Log) > 0 {
		msgBody["log"] = hcConfig.P2PConfig.Log
	}

	payload := map[string]interface{}{
		"protocol": 302,
		"t":        timestamp,
		"data": map[string]interface{}{
			"header": map[string]interface{}{
				"from":           c.uid,
				"to":             c.deviceId,
				"sessionid":      sid,
				"moto_id":        "", // CRITICAL: Empty in app!
				"type":           "offer",
				"trace_id":       traceID,
				"is_pre":         0,
				"p2p_skill":      1635,
				"security_level": 3,
				"path":           "mqtt", // over broker the app uses path=mqtt (by_lan=0); lan-path goes over LAN only
			},
			"msg": msgBody,
		},
	}

	return c.sendSignalingPaths(payload)
}

// SendCandidate sends an ICE candidate (legacy - not used for KCP)
func (c *NativeMQTTClient) SendCandidate(candidate string) error {
	// CRITICAL FIX: moto_id is EMPTY in the app's candidates too
	payload := map[string]interface{}{
		"protocol": 302, // CRITICAL: Was missing!
		"t":        time.Now().Unix(),
		"data": map[string]interface{}{
			"header": map[string]interface{}{
				"from":      c.uid,
				"to":        c.deviceId,
				"sessionid": c.currentSID,
				"moto_id":   "", // CRITICAL: Empty in app!
				"type":      "candidate",
				"trace_id":  c.currentTraceID,
				"path":      "mqtt", // candidates go over broker with path=mqtt (by_lan=0)
			},
			"msg": map[string]interface{}{
				"candidate": candidate,
			},
		},
	}

	return c.sendSignalingPaths(payload)
}

// SendTuyaCandidate sends an ICE candidate for Tuya KCP protocol
// The candidate should be in the format "a=candidate:..." with trailing \r\n
func (c *NativeMQTTClient) SendTuyaCandidate(candidate string) error {
	core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")
	core.Logger.Info().Msgf("🧊 SEND TUYA ICE CANDIDATE")
	core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")
	core.Logger.Info().Msgf("Input candidate: %s", candidate)
	core.Logger.Info().Msgf("SessionID: %s, TraceID: %s", c.currentSID, c.currentTraceID)

	// Offer structure fixes:
	// 1. Convert "udp" to "UDP" (app uses uppercase)
	// 2. Remove "ufrag ..." suffix (app doesn't include it)
	// 3. Add \r\n at the end

	originalCandidate := candidate
	// Remove ufrag suffix if present (everything after "ufrag" or from "ufrag" onwards)
	if idx := strings.Index(candidate, " ufrag "); idx != -1 {
		candidate = candidate[:idx]
		core.Logger.Debug().Msgf("Removed ufrag suffix, candidate now: %s", candidate)
	}

	// Convert lowercase udp to uppercase UDP
	if strings.Contains(candidate, " udp ") {
		candidate = strings.Replace(candidate, " udp ", " UDP ", 1)
		core.Logger.Debug().Msgf("Converted 'udp' to 'UDP'")
	}

	// Ensure candidate starts with "a=" and ends with \r\n (matching app format)
	if !strings.HasPrefix(candidate, "a=") {
		candidate = "a=" + candidate
		core.Logger.Debug().Msgf("Added 'a=' prefix")
	}
	if !strings.HasSuffix(candidate, "\r\n") {
		candidate = candidate + "\r\n"
		core.Logger.Debug().Msgf("Added '\\r\\n' suffix")
	}

	core.Logger.Info().Msgf("Processed candidate: %s (was: %s)", candidate, originalCandidate)

	payload := map[string]interface{}{
		"protocol": 302,
		"t":        time.Now().Unix(),
		"data": map[string]interface{}{
			"header": map[string]interface{}{
				"from":      c.uid,
				"to":        c.deviceId,
				"sessionid": c.currentSID,
				"moto_id":   "", // CRITICAL: Empty in app!
				"type":      "candidate",
				"trace_id":  c.currentTraceID,
				"path":      "mqtt", // candidates go over broker with path=mqtt (by_lan=0)
			},
			"msg": map[string]interface{}{
				"candidate": candidate,
			},
		},
	}

	core.Logger.Info().Msgf("Sending Tuya ICE candidate: %s", strings.TrimSpace(candidate))
	return c.sendSignalingPaths(payload)
}

// SendEmptyCandidate signals ICE gathering is complete (app sends this!)
func (c *NativeMQTTClient) SendEmptyCandidate() error {
	core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")
	core.Logger.Info().Msgf("📤 SEND EMPTY CANDIDATE (ICE gathering complete)")
	core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")
	core.Logger.Info().Msgf("SessionID: %s, TraceID: %s", c.currentSID, c.currentTraceID)

	payload := map[string]interface{}{
		"protocol": 302,
		"t":        time.Now().Unix(),
		"data": map[string]interface{}{
			"header": map[string]interface{}{
				"from":      c.uid,
				"to":        c.deviceId,
				"sessionid": c.currentSID,
				"moto_id":   "", // CRITICAL: Empty in app!
				"type":      "candidate",
				"trace_id":  c.currentTraceID,
				"path":      "mqtt", // candidates go over broker with path=mqtt (by_lan=0)
			},
			"msg": map[string]interface{}{
				"candidate": "",
			},
		},
	}

	core.Logger.Info().Msg("Sending empty candidate to signal ICE gathering complete")
	return c.sendSignalingPaths(payload)
}

// sendSignalingPaths mirrors the mobile/native flow: each offer or trickled
// candidate is published once with path=mqtt and once with path=lan. Both are
// message-2.2 broker frames and therefore receive distinct (s,o) tuples.
func (c *NativeMQTTClient) sendSignalingPaths(payload map[string]interface{}) error {
	data, ok := payload["data"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("signaling payload missing data object")
	}
	header, ok := data["header"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("signaling payload missing header object")
	}
	for _, path := range []string{"mqtt", "lan"} {
		header["path"] = path
		if err := c.sendEncryptedMessage(302, payload); err != nil {
			return fmt.Errorf("send signaling path %s: %w", path, err)
		}
	}
	return nil
}

func (c *NativeMQTTClient) sendEncryptedMessage(protocol int, data interface{}) error {
	core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")
	core.Logger.Info().Msgf("🔐 ENCRYPTING MESSAGE - Protocol %d", protocol)
	core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")

	// JSON encode the PublishBean2_2 structure
	// PublishBean2_2 has { "protocol": protocol, "t": timestamp, "data": msg }
	core.Logger.Debug().Msgf("Step 1: Marshaling payload to JSON...")
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		core.Logger.Error().Err(err).Msg("Failed to marshal payload to JSON")
		return err
	}
	core.Logger.Info().Msgf("✅ JSON marshaled: %d bytes", len(jsonBytes))

	// #region agent log - Hypothesis C: Log message being sent
	// #endregion

	// Encrypt the JSON payload using AES-ECB
	keyBytes := []byte(c.localKey)
	core.Logger.Info().Msgf("Step 2: Encrypting with AES-ECB...")
	core.Logger.Debug().Msgf("LocalKey loaded (len=%d)", len(keyBytes))
	core.Logger.Debug().Msgf("Plaintext length: %d bytes (must be multiple of 16 for AES-ECB)", len(jsonBytes))

	encrypted, err := AesEncryptECB(jsonBytes, keyBytes)
	if err != nil {
		core.Logger.Error().Err(err).Msg("AES encryption failed")
		return err
	}
	core.Logger.Info().Msgf("✅ Encrypted: %d bytes (was %d bytes)", len(encrypted), len(jsonBytes))
	core.Logger.Debug().Msgf("Encrypted data (first 64 bytes hex): %X", encrypted[:min(64, len(encrypted))])

	// Increment sequence 's'
	// Matching SandO.java: s starts at 2, first SAdd makes it 3.
	atomic.AddInt32(&c.seqS, 1)
	s := atomic.LoadInt32(&c.seqS)
	atomic.AddInt32(&c.randomO, 1)
	o := atomic.LoadInt32(&c.randomO)
	core.Logger.Info().Msgf("Step 3: Building Protocol 2.2 header...")
	core.Logger.Debug().Msgf("Sequence s=%d, random o=%d", s, o)

	// Final packet: pv + CRC32(s||o||ciphertext) + s + o + ciphertext.
	// The prior two-stage CRC was broker-valid but failed the camera's 12002
	// signature gate before the offer JSON could be parsed.
	message := BuildProtocol22Frame("2.2", uint32(s), uint32(o), encrypted)
	core.Logger.Info().Msgf("✅ Final message assembled: %d bytes total (15 header + %d encrypted)", len(message), len(encrypted))
	core.Logger.Debug().Msgf("Message structure: [15-byte header][%d-byte encrypted payload]", len(encrypted))
	core.Logger.Debug().Msgf("First 32 bytes of message: %X", message[:min(32, len(message))])

	core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")
	core.Logger.Info().Msgf("📤 PUBLISHING MQTT MESSAGE")
	core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")
	core.Logger.Info().Msgf("Topic: %s", c.publishTopic)
	core.Logger.Info().Msgf("Message length: %d bytes", len(message))
	core.Logger.Info().Msgf("Protocol: %d, Sequence: s=%d, o=%d", protocol, s, o)
	core.Logger.Debug().Msgf("Full message hex (first 100 bytes): %X", message[:min(100, len(message))])

	if err := c.Publish(c.publishTopic, message); err != nil {
		core.Logger.Error().Err(err).Msgf("❌ Failed to publish message to %s", c.publishTopic)
		return err
	}

	core.Logger.Info().Msgf("✅ Message published successfully to %s", c.publishTopic)
	core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")
	return nil
}
