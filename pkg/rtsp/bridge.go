package rtsp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	pion "github.com/pion/webrtc/v4"
	"golang.org/x/net/publicsuffix"

	"tuya-ipc-terminal/pkg/core"
	"tuya-ipc-terminal/pkg/storage"
	"tuya-ipc-terminal/pkg/tuya"
	"tuya-ipc-terminal/pkg/utils"
	"tuya-ipc-terminal/pkg/webrtc"

	"github.com/pion/rtp"
)

type WebRTCBridge struct {
	camera         *storage.CameraInfo
	resolution     string
	streamType     int
	isHEVC         bool
	user           *storage.UserSession
	storageManager *storage.StorageManager

	// WebRTC components
	peerConnection   *pion.PeerConnection
	dataChannel      *pion.DataChannel
	mqttClient       *tuya.MQTTClient
	nativeMqttClient *tuya.NativeMQTTClient // For hardcoded Philips camera
	cameraClient     *tuya.MQTTCameraClient
	rtpForwarder     *RTPForwarder

	// Tuya KCP ICE agent (for hardcoded cameras)
	tuyaICEAgent      *tuya.TuyaICEAgent
	tuyaKCPClient     *tuya.TuyaKCPClient
	isHardcodedCamera bool

	// State
	connected bool
	waiter    utils.Waiter
	mutex     sync.RWMutex
	kcpStart  sync.Once
	stopped   bool

	// Context for cancellation
	ctx    context.Context
	cancel context.CancelFunc

	// RTP forwarding
	videoTrack  *pion.TrackRemote
	audioTrack  *pion.TrackRemote
	backchannel *pion.TrackLocalStaticRTP

	// Callbacks
	OnVideoPacket func(packet *rtp.Packet)
	OnAudioPacket func(packet *rtp.Packet)
	OnError       func(error)
}

func NewWebRTCBridge(camera *storage.CameraInfo, streamResolution string, user *storage.UserSession, storageManager *storage.StorageManager) *WebRTCBridge {
	ctx, cancel := context.WithCancel(context.Background())

	wb := &WebRTCBridge{
		camera:         camera,
		resolution:     streamResolution,
		user:           user,
		rtpForwarder:   NewRTPForwarder(),
		storageManager: storageManager,
		connected:      false,
		waiter:         utils.Waiter{},
		ctx:            ctx,
		cancel:         cancel,
	}

	wb.rtpForwarder.OnBackchannelAudio = wb.ForwardBackchannelAudioPacket

	return wb
}

func (wb *WebRTCBridge) Start() error {
	wb.mutex.Lock()
	if wb.connected || wb.stopped {
		wb.mutex.Unlock()
		return errors.New("bridge already connected")
	}
	wb.mutex.Unlock()
	// Arm before any signaling callback can complete. Waiter's auto-start loses a
	// completion that arrives before WaitChan is created on fast LAN sessions.
	wb.waiter.Add(1)

	core.Logger.Info().Msgf("Starting WebRTC bridge for camera: %s", wb.camera.DeviceName)

	var webRTCConfig *tuya.WebRTCConfig
	wb.isHardcodedCamera = tuya.IsHardcodedDevice(wb.camera.DeviceID)

	// Check if this is our hardcoded Philips camera
	if wb.isHardcodedCamera {
		core.Logger.Info().Msg("🐾 Detected Philips Pet Series camera - refreshing live credentials")

		// Fetch fresh WebRTC creds (motoId/auth/ICE/localKey) from the sidecar
		// BEFORE building the MQTT client, so the AES localKey is current.
		// Fall back to the static fallback if the sidecar is unreachable.
		if _, err := tuya.RefreshFromSidecar(wb.camera.DeviceID); err != nil {
			return fmt.Errorf("camera credential refresh failed: %w", err)
		}

		// Use native MQTT client with SSL (not WebSocket)
		nativeMqtt, err := tuya.NewNativeMqttClient(wb.camera.DeviceID)
		if err != nil {
			return fmt.Errorf("failed to connect to native MQTT: %v", err)
		}

		// Store the native client
		wb.nativeMqttClient = nativeMqtt

		if err = nativeMqtt.Connected.Wait(); err != nil {
			return fmt.Errorf("native MQTT connection failed: %v", err)
		}

		// Use hardcoded WebRTC config
		webRTCConfig = tuya.GetHardcodedWebRTCConfig()

		core.Logger.Info().Msg("Hardcoded configuration loaded successfully")

	} else {
		// Original flow for authenticated devices
		// Create HTTP client with session
		httpClient := wb.createHTTPClient()
		if httpClient == nil {
			return errors.New("failed to create HTTP client")
		}

		// Get app info
		appInfo, err := tuya.GetAppInfo(httpClient, wb.user.SessionData.ServerHost)
		if err != nil {
			return fmt.Errorf("failed to get app info: %v", err)
		}

		// Get MQTT config
		mqttConfig, err := tuya.GetMQTTConfig(httpClient, wb.user.SessionData.ServerHost)
		if err != nil {
			return fmt.Errorf("failed to get MQTT config: %v", err)
		}

		// Connect to MQTT broker
		wb.mqttClient, err = tuya.NewMqttClient(
			appInfo.Result.ClientId,
			wb.user.SessionData.LoginResult.Domain.MobileMqttsUrl,
			&mqttConfig.Result,
		)

		if err != nil {
			return fmt.Errorf("failed to connect to MQTT: %v", err)
		}

		if err = wb.mqttClient.Connected.Wait(); err != nil {
			return fmt.Errorf("MQTT connection failed: %v", err)
		}

		// Get WebRTC configuration
		webRTCConfigResp, err := tuya.GetWebRTCConfig(httpClient, wb.user.SessionData.ServerHost, wb.camera.DeviceID)
		if err != nil {
			return fmt.Errorf("failed to get WebRTC config: %v", err)
		}
		webRTCConfig = &webRTCConfigResp.Result
	}

	// Parse skill information
	var skill tuya.Skill
	if err := json.Unmarshal([]byte(webRTCConfig.Skill), &skill); err != nil {
		return fmt.Errorf("failed to parse skill info: %v", err)
	}

	// Determine stream settings
	wb.streamType = tuya.GetStreamType(&skill, wb.resolution)
	wb.isHEVC = tuya.IsHEVC(&skill, wb.streamType)

	core.Logger.Info().Msgf("Stream settings - Resolution: %s, Type: %d, HEVC: %v", wb.resolution, wb.streamType, wb.isHEVC)

	// Tuya's AES/KCP stream is not WebRTC media. Creating Pion's data channel here
	// creates a second, unused ICE state machine and can race the native signaling
	// session. Keep Pion only for ordinary cameras.
	if !wb.isHardcodedCamera {
		if err := wb.setupPeerConnection(webRTCConfig); err != nil {
			return fmt.Errorf("failed to setup peer connection: %v", err)
		}
	}

	// Setup MQTT camera client
	if wb.isHardcodedCamera {
		core.Logger.Info().Msg("🐾 Hardcoded camera: Using native MQTT signaling with Tuya KCP")

		// Setup handlers for native MQTT client - route to Tuya ICE agent
		core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")
		core.Logger.Info().Msgf("🔧 SETTING UP NATIVE MQTT HANDLERS")
		core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")

		wb.nativeMqttClient.HandleAnswer = func(answer tuya.AnswerFrame) {
			core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")
			core.Logger.Info().Msgf("🎯 HANDLEANSWER CALLBACK INVOKED")
			core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")
			core.Logger.Info().Msgf("Received Tuya KCP answer via Native MQTT")
			core.Logger.Info().Msgf("Answer SDP length: %d bytes", len(answer.Sdp))
			core.Logger.Info().Msgf("Answer mode: %s", answer.Mode)

			// Parse remote ICE credentials from answer SDP
			core.Logger.Info().Msgf("Parsing ICE credentials from answer SDP...")
			remoteUfrag, remotePwd := tuya.ParseICECredentialsFromSDP(answer.Sdp)
			core.Logger.Info().Msgf("Parsed ICE credentials (ufrag_len=%d pwd_len=%d)", len(remoteUfrag), len(remotePwd))

			if remoteUfrag != "" && remotePwd != "" {
				core.Logger.Info().Msgf("✅ Successfully extracted remote ICE credentials")

				if wb.tuyaICEAgent != nil {
					core.Logger.Info().Msgf("Setting remote credentials on Tuya ICE agent...")
					wb.tuyaICEAgent.SetRemoteCredentials(remoteUfrag, remotePwd)

					// DIRECT-UDP KCP path (bypass pion ICE, which waits for STUN
					// checks the camera never sends). Wait briefly for the camera's
					// host candidate to arrive via HandleCandidate, then open a UDP
					// socket straight to it and run the KCP media client.
					wb.kcpStart.Do(func() {
						go func() {
							core.Logger.Info().Msgf("Waiting for camera host candidate (up to 8s)...")
							var lastErr error
							for i := 0; i < 40; i++ {
								if _, err := wb.extractCameraLANAddr(); err == nil {
									break
								} else {
									lastErr = err
								}
								time.Sleep(200 * time.Millisecond)
							}
							core.Logger.Info().Msgf("Starting direct KCP tunnel (last probe err: %v)...", lastErr)
							if err := wb.startKCPTunnel(nil); err != nil {
								core.Logger.Error().Err(err).Msg("❌ Failed to start direct KCP tunnel")
								wb.handleError(err)
								return
							}
							core.Logger.Info().Msgf("✅ Direct KCP tunnel started, signaling success...")
							wb.mutex.Lock()
							wb.connected = true
							wb.mutex.Unlock()
							wb.waiter.Done(nil)
						}()
					})
				} else {
					core.Logger.Error().Msg("❌ Tuya ICE agent is nil!")
				}
			} else {
				core.Logger.Warn().Msg("❌ Could not extract ICE credentials from answer SDP")
			}
			core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")
		}

		wb.nativeMqttClient.HandleCandidate = func(candidate tuya.CandidateFrame) {
			core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")
			core.Logger.Info().Msgf("🧊 HANDLECANDIDATE CALLBACK INVOKED")
			core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")
			candidateStr := strings.TrimSpace(candidate.Candidate)
			core.Logger.Info().Msgf("Received remote ICE candidate: %s", candidateStr)
			core.Logger.Info().Msgf("Candidate mode: %s", candidate.Mode)

			if candidateStr != "" {
				if wb.tuyaICEAgent != nil {
					core.Logger.Info().Msgf("Adding remote candidate to Tuya ICE agent...")
					if err := wb.tuyaICEAgent.AddRemoteCandidate(candidateStr); err != nil {
						core.Logger.Error().Err(err).Msg("❌ Failed to add remote ICE candidate")
					} else {
						core.Logger.Info().Msgf("✅ Remote candidate added successfully")
					}
				} else {
					core.Logger.Warn().Msg("⚠️ Tuya ICE agent is nil, cannot add candidate")
				}
			} else {
				core.Logger.Info().Msgf("Empty candidate (ICE gathering complete signal)")
			}
			core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")
		}

		wb.nativeMqttClient.HandleDisconnect = func() {
			core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")
			core.Logger.Info().Msgf("🔌 HANDLEDISCONNECT CALLBACK INVOKED")
			core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")
			if !wb.connected {
				// A close notification for the just-stopped prior session can arrive
				// after this client has published its offer. It is not evidence that
				// the pending session failed; wait for the matching answer/candidates.
				core.Logger.Warn().Msg("Ignoring disconnect while direct KCP session is pending")
				return
			}
			core.Logger.Warn().Msg("Camera client disconnected")
			wb.handleError(errors.New("camera client disconnected"))
			wb.connected = false
			core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")
		}

		core.Logger.Info().Msgf("✅ All handlers registered successfully")
		core.Logger.Info().Msgf("═══════════════════════════════════════════════════════════")

	} else {
		wb.setupMQTTCameraClient(webRTCConfig)
	}

	// Create and send offer
	if err := wb.createAndSendOffer(); err != nil {
		return fmt.Errorf("failed to create offer: %v", err)
	}

	core.Logger.Info().Msgf("⏳ Waiting for camera response (offer sent, waiting for answer)...")

	// Wait for WebRTC connection with a timeout
	// Increased to 60 seconds - camera may need more time to process the offer
	core.Logger.Info().Msgf("⏳ Waiting for camera response (offer sent, waiting for answer)...")
	core.Logger.Info().Msgf("   Timeout: 60 seconds (increased from 30s)")

	// Use a ticker to log periodic updates
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	timeout := time.After(60 * time.Second)
	waitCh := wb.waiter.WaitChan()

	for {
		select {
		case err := <-waitCh:
			if err != nil {
				return fmt.Errorf("failed to establish connection: %v", err)
			}
			core.Logger.Info().Msgf("✅ Camera responded successfully!")
			return nil
		case <-ticker.C:
			core.Logger.Debug().Msgf("⏳ Still waiting for camera response... (checking MQTT subscriptions)")
			core.Logger.Debug().Msgf("   Note: Protocol 4 messages (device status) indicate camera is online")
			core.Logger.Debug().Msgf("   Waiting for Protocol 302 WebRTC answer...")
		case <-timeout:
			core.Logger.Error().Msgf("❌ Timeout after 60 seconds - camera did not respond with Protocol 302 answer")
			core.Logger.Error().Msgf("   Note: Protocol 4 messages (device status) were received, confirming camera is online")
			core.Logger.Error().Msgf("   Possible issues:")
			core.Logger.Error().Msgf("   1) Camera may need TCP connection established first (using tcp_token)")
			core.Logger.Error().Msgf("   2) Camera may need a 'wake up' message before responding")
			core.Logger.Error().Msgf("   3) Offer format may need adjustment")
			core.Logger.Error().Msgf("   4) Camera may only respond when actively streaming")
			return errors.New("timeout waiting for WebRTC connection from camera - no Protocol 302 answer received")
		}
	}

}

func (wb *WebRTCBridge) Stop() {
	wb.mutex.Lock()
	if wb.stopped {
		wb.mutex.Unlock()
		return
	}
	wb.stopped = true
	wb.connected = false
	wb.mutex.Unlock()

	core.Logger.Info().Msgf("Stopping WebRTC bridge for camera: %s", wb.camera.DeviceName)

	// Cancel context to stop all goroutines
	wb.cancel()

	// Send disconnect
	if wb.cameraClient != nil {
		wb.cameraClient.SendDisconnect()
	}

	// Close peer connection
	if wb.peerConnection != nil {
		wb.peerConnection.Close()
	}
	if wb.tuyaKCPClient != nil {
		_ = wb.tuyaKCPClient.Close()
	}
	if wb.tuyaICEAgent != nil {
		_ = wb.tuyaICEAgent.Close()
	}
	if wb.nativeMqttClient != nil {
		wb.nativeMqttClient.Stop()
	}

	// Stop MQTT client
	if wb.mqttClient != nil {
		wb.mqttClient.Stop()
	}

	// Stop RTP forwarder
	if wb.rtpForwarder != nil {
		wb.rtpForwarder.Stop()
	}

	core.Logger.Info().Msgf("WebRTC bridge stopped for camera: %s", wb.camera.DeviceName)
}

func (wb *WebRTCBridge) IsConnected() bool {
	wb.mutex.RLock()
	defer wb.mutex.RUnlock()
	return wb.connected
}

func (wb *WebRTCBridge) ForwardBackchannelAudioPacket(packet *rtp.Packet) {
	if wb.backchannel != nil {
		_ = wb.backchannel.WriteRTP(packet)
	}
}

func (wb *WebRTCBridge) setupPeerConnection(webRTCConfig *tuya.WebRTCConfig) error {
	// Convert ICE servers
	iceServerBytes, err := json.Marshal(webRTCConfig.P2PConfig.Ices)
	if err != nil {
		return fmt.Errorf("failed to marshal ICE servers: %v", err)
	}

	iceServers, err := webrtc.UnmarshalICEServers(iceServerBytes)
	if err != nil {
		return fmt.Errorf("failed to unmarshal ICE servers: %v", err)
	}

	// Create peer connection configuration
	conf := pion.Configuration{
		ICEServers:         iceServers,
		ICETransportPolicy: pion.ICETransportPolicyAll,
		BundlePolicy:       pion.BundlePolicyMaxBundle,
	}

	// Create WebRTC API
	api, err := webrtc.NewAPI()
	if err != nil {
		return fmt.Errorf("failed to create WebRTC API: %v", err)
	}

	// Create peer connection
	wb.peerConnection, err = api.NewPeerConnection(conf)
	if err != nil {
		return fmt.Errorf("failed to create peer connection: %v", err)
	}

	// On HEVC, use DataChannel to receive video/audio
	if wb.isHEVC {
		maxRetransmits := uint16(5)
		ordered := true

		wb.dataChannel, err = wb.peerConnection.CreateDataChannel("fmp4Stream", &pion.DataChannelInit{
			MaxRetransmits: &maxRetransmits,
			Ordered:        &ordered,
		})

		wb.dataChannel.OnMessage(func(msg pion.DataChannelMessage) {
			if msg.IsString {
				if connected, err := wb.probe(msg); err != nil {
					wb.handleError(err)
				} else if connected {
					wb.waiter.Done(nil)
				}
			} else {
				packet := &rtp.Packet{}
				if err := packet.Unmarshal(msg.Data); err != nil {
					// skip
					return
				}

				switch packet.SSRC {
				case wb.rtpForwarder.videoSSRC:
					wb.rtpForwarder.ForwardVideoPacket(packet)
				case wb.rtpForwarder.audioSSRC:
					wb.rtpForwarder.ForwardAudioPacket(packet)
				}
			}
		})

		wb.dataChannel.OnError(func(err error) {
			wb.handleError(err)
		})

		wb.dataChannel.OnClose(func() {
			wb.handleError(errors.New("datachannel: closed"))
		})

		wb.dataChannel.OnOpen(func() {
			codecRequest, _ := json.Marshal(tuya.DataChannelMessage{
				Type: "codec",
				Msg:  "",
			})

			if err := wb.sendMessageToDataChannel(codecRequest); err != nil {
				wb.handleError(fmt.Errorf("failed to send codec request: %w", err))
			}
		})
	}

	// Setup connection state handler
	wb.peerConnection.OnConnectionStateChange(func(state pion.PeerConnectionState) {
		if state == pion.PeerConnectionStateFailed || state == pion.PeerConnectionStateClosed {
			wb.handleError(errors.New("WebRTC connection failed/closed"))
		}

		if state == pion.PeerConnectionStateConnected {
			core.Logger.Info().Msgf("WebRTC connection established")

			if !wb.isHEVC && wb.resolution == "hd" {
				_ = wb.cameraClient.SendResolution(0)
				wb.waiter.Done(nil)
			}
		}
	})

	// Setup track handler for incoming media if not HEVC
	wb.peerConnection.OnTrack(func(track *pion.TrackRemote, receiver *pion.RTPReceiver) {
		codec := track.Codec()
		core.Logger.Trace().Msgf("Received track: %s, PayloadType: %d", codec.MimeType, codec.PayloadType)

		if track.Kind() == pion.RTPCodecTypeVideo {
			wb.videoTrack = track

			if !wb.isHEVC {
				go wb.handleVideoTrack(track)
			}
		} else if track.Kind() == pion.RTPCodecTypeAudio {
			wb.audioTrack = track

			for _, tr := range wb.peerConnection.GetTransceivers() {
				if tr.Receiver() == receiver && tr.Kind() == pion.RTPCodecTypeAudio {
					if tr.Direction() == pion.RTPTransceiverDirectionSendrecv || tr.Direction() == pion.RTPTransceiverDirectionSendonly {
						localTrack, _ := pion.NewTrackLocalStaticRTP(
							pion.RTPCodecCapability{MimeType: track.Codec().MimeType},
							"audio-backchannel", "pion",
						)
						tr.Sender().ReplaceTrack(localTrack)
						wb.backchannel = localTrack
						core.Logger.Trace().Msgf("Setup backchannel track")
						break
					}
				}
			}

			if !wb.isHEVC {
				go wb.handleAudioTrack(track)
			}
		}
	})

	return nil
}

func (wb *WebRTCBridge) setupMQTTCameraClient(webRTCConfig *tuya.WebRTCConfig) {
	device := &tuya.Device{
		DeviceId:   wb.camera.DeviceID,
		DeviceName: wb.camera.DeviceName,
		Category:   wb.camera.Category,
		ProductId:  wb.camera.ProductID,
		Uuid:       wb.camera.UUID,
	}

	// Create MQTT camera client
	wb.cameraClient = tuya.NewMqttCameraClient(wb.mqttClient, device, webRTCConfig)
	wb.mqttClient.AddCameraClient(wb.cameraClient.SessionId, wb.cameraClient)

	// Setup handlers
	wb.cameraClient.HandleAnswer = func(answer tuya.AnswerFrame) {
		core.Logger.Trace().Msgf("Received WebRTC answer")
		core.Logger.Trace().Msgf("Answer SDP received (%d bytes)", len(answer.Sdp))

		desc := pion.SessionDescription{
			Type: pion.SDPTypePranswer,
			SDP:  answer.Sdp,
		}

		if err := wb.peerConnection.SetRemoteDescription(desc); err != nil {
			wb.handleError(err)
			return
		}

		if err := webrtc.SetAnswer(wb.peerConnection, answer.Sdp); err != nil {
			wb.handleError(err)
			return
		}
	}

	wb.cameraClient.HandleCandidate = func(candidate tuya.CandidateFrame) {
		candidateStr := strings.TrimSpace(candidate.Candidate)
		core.Logger.Trace().Msgf("Received ICE candidate: %s", candidateStr)

		if candidateStr != "" {
			// Remove "a=" prefix if present
			if strings.HasPrefix(candidateStr, "a=") {
				candidateStr = candidateStr[2:]
			}

			// Ensure candidate ends with CRLF
			if !strings.HasSuffix(candidateStr, "\r\n") && !strings.HasSuffix(candidateStr, "\n") {
				candidateStr = candidateStr + "\r\n"
			}

			core.Logger.Trace().Msgf("Adding ICE candidate: %s", strings.TrimSpace(candidateStr))

			if err := wb.peerConnection.AddICECandidate(pion.ICECandidateInit{
				Candidate: strings.TrimSpace(candidateStr),
			}); err != nil {
				wb.handleError(err)
			}
		}
	}

	wb.cameraClient.HandleError = func(err error) {
		wb.handleError(err)
	}

	wb.cameraClient.HandleDisconnect = func() {
		wb.handleError(errors.New("camera client disconnected"))
		wb.connected = false
	}
}

func (wb *WebRTCBridge) createAndSendOffer() error {
	// Native Tuya IMM signaling generates its own SDP in SendOffer. It must not
	// touch Pion: AES/KCP uses the native SDP credentials and direct UDP rather
	// than a WebRTC PeerConnection.
	if wb.isHardcodedCamera {
		if wb.nativeMqttClient == nil {
			return errors.New("native MQTT client unavailable for Tuya KCP offer")
		}
		if err := wb.nativeMqttClient.SendOffer(""); err != nil {
			return err
		}
		return wb.startTuyaICEAgent()
	}

	// For hardcoded cameras using Tuya KCP, we DON'T send pion's ICE candidates
	// They have a different ice-ufrag that doesn't match our Tuya SDP
	if !wb.isHardcodedCamera {
		wb.peerConnection.OnICECandidate(func(candidate *pion.ICECandidate) {
			if candidate != nil {
				core.Logger.Trace().Msgf("Generated ICE candidate: %s", candidate.ToJSON().Candidate)

				if wb.cameraClient != nil {
					if err := wb.cameraClient.SendCandidate("a=" + candidate.ToJSON().Candidate); err != nil {
						core.Logger.Error().Err(err).Msg("Error sending ICE candidate")
					}
				}
			}
		})
	} else {
		// For hardcoded cameras, log but don't send pion candidates
		wb.peerConnection.OnICECandidate(func(candidate *pion.ICECandidate) {
			if candidate != nil {
				core.Logger.Trace().Msgf("(Skipping pion ICE candidate for KCP): %s", candidate.ToJSON().Candidate)
			}
		})
	}

	medias := []*utils.Media{
		{Kind: utils.KindAudio, Direction: utils.DirectionSendRecv},
		{Kind: utils.KindVideo, Direction: utils.DirectionRecvonly},
	}

	// Create offer (still needed to initialize ICE gathering)
	offerSDP, err := webrtc.CreateOffer(wb.peerConnection, medias)
	if err != nil {
		return fmt.Errorf("failed to create offer: %v", err)
	}

	core.Logger.Trace().Msgf("Generated offer SDP: %s", offerSDP)

	// Send offer via MQTT
	if wb.nativeMqttClient != nil {
		core.Logger.Info().Msg("Sending Tuya KCP offer via Native MQTT...")
		if err := wb.nativeMqttClient.SendOffer(offerSDP); err != nil {
			return err
		}

		// For hardcoded cameras, start our Tuya ICE agent with matching credentials
		if wb.isHardcodedCamera {
			return wb.startTuyaICEAgent()
		}
		return nil
	} else if wb.cameraClient != nil {
		return wb.cameraClient.SendOffer(offerSDP, wb.resolution, wb.streamType, wb.isHEVC)
	}

	return errors.New("no MQTT client available to send offer")
}

// startKCPTunnel creates and starts a KCP client for direct UDP communication with the camera
func (wb *WebRTCBridge) startKCPTunnel(iceConn net.Conn) error {
	// Get AES key from MQTT client
	aesKey := wb.nativeMqttClient.TuyaAesKey
	if aesKey == "" {
		return errors.New("AES key not available")
	}

	core.Logger.Info().Msg("Starting direct KCP tunnel (bypassing Pion ICE)")

	// Extract camera's LAN address from ICE candidates
	// The camera sends a "host" candidate with its LAN IP and port
	cameraAddr, err := wb.extractCameraLANAddr()
	if err != nil {
		return fmt.Errorf("failed to extract camera LAN address: %v", err)
	}
	core.Logger.Info().Msgf("Using camera address: %s", cameraAddr)

	// The camera only accepts the local UDP tuple advertised in our trickle ICE
	// candidate. Free the Pion ICE socket once gathering is done, then bind KCP
	// to that exact host address and port. Snapshot the short-term credentials so
	// the replacement socket can perform the required STUN connectivity check.
	localAddr := ""
	var directICE tuya.DirectICEParams
	if iceConn != nil {
		localAddr = iceConn.LocalAddr().String()
	} else if wb.tuyaICEAgent != nil {
		directICE, err = wb.tuyaICEAgent.GetDirectICEParams()
		if err != nil {
			return fmt.Errorf("failed to snapshot direct ICE path: %v", err)
		}
		localAddr = directICE.LocalAddr
		if err := wb.tuyaICEAgent.Close(); err != nil {
			return fmt.Errorf("failed to release ICE UDP socket: %v", err)
		}
	}
	core.Logger.Info().Msgf("Using local address: %q", localAddr)

	// Create direct UDP KCP client (NOT over ICE, but direct to camera)
	config := tuya.GetHardcodedWebRTCConfig()
	cameraPassword := config.Password
	if cameraPassword == "" {
		cameraPassword = os.Getenv("PETSERIES_CAMERA_PASSWORD")
	}
	localKey := tuya.ActiveLocalKey()
	if v := os.Getenv("PETSERIES_LOCAL_KEY"); v != "" {
		localKey = v
	}
	kcpClient, err := tuya.NewTuyaKCPClient(cameraAddr, localAddr, aesKey, cameraPassword, localKey, directICE)
	if err != nil {
		return fmt.Errorf("failed to create KCP client: %v", err)
	}
	wb.tuyaKCPClient = kcpClient

	// AES/KCP delivers complete RTP packets after KCP reassembly. Preserve their
	// sequence/timestamp/marker fields so RTSP clients receive the camera's native
	// H.264 packetization instead of a synthetic HEVC wrapper.
	kcpClient.OnVideoRTP = wb.rtpForwarder.ForwardVideoPacket
	kcpClient.OnAudioRTP = wb.rtpForwarder.ForwardAudioPacket

	kcpClient.OnError = func(err error) {
		core.Logger.Error().Err(err).Msg("KCP client error")
		wb.handleError(err)
	}

	// Start the KCP client (performs handshake, then reads media)
	if err := kcpClient.Start(); err != nil {
		return fmt.Errorf("failed to start KCP client: %v", err)
	}

	core.Logger.Info().Msg("Direct UDP KCP tunnel started successfully, receiving media")
	return nil
}

// extractCameraLANAddr extracts the camera's LAN address from the Tuya ICE agent's remote candidates
// Returns e.g. "192.168.1.50:42941"
func (wb *WebRTCBridge) extractCameraLANAddr() (string, error) {
	if wb.tuyaICEAgent == nil {
		return "", errors.New("Tuya ICE agent not available")
	}

	// Get the remote candidates that were added
	// We need to find the "host" type candidate with the LAN address
	// The candidates are in format: "candidate:... 192.168.1.50 42941 typ host ..."

	remoteCandidates := wb.tuyaICEAgent.GetRemoteCandidates()
	if len(remoteCandidates) == 0 {
		return "", errors.New("no remote candidates available")
	}

	// Look for host candidate (highest priority)
	for _, candidate := range remoteCandidates {
		if candidate.Type().String() == "host" {
			addr := candidate.Address()
			port := candidate.Port()
			if addr != "" && port > 0 {
				cameraAddr := fmt.Sprintf("%s:%d", addr, port)
				core.Logger.Info().Msgf("Found camera host candidate: %s", cameraAddr)
				return cameraAddr, nil
			}
		}
	}

	return "", errors.New("no host candidate found in remote ICE candidates")
}

// forwardHEVCData writes HEVC NAL data to the RTSP stream
func (wb *WebRTCBridge) forwardHEVCData(hevcData []byte) error {
	if len(hevcData) < 4 {
		return fmt.Errorf("HEVC data too short")
	}

	// The HEVC data should start with 00000001 (4-byte NAL start code) or 000001 (3-byte)
	// Convert to RTP packets and forward to all connected RTSP clients

	// For now, we'll implement a basic single-packet handler
	// A real implementation would need to handle fragmentation and proper RTP headers

	// Create an RTP packet with HEVC payload
	packet := &rtp.Packet{
		Header: rtp.Header{
			Version:        2,
			Padding:        false,
			Extension:      false,
			Marker:         true, // Mark as end of frame for now
			PayloadType:    96,   // Dynamic RTP payload type for H.265/HEVC
			SequenceNumber: uint16(time.Now().UnixNano() & 0xFFFF),
			Timestamp:      uint32((time.Now().UnixNano() / 1e6) & 0xFFFFFFFF), // milliseconds
			SSRC:           wb.rtpForwarder.videoSSRC,
			CSRC:           []uint32{},
		},
		Payload: hevcData,
	}

	// Forward to RTP forwarder (which sends to all RTSP clients)
	wb.rtpForwarder.ForwardVideoPacket(packet)

	return nil
}

// min is a helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// startTuyaICEAgent initializes and starts the Tuya ICE agent with matching credentials
func (wb *WebRTCBridge) startTuyaICEAgent() error {
	if wb.nativeMqttClient == nil {
		return errors.New("native MQTT client not available")
	}

	// Get credentials from the MQTT client (they were set in SendOffer)
	iceUfrag := wb.nativeMqttClient.TuyaIceUfrag
	icePwd := wb.nativeMqttClient.TuyaIcePwd

	if iceUfrag == "" || icePwd == "" {
		return errors.New("Tuya ICE credentials not available")
	}

	core.Logger.Info().Msgf("Starting Tuya ICE agent with ufrag=%s", iceUfrag)

	// Get STUN/TURN servers from hardcoded config
	hcConfig := tuya.GetHardcodedWebRTCConfig()
	var stunServers []string
	var turnServers []tuya.TurnServer

	for _, ice := range hcConfig.P2PConfig.Ices {
		if strings.HasPrefix(ice.Urls, "stun:") {
			stunServers = append(stunServers, ice.Urls)
		} else if strings.HasPrefix(ice.Urls, "turn:") {
			turnServers = append(turnServers, tuya.TurnServer{
				URL:        ice.Urls,
				Username:   ice.Username,
				Credential: ice.Credential,
			})
		}
	}

	// Create ICE agent
	agent, err := tuya.NewTuyaICEAgent(iceUfrag, icePwd, stunServers, turnServers)
	if err != nil {
		return fmt.Errorf("failed to create Tuya ICE agent: %v", err)
	}
	wb.tuyaICEAgent = agent

	// Set callback to send candidates via MQTT
	agent.OnLocalCandidate = func(candidate string) {
		if err := wb.nativeMqttClient.SendTuyaCandidate(candidate); err != nil {
			core.Logger.Error().Err(err).Msg("Error sending Tuya ICE candidate")
		}
	}

	// CRITICAL: Set callback to send empty candidate when ICE gathering is complete
	// (The app does this to signal end of candidates)
	agent.OnGatheringComplete = func() {
		if err := wb.nativeMqttClient.SendEmptyCandidate(); err != nil {
			core.Logger.Error().Err(err).Msg("Error sending empty candidate")
		}
	}

	// Start the ICE agent
	if err := agent.Start(wb.ctx); err != nil {
		return fmt.Errorf("failed to start Tuya ICE agent: %v", err)
	}

	core.Logger.Info().Msg("Tuya ICE agent started, gathering candidates...")
	return nil
}

func (wb *WebRTCBridge) handleVideoTrack(track *pion.TrackRemote) {
	core.Logger.Trace().Msgf("Starting video track handler")

	for {
		select {
		case <-wb.ctx.Done():
			return
		default:
			packet, _, err := track.ReadRTP()
			if err != nil {
				if err == io.EOF {
					return
				}
				// Check if it's a known close error
				if strings.Contains(err.Error(), "closed") ||
					strings.Contains(err.Error(), "EOF") ||
					strings.Contains(err.Error(), "use of closed network connection") {
					return
				}
				core.Logger.Warn().Err(err).Msg("Unexpected error reading video RTP packet")
				time.Sleep(10 * time.Millisecond)
				continue
			}

			wb.rtpForwarder.ForwardVideoPacket(packet)
		}
	}
}

func (wb *WebRTCBridge) handleAudioTrack(track *pion.TrackRemote) {
	core.Logger.Trace().Msgf("Starting audio track handler")

	for {
		select {
		case <-wb.ctx.Done():
			return
		default:
			packet, _, err := track.ReadRTP()
			if err != nil {
				if err == io.EOF {
					return
				}
				if strings.Contains(err.Error(), "closed") ||
					strings.Contains(err.Error(), "EOF") ||
					strings.Contains(err.Error(), "use of closed network connection") {
					return
				}
				core.Logger.Warn().Err(err).Msg("Unexpected error reading audio RTP packet")
				time.Sleep(10 * time.Millisecond)
				continue
			}

			wb.rtpForwarder.ForwardAudioPacket(packet)
		}
	}
}

func (wb *WebRTCBridge) createHTTPClient() *http.Client {
	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		return nil
	}

	if wb.user.SessionData != nil && len(wb.user.SessionData.Cookies) > 0 {
		serverURL, _ := url.Parse(fmt.Sprintf("https://%s", wb.user.SessionData.ServerHost))

		var httpCookies []*http.Cookie
		for _, cookie := range wb.user.SessionData.Cookies {
			httpCookies = append(httpCookies, &http.Cookie{
				Name:     cookie.Name,
				Value:    cookie.Value,
				Domain:   cookie.Domain,
				Path:     cookie.Path,
				Expires:  cookie.Expires,
				Secure:   cookie.Secure,
				HttpOnly: cookie.HttpOnly,
			})
		}

		jar.SetCookies(serverURL, httpCookies)
	}

	return &http.Client{
		Timeout: 30 * time.Second,
		Jar:     jar,
	}
}

func (wb *WebRTCBridge) probe(msg pion.DataChannelMessage) (bool, error) {
	var message tuya.DataChannelMessage
	if err := json.Unmarshal([]byte(msg.Data), &message); err != nil {
		return false, err
	}

	switch message.Type {
	case "codec":
		frameRequest, _ := json.Marshal(tuya.DataChannelMessage{
			Type: "start",
			Msg:  "frame",
		})

		err := wb.sendMessageToDataChannel(frameRequest)
		if err != nil {
			return false, err
		}

	case "recv":
		var recvMessage tuya.RecvMessage
		if err := json.Unmarshal([]byte(message.Msg), &recvMessage); err != nil {
			return false, err
		}

		wb.rtpForwarder.videoSSRC = recvMessage.Video.SSRC
		wb.rtpForwarder.audioSSRC = recvMessage.Audio.SSRC

		completeMsg, _ := json.Marshal(tuya.DataChannelMessage{
			Type: "complete",
			Msg:  "",
		})

		err := wb.sendMessageToDataChannel(completeMsg)
		if err != nil {
			return false, err
		}

		return true, nil
	}

	return false, nil
}

func (wb *WebRTCBridge) sendMessageToDataChannel(message []byte) error {
	if wb.dataChannel != nil {
		return wb.dataChannel.Send(message)
	}

	return nil
}

func (wb *WebRTCBridge) handleError(err error) {
	if wb.OnError != nil {
		wb.waiter.Done(err)
		wb.OnError(err)
	}
}
