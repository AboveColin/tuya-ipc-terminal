package tuya

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"tuya-ipc-terminal/pkg/core"
)

// The creds sidecar (creds_sidecar.py) reuses the working petsseries mobile
// session to serve *fresh* WebRTC signaling config, replacing the static
// hardcoded values. This is what lets the bridge survive motoId rotation.

// MQTTCredentials holds the MQTT connection parameters returned by the sidecar
type MQTTCredentials struct {
	Broker         string `json:"broker"`
	ClientID       string `json:"client_id"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	PublishTopic   string `json:"publish_topic"`
	SubscribeTopic string `json:"subscribe_topic"`
	UID            string `json:"uid"`
}

var (
	activeMu        sync.RWMutex
	activeConfig    *WebRTCConfig
	activeLocalKey  string
	activeMQTTCreds *MQTTCredentials
)

func sidecarURL() string {
	if v := os.Getenv("PETSERIES_CREDS_SIDECAR"); v != "" {
		return v
	}
	return "http://127.0.0.1:8766"
}

func signalingTopics(deviceID string) (publish, subscribe string) {
	return fmt.Sprintf("smart/mb/out/%s", deviceID),
		fmt.Sprintf("smart/mb/in/%s", deviceID)
}

// RefreshFromSidecar fetches live WebRTC credentials for deviceID and caches
// them. The Home Assistant bridge requires this dynamic source; distributable
// binaries contain no static account or camera credential fallback.
func RefreshFromSidecar(deviceID string) (*WebRTCConfig, error) {
	url := fmt.Sprintf("%s/webrtc?devId=%s", sidecarURL(), deviceID)
	client := &http.Client{Timeout: 20 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if token := os.Getenv("PETSERIES_SIDECAR_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("creds sidecar unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("creds sidecar HTTP %d: %s", resp.StatusCode, string(body))
	}

	// The sidecar returns the raw thing.m.ipc.rtc.config.get result (plus a
	// merged localKey), whose JSON matches WebRTCConfig one-to-one.
	var cfg WebRTCConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, fmt.Errorf("decode sidecar config: %w", err)
	}
	if cfg.MotoId == "" && cfg.P2PConfig.MotoId == "" {
		return nil, fmt.Errorf("sidecar config missing motoId")
	}

	// Extract localKey and MQTT credentials
	var parsed struct {
		LocalKey string          `json:"localKey"`
		MQTT     MQTTCredentials `json:"mqtt"`
	}
	_ = json.Unmarshal(body, &parsed)

	// WebRTC protocol 302 always addresses the camera device. Do not trust
	// account/control-channel topic hints returned alongside the credentials:
	// those use the opposite direction and are keyed by the mobile account UID.
	parsed.MQTT.PublishTopic, parsed.MQTT.SubscribeTopic = signalingTopics(deviceID)

	activeMu.Lock()
	activeConfig = &cfg
	if parsed.LocalKey != "" {
		activeLocalKey = parsed.LocalKey
	}
	if parsed.MQTT.Broker != "" {
		// Ensure required fields have defaults
		activeMQTTCreds = &parsed.MQTT
		core.Logger.Info().Msgf("Cached fresh MQTT credentials from sidecar (broker=%s, client_id_len=%d)",
			parsed.MQTT.Broker, len(parsed.MQTT.ClientID))
	}
	activeMu.Unlock()

	core.Logger.Info().Msgf("Refreshed WebRTC config from sidecar (motoId=%s)", cfg.MotoId)
	return &cfg, nil
}

// GetHardcodedWebRTCConfig returns the live sidecar config if one has been
// fetched, otherwise the static fallback. Name kept for the
// existing call sites.
func GetHardcodedWebRTCConfig() *WebRTCConfig {
	activeMu.RLock()
	cfg := activeConfig
	activeMu.RUnlock()
	if cfg != nil {
		return cfg
	}
	return staticWebRTCConfig()
}

// ActiveLocalKey returns the localKey from the last sidecar refresh, falling
// back to the hardcoded value.
func ActiveLocalKey() string {
	activeMu.RLock()
	lk := activeLocalKey
	activeMu.RUnlock()
	if lk != "" {
		return lk
	}
	return HardcodedLocalKey
}

// ActiveMQTTCredentials returns the MQTT credentials from the last sidecar
// refresh, or nil if none has been fetched. Falls back to hardcoded credentials
// if needed.
func ActiveMQTTCredentials() *MQTTCredentials {
	activeMu.RLock()
	creds := activeMQTTCreds
	activeMu.RUnlock()

	if creds != nil {
		// Return a copy to prevent accidental mutation
		cp := *creds
		return &cp
	}

	// Fallback to hardcoded credentials
	return &MQTTCredentials{
		Broker:   HardcodedMQTTBroker,
		ClientID: HardcodedMQTTClientID,
		Username: HardcodedMQTTUsername,
		Password: HardcodedMQTTPassword,
		UID:      HardcodedUID,
	}
}
