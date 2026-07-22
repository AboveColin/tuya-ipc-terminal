package tuya

import "os"

// Legacy names are retained for existing call sites, but the distributable
// bridge contains no account or camera credentials. All session material is
// supplied just-in-time by the authenticated Home Assistant sidecar.
var HardcodedMQTTBroker = "ssl://m1.tuyaeu.com:8883"
var HardcodedMQTTClientID = ""
var HardcodedMQTTUsername = ""
var HardcodedMQTTPassword = ""
var HardcodedMQTTPasswordBinary = ""
var HardcodedUID = ""
var HardcodedDeviceID = ""
var HardcodedLocalKey = ""
var OtherLocalKey = ""

func staticWebRTCConfig() *WebRTCConfig {
	return &WebRTCConfig{}
}

// IsHardcodedDevice is kept as a compatibility name for the bridge-specific
// protocol path. The selected device is dynamic and never compiled in.
func IsHardcodedDevice(deviceID string) bool {
	return deviceID != "" && deviceID == BridgeDeviceID()
}

// BridgeDeviceID returns the camera selected by the embedding application.
func BridgeDeviceID() string {
	return os.Getenv("PETSERIES_DEVICE_ID")
}
