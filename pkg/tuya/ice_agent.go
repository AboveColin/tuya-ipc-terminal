package tuya

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
	"tuya-ipc-terminal/pkg/core"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v3"
)

// TuyaICEAgent handles ICE connectivity for Tuya KCP protocol
type TuyaICEAgent struct {
	agent              *ice.Agent
	iceUfrag           string
	icePwd             string
	remoteUfrag        string
	remotePwd          string
	conn               *ice.Conn
	stunServers        []string
	turnServers        []TurnServer
	localCandidates    []string
	localCandidateObjs []ice.Candidate
	remoteCandidates   []ice.Candidate
	connected          bool
	mu                 sync.Mutex

	// Callback for sending candidates via MQTT
	OnLocalCandidate func(candidate string)
	// Callback when ICE gathering is complete (to send empty candidate)
	OnGatheringComplete func()
}

// DirectICEParams contains the short-term credentials and local candidate data
// needed to continue ICE checks after replacing Pion's gathering socket with the
// direct Tuya AES/KCP socket.
type DirectICEParams struct {
	LocalAddr   string
	LocalUfrag  string
	LocalPwd    string
	RemoteUfrag string
	RemotePwd   string
	Priority    uint32
}

// TurnServer represents TURN server credentials
type TurnServer struct {
	URL        string
	Username   string
	Credential string
}

// NewTuyaICEAgent creates a new ICE agent for Tuya KCP protocol
func NewTuyaICEAgent(iceUfrag, icePwd string, stunServers []string, turnServers []TurnServer) (*TuyaICEAgent, error) {
	agent := &TuyaICEAgent{
		iceUfrag:    iceUfrag,
		icePwd:      icePwd,
		stunServers: stunServers,
		turnServers: turnServers,
	}

	return agent, nil
}

// Start initializes the ICE agent and begins gathering candidates
func (a *TuyaICEAgent) Start(ctx context.Context) error {
	// Configure STUN/TURN servers
	var urls []*stun.URI

	for _, s := range a.stunServers {
		// Parse STUN URL (e.g., "stun:51.75.92.250:3478")
		stunURL := strings.TrimPrefix(s, "stun:")
		host, port, err := net.SplitHostPort(stunURL)
		if err != nil {
			host = stunURL
			port = "3478"
		}
		urls = append(urls, &stun.URI{
			Scheme: stun.SchemeTypeSTUN,
			Host:   host,
			Port:   parseInt(port),
		})
		core.Logger.Debug().Msgf("Added STUN server: %s:%s", host, port)
	}

	for _, t := range a.turnServers {
		// Parse TURN URL (e.g., "turn:51.75.92.36:3478")
		turnURL := strings.TrimPrefix(t.URL, "turn:")
		host, port, err := net.SplitHostPort(turnURL)
		if err != nil {
			host = turnURL
			port = "3478"
		}
		urls = append(urls, &stun.URI{
			Scheme:   stun.SchemeTypeTURN,
			Host:     host,
			Port:     parseInt(port),
			Username: t.Username,
			Password: t.Credential,
			Proto:    stun.ProtoTypeUDP,
		})
		core.Logger.Debug().Msgf("Added TURN server: %s:%s (username_len=%d)", host, port, len(t.Username))
	}

	// Create ICE agent with our custom credentials
	agentConfig := &ice.AgentConfig{
		NetworkTypes:       []ice.NetworkType{ice.NetworkTypeUDP4, ice.NetworkTypeUDP6},
		CandidateTypes:     []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive, ice.CandidateTypeRelay},
		LocalUfrag:         a.iceUfrag,
		LocalPwd:           a.icePwd,
		Urls:               urls,
		InsecureSkipVerify: true,
	}

	agent, err := ice.NewAgent(agentConfig)
	if err != nil {
		return fmt.Errorf("failed to create ICE agent: %v", err)
	}
	a.agent = agent

	// Set up candidate handler
	err = a.agent.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			core.Logger.Debug().Msg("ICE gathering complete")
			// CRITICAL: Signal gathering complete by calling callback
			if a.OnGatheringComplete != nil {
				a.OnGatheringComplete()
			}
			return
		}

		// Marshal returns the candidate string without "candidate:" prefix
		// We need to add "a=candidate:" for the full SDP attribute format
		candidateStr := "a=candidate:" + c.Marshal()
		core.Logger.Debug().Msgf("ICE local candidate: %s", candidateStr)

		a.mu.Lock()
		a.localCandidates = append(a.localCandidates, candidateStr)
		a.localCandidateObjs = append(a.localCandidateObjs, c)
		a.mu.Unlock()

		// Send candidate via MQTT
		if a.OnLocalCandidate != nil {
			a.OnLocalCandidate(candidateStr)
		}
	})
	if err != nil {
		return fmt.Errorf("failed to set candidate handler: %v", err)
	}

	// Set up connection state handler
	err = a.agent.OnConnectionStateChange(func(state ice.ConnectionState) {
		core.Logger.Info().Msgf("ICE connection state: %s", state.String())
		if state == ice.ConnectionStateConnected {
			a.mu.Lock()
			a.connected = true
			a.mu.Unlock()
		} else if state == ice.ConnectionStateFailed || state == ice.ConnectionStateDisconnected {
			a.mu.Lock()
			a.connected = false
			a.mu.Unlock()
		}
	})
	if err != nil {
		return fmt.Errorf("failed to set connection state handler: %v", err)
	}

	// Start gathering candidates
	err = a.agent.GatherCandidates()
	if err != nil {
		return fmt.Errorf("failed to gather candidates: %v", err)
	}

	core.Logger.Info().Msg("ICE agent started, gathering candidates...")
	return nil
}

// AddRemoteCandidate adds a remote ICE candidate from the camera
func (a *TuyaICEAgent) AddRemoteCandidate(candidateStr string) error {
	// Remove "a=" prefix if present
	candidateStr = strings.TrimPrefix(candidateStr, "a=")
	candidateStr = strings.TrimSpace(candidateStr)

	if candidateStr == "" {
		return nil
	}

	candidate, err := ice.UnmarshalCandidate(candidateStr)
	if err != nil {
		return fmt.Errorf("failed to parse candidate: %v", err)
	}

	a.mu.Lock()
	a.remoteCandidates = append(a.remoteCandidates, candidate)
	a.mu.Unlock()

	err = a.agent.AddRemoteCandidate(candidate)
	if err != nil {
		return fmt.Errorf("failed to add remote candidate: %v", err)
	}

	core.Logger.Debug().Msgf("Added remote ICE candidate: %s", candidateStr)
	return nil
}

// SetRemoteCredentials sets the remote ICE credentials from the camera's answer
func (a *TuyaICEAgent) SetRemoteCredentials(ufrag, pwd string) {
	a.mu.Lock()
	a.remoteUfrag = ufrag
	a.remotePwd = pwd
	a.mu.Unlock()
	core.Logger.Debug().Msgf("Set remote ICE credentials: ufrag=%s", ufrag)
}

// Connect establishes the ICE connection (as controlling agent)
func (a *TuyaICEAgent) Connect(ctx context.Context, timeout time.Duration) (net.Conn, error) {
	a.mu.Lock()
	remoteUfrag := a.remoteUfrag
	remotePwd := a.remotePwd
	a.mu.Unlock()

	if remoteUfrag == "" || remotePwd == "" {
		return nil, fmt.Errorf("remote credentials not set")
	}

	connectCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Accept the connection (we're the controlling agent since we sent the offer)
	conn, err := a.agent.Accept(connectCtx, remoteUfrag, remotePwd)
	if err != nil {
		return nil, fmt.Errorf("ICE connection failed: %v", err)
	}

	a.conn = conn
	core.Logger.Info().Msg("ICE connection established!")
	return conn, nil
}

// GetConnection returns the established ICE connection
func (a *TuyaICEAgent) GetConnection() net.Conn {
	return a.conn
}

// GetRemoteCandidates returns the list of remote ICE candidates from the camera
func (a *TuyaICEAgent) GetRemoteCandidates() []ice.Candidate {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.remoteCandidates
}

// GetLocalHostCandidateAddr returns the host socket advertised to the camera.
// The direct AES/KCP socket must reuse this exact 5-tuple after ICE gathering;
// an unrelated ephemeral port is not accepted by the camera.
func (a *TuyaICEAgent) GetLocalHostCandidateAddr() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, candidate := range a.localCandidateObjs {
		if candidate.Type() == ice.CandidateTypeHost {
			return net.JoinHostPort(candidate.Address(), fmt.Sprint(candidate.Port())), nil
		}
	}
	return "", fmt.Errorf("no local host ICE candidate available")
}

// GetDirectICEParams snapshots the host candidate and both sides' ICE
// credentials before the gathering agent is closed. No secret values are logged.
func (a *TuyaICEAgent) GetDirectICEParams() (DirectICEParams, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.remoteUfrag == "" || a.remotePwd == "" {
		return DirectICEParams{}, fmt.Errorf("remote ICE credentials unavailable")
	}
	for _, candidate := range a.localCandidateObjs {
		if candidate.Type() == ice.CandidateTypeHost {
			return DirectICEParams{
				LocalAddr:   net.JoinHostPort(candidate.Address(), fmt.Sprint(candidate.Port())),
				LocalUfrag:  a.iceUfrag,
				LocalPwd:    a.icePwd,
				RemoteUfrag: a.remoteUfrag,
				RemotePwd:   a.remotePwd,
				Priority:    candidate.Priority(),
			}, nil
		}
	}
	return DirectICEParams{}, fmt.Errorf("no local host ICE candidate available")
}

// IsConnected returns whether ICE is connected
func (a *TuyaICEAgent) IsConnected() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.connected
}

// Close closes the ICE agent
func (a *TuyaICEAgent) Close() error {
	if a.agent != nil {
		return a.agent.Close()
	}
	return nil
}

// parseInt converts string to int with default
func parseInt(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}

// ParseICECredentialsFromSDP extracts ice-ufrag and ice-pwd from an SDP
func ParseICECredentialsFromSDP(sdp string) (ufrag, pwd string) {
	for _, line := range strings.Split(sdp, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "a=ice-ufrag:") {
			ufrag = strings.TrimPrefix(line, "a=ice-ufrag:")
		} else if strings.HasPrefix(line, "a=ice-pwd:") {
			pwd = strings.TrimPrefix(line, "a=ice-pwd:")
		}
	}
	return
}

// ParseMediaAESKeyFromSDP returns the negotiated 16-byte AES/KCP key. The
// camera is allowed to replace the offer key in its answer, and that answer key
// is the one the media channel must use.
func ParseMediaAESKeyFromSDP(sdp string) (string, error) {
	for _, line := range strings.Split(sdp, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "a=aes-key:") {
			continue
		}
		key := strings.TrimSpace(strings.TrimPrefix(line, "a=aes-key:"))
		raw, err := hex.DecodeString(key)
		if err != nil || len(raw) != 16 {
			return "", fmt.Errorf("answer SDP contains an invalid AES/KCP key")
		}
		return key, nil
	}
	return "", fmt.Errorf("answer SDP is missing a=aes-key")
}
