package main

import (
	"crypto/x509"
	"encoding/pem"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type caPublicState struct {
	CAEnabled      bool      `json:"ca_enabled"`
	CAOrganization string    `json:"ca_org,omitempty"`
	CACertPath     string    `json:"ca_cert_path,omitempty"`
	CANotBefore    time.Time `json:"ca_not_before,omitempty"`
	CANotAfter     time.Time `json:"ca_not_after,omitempty"`
}

type mitmController struct {
	mu      sync.RWMutex
	handler *connectHandler
	core    *proxyCore
	logger  *log.Logger
	events  *eventHub
}

func newMITMController(core *proxyCore, handler *connectHandler, logger *log.Logger, events *eventHub) *mitmController {
	if logger == nil {
		logger = log.Default()
	}
	return &mitmController{handler: handler, core: core, logger: logger, events: events}
}

func (m *mitmController) serve(w http.ResponseWriter, r *http.Request) {
	m.mu.RLock()
	handler := m.handler
	m.mu.RUnlock()
	if handler == nil {
		http.Error(w, "CONNECT tunneling is not enabled", http.StatusNotImplemented)
		return
	}
	handler.serve(w, r)
}

func (m *mitmController) setEnabled(enabled bool) (caPublicState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if enabled && m.handler == nil {
		cfg, err := configuredConnectConfig()
		if err != nil {
			return caPublicState{}, err
		}
		ca, err := newCertAuthority(cfg.caDir, cfg.caOrg)
		if err != nil {
			return caPublicState{}, err
		}
		m.handler = newConnectHandler(ca, m.core, cfg, m.logger)
	} else if !enabled && m.handler != nil {
		handler := m.handler
		m.handler = nil
		handler.closeAll()
	}

	state := m.publicStateLocked()
	if m.events != nil {
		m.events.publishState(state)
	}
	return state, nil
}

func (m *mitmController) publicState() caPublicState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.publicStateLocked()
}

func (m *mitmController) publicStateLocked() caPublicState {
	caDir := strings.TrimSpace(os.Getenv("PROXYGO_CA_DIR"))
	organization := strings.TrimSpace(os.Getenv("PROXYGO_CA_ORG"))
	if caDir == "" {
		caDir = defaultCADir
	}
	if organization == "" {
		organization = defaultCAOrg
	}
	state := caPublicState{CAEnabled: m.handler != nil, CAOrganization: organization, CACertPath: filepath.Join(caDir, "ca.crt")}
	if m.handler != nil {
		caDir = m.handler.cfg.caDir
		organization = m.handler.cfg.caOrg
		state.CACertPath = filepath.Join(caDir, "ca.crt")
		state.CAOrganization = organization
	}
	data, err := os.ReadFile(state.CACertPath)
	if err != nil {
		return state
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return state
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return state
	}
	if len(cert.Subject.Organization) > 0 {
		state.CAOrganization = cert.Subject.Organization[0]
	}
	state.CANotBefore = cert.NotBefore.UTC()
	state.CANotAfter = cert.NotAfter.UTC()
	return state
}
