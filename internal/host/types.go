package host

import (
	"encoding/json"
	"errors"
)

// Event is something the app tells the core.
type Event struct {
	Name string          `json:"event"`
	Data json.RawMessage `json:"data,omitempty"`
}

// ErrNoHost: the core runs without the app (development).
var ErrNoHost = errors.New("нет связи с приложением Android")

// TunParams describe the VPN interface the app should create.
type TunParams struct {
	Session     string   `json:"session"`
	MTU         int      `json:"mtu"`
	Address4    string   `json:"address4"` // "198.18.0.1/30"
	Address6    string   `json:"address6"` // captures IPv6 so it cannot leak past the VPN
	DNS         string   `json:"dns"`
	BypassApps  []string `json:"bypass_apps"` // package names that skip the VPN
	AllowBypass bool     `json:"allow_bypass"`
}

// Status is the line in the notification.
type Status struct {
	Mode   string `json:"mode"` // on | off | busy | err
	Title  string `json:"title"`
	Text   string `json:"text"`
	VPNOn  bool   `json:"vpn_on"`
	DPIOn  bool   `json:"dpi_on"`
	Notify bool   `json:"notify,omitempty"` // a one-off message, not the status
	Warn   bool   `json:"warn,omitempty"`
}

// AppInfo is an installed application.
type AppInfo struct {
	Package string `json:"package"`
	Label   string `json:"label"`
	System  bool   `json:"system"`
}
