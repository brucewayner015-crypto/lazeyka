package app

import (
	"time"

	"lazeyka/internal/logx"
	"lazeyka/internal/platform"
)

// Microsoft Defender's machine-learning check sometimes takes Лазейка and
// zapret's WinDivert driver for malware. The honest fix is for the user to
// add Лазейка's folder to Defender's exclusions themselves (the window and
// settings show the one command to run). Лазейка only *reads* Defender's
// state, to tell the user whether the exclusion is already there; it never
// changes antivirus settings on its own.

// DefenderView answers /api/defender.
type DefenderView struct {
	Supported bool      `json:"supported"`
	Checked   bool      `json:"checked"`
	Active    bool      `json:"active"` // Defender is the antivirus in charge
	Excluded  bool      `json:"excluded"`
	Mode      string    `json:"mode,omitempty"`
	Error     string    `json:"error,omitempty"`
	At        time.Time `json:"at"`
}

// Defender reports the last known state and refreshes it in the background
// when it is old.
func (a *App) Defender() DefenderView {
	a.mu.Lock()
	v := a.defender
	busy := a.defenderBusy
	a.mu.Unlock()
	v.Supported = platform.IsWindows && !a.Dev
	if v.Supported && !busy && time.Since(v.At) > 5*time.Minute {
		go a.refreshDefender()
	}
	return v
}

// refreshDefender reads Defender's state (read-only) and caches it.
func (a *App) refreshDefender() {
	if !platform.IsWindows || a.Dev {
		return
	}
	a.mu.Lock()
	if a.defenderBusy {
		a.mu.Unlock()
		return
	}
	a.defenderBusy = true
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.defenderBusy = false
		a.mu.Unlock()
	}()

	v := DefenderView{At: time.Now()}
	st, err := platform.DefenderStatus(a.P.Root)
	if err != nil {
		// no Defender (removed by another antivirus) or it refuses to answer
		v.Error = err.Error()
		logx.Debugf("Защитник Windows: %v", err)
		a.setDefender(v)
		return
	}
	v.Checked, v.Active, v.Excluded, v.Mode = true, st.Active, st.Excluded, st.Mode
	a.setDefender(v)
}

func (a *App) setDefender(v DefenderView) {
	a.mu.Lock()
	a.defender = v
	a.mu.Unlock()
}
