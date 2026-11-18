package app

import (
	"time"

	"lazeyka/internal/logx"
	"lazeyka/internal/platform"
)

// Microsoft Defender's machine-learning check takes Лазейка for malware now
// and then (an unsigned program that installs itself, creates scheduled
// tasks, downloads programs and loads a driver: zapret's WinDivert), and
// quarantines it or the engines. Лазейка keeps its own folder out of
// Defender's scans; only administrators can write there, so nothing else
// hides in it. Updates arrive straight into that folder (selfupdate.go), so
// they are not scanned or held up by SmartScreen either.

// DefenderView answers /api/defender.
type DefenderView struct {
	Supported bool      `json:"supported"`
	Want      bool      `json:"want"` // the folder should be excluded
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
	v.Want = !a.Settings().App.ScanByDefender
	if v.Supported && !busy && time.Since(v.At) > 5*time.Minute {
		go a.applyDefender()
	}
	return v
}

// applyDefender makes Defender's exclusions match the setting.
func (a *App) applyDefender() {
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

	want := !a.Settings().App.ScanByDefender
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
	if want != st.Excluded {
		if err := platform.SetDefenderExclusion(a.P.Root, want); err != nil {
			v.Error = err.Error()
			logx.Warnf("Защитник Windows: не удалось изменить исключения: %v", err)
		} else {
			v.Excluded = want
			if want {
				logx.Infof("папка %s добавлена в исключения Защитника Windows", a.P.Root)
			} else {
				logx.Infof("папка %s убрана из исключений Защитника Windows: он снова её проверяет", a.P.Root)
			}
		}
	}
	if want && !st.Active {
		logx.Infof("Защитник Windows не основной антивирус (режим «%s»): если ваш антивирус мешает Лазейке, добавьте %s в исключения в нём самом", st.Mode, a.P.Root)
	}
	a.setDefender(v)
}

func (a *App) setDefender(v DefenderView) {
	a.mu.Lock()
	a.defender = v
	a.mu.Unlock()
}

// RemoveDefenderExclusion is part of uninstalling.
func RemoveDefenderExclusion(p Paths) {
	if !platform.IsWindows {
		return
	}
	if st, err := platform.DefenderStatus(p.Root); err == nil && st.Excluded {
		if err := platform.SetDefenderExclusion(p.Root, false); err != nil {
			logx.Warnf("Защитник Windows: %v", err)
		}
	}
}
