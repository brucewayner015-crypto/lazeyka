package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	"lazeyka/internal/logx"
	"lazeyka/internal/zapret"
)

// Results of strategy checks outlive the program (zapret-scores.json), so the
// strategy lists show which strategies worked here without a new run.

// RankedStrategy is a zapret strategy with what its last check showed.
type RankedStrategy struct {
	File    string `json:"file"`
	Name    string `json:"name"`
	Checked bool   `json:"checked"`
	OK      int    `json:"ok"`
	Total   int    `json:"total"`
	YouTube int    `json:"youtube"`
	Discord int    `json:"discord"`
	AvgMs   int    `json:"avg_ms"`
	Failed  string `json:"failed,omitempty"` // did not start
}

// Works: opened at least something in its last check.
func (r RankedStrategy) Works() bool { return r.Checked && r.Failed == "" && r.OK > 0 }

// StrategiesView answers /api/zapret/strategies.
type StrategiesView struct {
	Installed bool             `json:"installed"`
	Current   string           `json:"current"`
	List      []RankedStrategy `json:"list"`
}

// RankedStrategies lists the strategies, the ones that worked first (most
// successes, then the fastest), the rest in Flowseal's order.
func (a *App) RankedStrategies() StrategiesView {
	v := StrategiesView{Installed: a.dpiInstalled(), Current: a.Settings().Zapret.Strategy}
	if !v.Installed {
		return v
	}
	list, err := a.strategyList()
	if err != nil {
		return v
	}
	v.List = rankStrategies(list, a.strategyScores())
	return v
}

func rankStrategies(list []zapret.Strategy, scores []zapret.StrategyScore) []RankedStrategy {
	byFile := map[string]zapret.StrategyScore{}
	for _, sc := range scores {
		if sc.File != "" {
			byFile[sc.File] = sc
		}
	}
	out := make([]RankedStrategy, len(list))
	for i, st := range list {
		r := RankedStrategy{File: st.File, Name: st.Name}
		if sc, ok := byFile[st.File]; ok {
			r.Checked, r.Failed = true, sc.Err
			r.OK, r.Total, r.YouTube, r.Discord, r.AvgMs = sc.Summary.OK, sc.Summary.Total, sc.Summary.YouTube, sc.Summary.Discord, sc.Summary.AvgMs
		}
		out[i] = r
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Works() != b.Works() {
			return a.Works()
		}
		if !a.Works() {
			return false // keep Flowseal's order
		}
		if a.OK != b.OK {
			return a.OK > b.OK
		}
		return fastest(a.AvgMs, b.AvgMs)
	})
	return out
}

// fastest: lower average wins, an unknown (0) one loses.
func fastest(a, b int) bool {
	if a == 0 || b == 0 {
		return a != 0
	}
	return a < b
}

func (a *App) scoresPath() string { return filepath.Join(a.P.Data, "zapret-scores.json") }

// strategyScores: the last results, loaded from disk after a restart.
func (a *App) strategyScores() []zapret.StrategyScore {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.scores == nil {
		if b, err := os.ReadFile(a.scoresPath()); err == nil {
			var saved []zapret.StrategyScore
			if json.Unmarshal(b, &saved) == nil {
				a.scores = saved
			}
		}
	}
	return a.scores
}

// setScores replaces the results after a full run.
func (a *App) setScores(scores []zapret.StrategyScore) {
	a.mu.Lock()
	a.scores = scores
	a.mu.Unlock()
	a.saveScores()
}

// recordScore updates one strategy after a check of the running zapret.
func (a *App) recordScore(file string, sum zapret.Summary) {
	if file == "" {
		return
	}
	a.strategyScores()
	a.mu.Lock()
	found := false
	for i := range a.scores {
		if a.scores[i].File == file {
			a.scores[i].Summary, a.scores[i].Err, a.scores[i].Results = sum, "", nil
			found = true
		}
	}
	if !found {
		a.scores = append(a.scores, zapret.StrategyScore{File: file, Summary: sum})
	}
	a.mu.Unlock()
	a.saveScores()
}

func (a *App) saveScores() {
	a.mu.Lock()
	// the detailed results stay in memory: the file keeps the counts
	slim := make([]zapret.StrategyScore, len(a.scores))
	for i, sc := range a.scores {
		slim[i] = zapret.StrategyScore{File: sc.File, Summary: sc.Summary, Err: sc.Err}
	}
	a.mu.Unlock()
	b, err := json.MarshalIndent(slim, "", "  ")
	if err != nil {
		return
	}
	tmp := a.scoresPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		logx.Debugf("результаты стратегий: %v", err)
		return
	}
	_ = os.Rename(tmp, a.scoresPath())
}
