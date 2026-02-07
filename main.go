package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

// SecurityDashboard aggregates data from all agent security tools
type SecurityDashboard struct {
	Firewall      FirewallStatus      `json:"firewall"`
	Honeypot      HoneypotStatus      `json:"honeypot"`
	PromptGuard   PromptGuardStatus   `json:"prompt_guard"`
	Simulator     SimulatorStatus     `json:"simulator"`
	LastUpdated   time.Time           `json:"last_updated"`
	Version       string              `json:"version"`
}

type FirewallStatus struct {
	Enabled           bool     `json:"enabled"`
	DailyLimit        float64  `json:"daily_limit"`
	DailySpent        float64  `json:"daily_spent"`
	Remaining         float64  `json:"remaining"`
	BlockedToday      int      `json:"blocked_today"`
	RiskScore         int      `json:"risk_score"`
	PolicyViolations  []string `json:"policy_violations"`
}

type HoneypotStatus struct {
	Enabled          bool              `json:"enabled"`
	AttacksDetected  int               `json:"attacks_detected"`
	AttackPatterns   map[string]int    `json:"attack_patterns"`
	RecentProbes     []Probe           `json:"recent_probes"`
}

type Probe struct {
	Timestamp   time.Time `json:"timestamp"`
	Type        string    `json:"type"`
	Confidence  float64   `json:"confidence"`
	Source      string    `json:"source"`
}

type PromptGuardStatus struct {
	Enabled         bool    `json:"enabled"`
	ScannedToday    int     `json:"scanned_today"`
	BlockedToday    int     `json:"blocked_today"`
	AvgConfidence   float64 `json:"avg_confidence"`
}

type SimulatorStatus struct {
	Enabled        bool   `json:"enabled"`
	SimulatedToday int    `json:"simulated_today"`
	WouldRevert    int    `json:"would_revert"`
	GasSaved       uint64 `json:"gas_saved"`
}

var dashboard *SecurityDashboard

func init() {
	dashboard = &SecurityDashboard{
		Version:     "0.1.0",
		LastUpdated: time.Now(),
		Firewall: FirewallStatus{
			Enabled:          true,
			DailyLimit:       0.5,
			DailySpent:       0.0,
			Remaining:        0.5,
			BlockedToday:     0,
			RiskScore:        0,
			PolicyViolations: []string{},
		},
		Honeypot: HoneypotStatus{
			Enabled:         true,
			AttacksDetected: 0,
			AttackPatterns:  make(map[string]int),
			RecentProbes:    []Probe{},
		},
		PromptGuard: PromptGuardStatus{
			Enabled:       true,
			ScannedToday:  0,
			BlockedToday:  0,
			AvgConfidence: 0.0,
		},
		Simulator: SimulatorStatus{
			Enabled:        true,
			SimulatedToday: 0,
			WouldRevert:    0,
			GasSaved:       0,
		},
	}
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/api/dashboard", dashboardHandler)
	http.HandleFunc("/api/firewall/block", firewallBlockHandler)
	http.HandleFunc("/api/honeypot/report", honeypotReportHandler)
	http.HandleFunc("/api/prompt-guard/scan", promptGuardScanHandler)
	http.HandleFunc("/api/simulator/run", simulatorRunHandler)
	http.HandleFunc("/", indexHandler)

	fmt.Printf("🔐 Agent Security Dashboard v%s starting on port %s\n", dashboard.Version, port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
		"time":   time.Now().Format(time.RFC3339),
	})
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	dashboard.LastUpdated = time.Now()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dashboard)
}

func firewallBlockHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Reason   string  `json:"reason"`
		Amount   float64 `json:"amount"`
		RiskScore int    `json:"risk_score"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	dashboard.Firewall.BlockedToday++
	dashboard.Firewall.PolicyViolations = append(
		dashboard.Firewall.PolicyViolations,
		fmt.Sprintf("%s: %s (risk: %d)", time.Now().Format("15:04"), req.Reason, req.RiskScore),
	)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"blocked": true,
		"reason":  req.Reason,
		"total_blocked": dashboard.Firewall.BlockedToday,
	})
}

func honeypotReportHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		AttackType string  `json:"attack_type"`
		Confidence float64 `json:"confidence"`
		Source     string  `json:"source"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	dashboard.Honeypot.AttacksDetected++
	dashboard.Honeypot.AttackPatterns[req.AttackType]++
	dashboard.Honeypot.RecentProbes = append(
		dashboard.Honeypot.RecentProbes[:min(9, len(dashboard.Honeypot.RecentProbes))],
		Probe{
			Timestamp:  time.Now(),
			Type:       req.AttackType,
			Confidence: req.Confidence,
			Source:     req.Source,
		},
	)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"detected": true,
		"attack_type": req.AttackType,
		"total_attacks": dashboard.Honeypot.AttacksDetected,
	})
}

func promptGuardScanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Input      string  `json:"input"`
		Confidence float64 `json:"confidence"`
		Blocked    bool    `json:"blocked"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	dashboard.PromptGuard.ScannedToday++
	if req.Blocked {
		dashboard.PromptGuard.BlockedToday++
	}
	
	// Update running average
	oldAvg := dashboard.PromptGuard.AvgConfidence
	count := float64(dashboard.PromptGuard.ScannedToday)
	dashboard.PromptGuard.AvgConfidence = (oldAvg*(count-1) + req.Confidence) / count

	json.NewEncoder(w).Encode(map[string]interface{}{
		"scanned":   true,
		"blocked":   req.Blocked,
		"confidence": req.Confidence,
	})
}

func simulatorRunHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		WouldRevert bool   `json:"would_revert"`
		GasEstimate uint64 `json:"gas_estimate"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	dashboard.Simulator.SimulatedToday++
	if req.WouldRevert {
		dashboard.Simulator.WouldRevert++
		dashboard.Simulator.GasSaved += req.GasEstimate
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"simulated":   true,
		"would_revert": req.WouldRevert,
		"gas_saved":    dashboard.Simulator.GasSaved,
	})
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head>
    <title>Agent Security Dashboard</title>
    <style>
        body { font-family: -apple-system, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: #0a0a0a; color: #e0e0e0; }
        h1 { color: #00ff88; }
        .status-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-top: 20px; }
        .card { background: #1a1a1a; border-radius: 12px; padding: 20px; border: 1px solid #333; }
        .card h2 { margin-top: 0; color: #fff; font-size: 18px; }
        .metric { display: flex; justify-content: space-between; margin: 10px 0; padding: 8px 0; border-bottom: 1px solid #333; }
        .metric:last-child { border-bottom: none; }
        .label { color: #888; }
        .value { font-weight: bold; color: #00ff88; }
        .value.warning { color: #ffaa00; }
        .value.danger { color: #ff4444; }
        .enabled { color: #00ff88; }
        .disabled { color: #ff4444; }
        .timestamp { color: #666; font-size: 12px; margin-top: 20px; }
        pre { background: #0a0a0a; padding: 15px; border-radius: 8px; overflow-x: auto; font-size: 12px; }
    </style>
</head>
<body>
    <h1>🔐 Agent Security Dashboard</h1>
    <p>Unified security monitoring for autonomous AI agents</p>
    
    <div class="status-grid">
        <div class="card">
            <h2>🛡️ Transaction Firewall</h2>
            <div class="metric">
                <span class="label">Status</span>
                <span class="value enabled">● Enabled</span>
            </div>
            <div class="metric">
                <span class="label">Daily Limit</span>
                <span class="value">0.5 ETH</span>
            </div>
            <div class="metric">
                <span class="label">Daily Spent</span>
                <span class="value">0.0 ETH</span>
            </div>
            <div class="metric">
                <span class="label">Blocked Today</span>
                <span class="value">%d</span>
            </div>
            <div class="metric">
                <span class="label">Risk Score</span>
                <span class="value">%d/100</span>
            </div>
        </div>
        
        <div class="card">
            <h2>🍯 Honeypot</h2>
            <div class="metric">
                <span class="label">Status</span>
                <span class="value enabled">● Enabled</span>
            </div>
            <div class="metric">
                <span class="label">Attacks Detected</span>
                <span class="value">%d</span>
            </div>
            <div class="metric">
                <span class="label">Recent Probes</span>
                <span class="value">%d</span>
            </div>
        </div>
        
        <div class="card">
            <h2>📝 Prompt Guard</h2>
            <div class="metric">
                <span class="label">Status</span>
                <span class="value enabled">● Enabled</span>
            </div>
            <div class="metric">
                <span class="label">Scanned Today</span>
                <span class="value">%d</span>
            </div>
            <div class="metric">
                <span class="label">Blocked Today</span>
                <span class="value">%d</span>
            </div>
            <div class="metric">
                <span class="label">Avg Confidence</span>
                <span class="value">%%.1f</span>
            </div>
        </div>
        
        <div class="card">
            <h2>🔬 Transaction Simulator</h2>
            <div class="metric">
                <span class="label">Status</span>
                <span class="value enabled">● Enabled</span>
            </div>
            <div class="metric">
                <span class="label">Simulated Today</span>
                <span class="value">%d</span>
            </div>
            <div class="metric">
                <span class="label">Would Revert</span>
                <span class="value warning">%d</span>
            </div>
            <div class="metric">
                <span class="label">Gas Saved</span>
                <span class="value">%d</span>
            </div>
        </div>
    </div>
    
    <div class="card" style="margin-top: 20px;">
        <h2>📊 Raw Data</h2>
        <pre id="json-data">Loading...</pre>
    </div>
    
    <p class="timestamp">Last updated: %s | Dashboard v%s</p>
    
    <script>
        async function refreshData() {
            const res = await fetch('/api/dashboard');
            const data = await res.json();
            document.getElementById('json-data').textContent = JSON.stringify(data, null, 2);
        }
        refreshData();
        setInterval(refreshData, 5000);
    </script>
</body>
</html>
`,
		dashboard.Firewall.BlockedToday,
		dashboard.Firewall.RiskScore,
		dashboard.Honeypot.AttacksDetected,
		len(dashboard.Honeypot.RecentProbes),
		dashboard.PromptGuard.ScannedToday,
		dashboard.PromptGuard.BlockedToday,
		dashboard.PromptGuard.AvgConfidence*100,
		dashboard.Simulator.SimulatedToday,
		dashboard.Simulator.WouldRevert,
		dashboard.Simulator.GasSaved,
		dashboard.LastUpdated.Format("15:04:05"),
		dashboard.Version,
	)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
