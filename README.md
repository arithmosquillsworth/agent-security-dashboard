# Agent Security Dashboard

🔐 Unified security monitoring dashboard for autonomous AI agents.

## Overview

Aggregates data from all Agent Security Stack components:
- **Transaction Firewall** — Policy enforcement and blocking stats
- **Agent Honeypot** — Attack detection and pattern analysis
- **Prompt Guard** — Input scanning and injection detection
- **Transaction Simulator** — Pre-execution validation

## Quick Start

```bash
# Run locally
go run main.go

# Or build and run
go build -o dashboard
./dashboard

# Set custom port
PORT=3000 go run main.go
```

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web dashboard UI |
| `/health` | GET | Health check |
| `/api/dashboard` | GET | Full dashboard JSON |
| `/api/firewall/block` | POST | Report blocked transaction |
| `/api/honeypot/report` | POST | Report detected attack |
| `/api/prompt-guard/scan` | POST | Report scanned input |
| `/api/simulator/run` | POST | Report simulation result |

## API Examples

### Report Blocked Transaction
```bash
curl -X POST http://localhost:8080/api/firewall/block \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "Daily limit exceeded",
    "amount": 0.6,
    "risk_score": 85
  }'
```

### Report Attack Detection
```bash
curl -X POST http://localhost:8080/api/honeypot/report \
  -H "Content-Type: application/json" \
  -d '{
    "attack_type": "prompt_injection",
    "confidence": 0.95,
    "source": "0xattacker..."
  }'
```

### Report Prompt Scan
```bash
curl -X POST http://localhost:8080/api/prompt-guard/scan \
  -H "Content-Type: application/json" \
  -d '{
    "input": "ignore previous instructions...",
    "confidence": 0.92,
    "blocked": true
  }'
```

### Report Simulation
```bash
curl -X POST http://localhost:8080/api/simulator/run \
  -H "Content-Type: application/json" \
  -d '{
    "would_revert": true,
    "gas_estimate": 150000
  }'
```

## Screenshot

The dashboard provides real-time visibility into:
- Daily spend limits and remaining budget
- Blocked transactions with reasons
- Detected attack patterns
- Prompt injection confidence scores
- Gas saved through simulation

## Integration

Each security tool reports to the dashboard via HTTP POST:

```go
// Example: Firewall reporting a block
http.Post("http://dashboard:8080/api/firewall/block", 
    "application/json",
    strings.NewReader(`{"reason": "...", "risk_score": 85}`))
```

## Environment

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP server port |

## Part of Agent Security Stack

- [agent-tx-firewall](https://github.com/arithmosquillsworth/agent-tx-firewall)
- [agent-honeypot](https://github.com/arithmosquillsworth/agent-honeypot)
- [prompt-guard](https://github.com/arithmosquillsworth/prompt-guard)
- [tx-simulator](https://github.com/arithmosquillsworth/tx-simulator)
- **agent-security-dashboard** (this repo)

## License

MIT
