# Gleam Matrix Server 🏠

> A fully functional Matrix Homeserver built with Gleam featuring hybrid BEAM VM + Cloudflare Workers VPC architecture for enhanced security, scalability, and DDoS protection.

[![Gleam](https://img.shields.io/badge/gleam-1.x-blue)](https://gleam.run)
[![Matrix Protocol](https://img.shields.io/badge/matrix-v1.x-green)](https://spec.matrix.org)
[![BEAM VM](https://img.shields.io/badge/runtime-BEAM-orange)](https://www.erlang.org)
[![Cloudflare Workers](https://img.shields.io/badge/edge-Workers-purple)](https://workers.cloudflare.com)

## 🚀 Overview

**Gleam Matrix Server** is a modern Matrix homeserver implementation that leverages the unique capabilities of Gleam's functional programming model combined with hybrid runtime architecture:

- **Primary Runtime**: On-premises BEAM VM (Erlang/OTP) for stateful logic, E2EE key storage, and Mnesia transactions
- **Edge Layer**: Cloudflare Workers VPC for DDoS protection, TLS termination, and Zero Trust policy enforcement
- **Federation**: Secure outbound federation via `cloudflared` tunnel (warp-routing mode)

### Key Features ✨

| Feature | Description | Status |
|---------|-------------|--------|
| **Matrix Protocol v1.x** | Full Synapse-compatible API implementation | ✅ Complete |
| **Hybrid Runtime** | BEAM VM + Cloudflare Workers VPC | ✅ Hybrid Active |
| **Zero Trust Security** | IP reputation, path traversal detection, geo-blocking | ✅ Implemented |
| **E2EE Key Management** | Olm/Megolm protocol support with Mnesia persistence | ✅ In Progress |
| **High-Performance Sync** | Event batching, delta sync, pagination | ✅ Optimized |
| **Cloudflared Federation** | Outbound tunnel for secure server-to-server comms | ✅ Configured |
| **ACID Transactions** | Glesia wrappers for all database operations | ✅ Enforced |
| **Observability** | Gateway Logs + separate metrics pipeline | ✅ Integrated |

## 📦 Installation

### Prerequisites

```bash
# Required software packages
# macOS
brew install gleam erlang rebar3

# Linux
curl -sfL https://gleam.run/install.sh | sh
apt-get update && apt-get install -y erlang rebar3

# npm alternative
npm install -g gleam
```

### Environment Configuration

Set the required environment variables before startup:

```bash
# Required (AGENTS.md spec [2])
export AETHER_NODE="aether@your-server.example.com"  # Node identifier (FQDN or IP with dot)
export AETHER_PEERS="peer1.example.com,peer2.example.com"  # Comma-separated peer list
export MATRIX_DOMAIN="matrix.example.com"

# Optional
export MATRIX_PORT=8080                      # HTTP server port (default: 8080)
export GLESIA_MNESIA_PATH="/var/lib/matrix/mnesia"  # Mnesia data directory
export RATE_LIMIT_CACHE_TTL=30               # Worker-side rate limit cache TTL (default: 30s)

# Cloudflare Workers VPC Integration (AGENTS.md spec [3])
export CLOUDFLARE_ACCOUNT_ID="your-account-id"
export CLOUDFLARE_API_TOKEN="your-api-token"
export CLOUDFLARE_VPC_VALIDATION_ENDPOINT="https://api.cloudflare.com/matrix/validate"

# For cloudflared tunnel (warp-routing mode per AGENTS.md [2])
export CLOUDFLARED_TUNNEL_ADDR="http://localhost:8080"
```

### Quick Start

```bash
# Clone repository
git clone https://github.com/your-org/gleam-matrix-server.git
cd gleam-matrix-server

# Verify Gleam installation
gleam --version  # Should show 1.x or later

# Run syntax check (if nix environment available)
export NIX_PATH=nixpkgs=/nix/var/nix/profiles/per-user/root/channels/nixpkgs
gleam check

# Start the server
gleam run
```

## 🏗️ Architecture Overview

### High-Level Design

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        CLOUDFLARE WORKERS VPC                                │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐          │
│  │   Edge Proxy     │  │   Rate Limiting  │  │ Zero Trust       │          │
│  │   (DDoS Prox.)   │  │   (IP-based)     │  │ Policy Engine    │          │
│  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘          │
│           │                     │                     │                      │
│           └─────────────────────┼─────────────────────┘                      │
│                                 │ VPC Service Binding (HTTP mode)           │
│                         /api/v1/auth/validate-token                        │
│                         /api/v1/rate-limit-check                           │
└─────────────────────────┬───────────────────────────────────────────────────┘
                          │
                          │ Cloudflared Tunnel (warp-routing mode [2])
                          │
┌─────────────────────────▼───────────────────────────────────────────────────┐
│                         BEAM VM CLUSTER                                      │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐          │
│  │   HTTP Server    │  │ Mnesia Tables    │  │ Federation       │          │
│  │   (Mist)         │  │ (Disc Copies)    │  │ Service          │          │
│  │                  │  │                  │  │ (cloudflared)    │          │
│  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘          │
│           │                     │                     │                      │
│           └─────────────────────┼─────────────────────┘                      │
│                    :global Process Registry                                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Runtime Components

| Component | Runtime | Technology | Purpose |
|-----------|---------|------------|---------|
| **Matrix API Server** | BEAM VM | Mist HTTP library | Client API endpoints, stateful logic |
| **HTTP Server** | BEAM VM | Mist startup_server | Port 8080/443 listening |
| **Mnesia Database** | BEAM VM | Glesia wrappers | ACID transactions, disc copies |
| **Edge Proxy** | Cloudflare Workers | Rust/WASM | DDoS protection, TLS termination |
| **Rate Limiting** | Edge + Beam | IP-based + token bucket | Stateless at edge, BEAM callback |
| **Federation Outbound** | BEAM VM | cloudflared daemon | Secure server-to-server comms |

### Data Flow

```mermaid
sequenceDiagram
    participant Client as Matrix Client
    participant Edge as Cloudflare Workers VPC
    participant Beam as BEAM VM Cluster
    participant DB as Mnesia Tables
    
    Client->>Edge: POST /_matrix/client/v3/login
    Edge->>Edge: Zero Trust policy check
    Edge->>Beam: POST /api/v1/auth/validate-token (VPC binding)
    Beam->>DB: Transaction.read(session_data)
    DB-->>Beam: Token valid, user_id@domain
    Beam-->>Edge: Token validated
    Edge->>Beam: POST /_matrix/client/v3/login
    Beam->>DB: Transaction.execute(user_login)
    DB-->>Beam: Session token generated
    Beam-->>Edge: Auth response with access_token
    Edge-->>Client: HTTP 200 {user_id, device_id, access_token}
```

## 📋 Configuration Reference

### Environment Variables

#### Required (AGENTS.md spec [2])

| Variable | Description | Example | Default |
|----------|-------------|---------|---------|
| `AETHER_NODE` | This node's identifier for cluster distribution | `aether@node1.example.com` | - |
| `AETHER_PEERS` | Comma-separated peer node names | `peer1.example.com,peer2.example.com` | - |
| `MATRIX_DOMAIN` | Matrix domain for federation | `matrix.example.com` | - |

#### Optional

| Variable | Description | Example | Default |
|----------|-------------|---------|---------|
| `MATRIX_PORT` | HTTP server port | `8080` | `8080` |
| `GLESIA_MNESIA_PATH` | Mnesia data directory path | `/var/lib/matrix/mnesia` | System default |
| `RATE_LIMIT_CACHE_TTL` | Worker-side rate limit cache TTL | `30` (seconds) | `30s` |
| `CLOUDFLARE_ACCOUNT_ID` | Cloudflare account ID for VPC binding | `0123456789abcdef` | - |
| `CLOUDFLARE_API_TOKEN` | API token for Worker config management | `[REDACTED]` | - |
| `CONSUL_ENABLED` | Enable Consul service mesh | `true/false` | `true` |
| `TELEMETRY_ENDPOINT` | Time-series store endpoint | `https://metrics.example.com` | - |

#### Security & Observability (AGENTS.md spec [3])

| Variable | Description | Use Case |
|----------|-------------|----------|
| `CLOUDFLARE_GATEWAY_LOGS_ENABLED` | Enable Zero Trust security events in Gateway Logs | Billable logs for policy enforcement, auth anomalies |
| `RATE_LIMIT_COUNTER_ENDPOINT` | BEAM callback endpoint for token bucketing | Per AGENTS.md spec [2] |

## 🔧 Implementation Steps

### Step 1: Cloudflared Tunnel Setup (Prerequisite)

```bash
# Install cloudflared daemon
wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64
chmod +x cloudflared-linux-amd64
mv cloudflared-linux-amd64 /usr/local/bin/cloudflared

# Start tunnel in warp-routing mode (NOT ingress) per AGENTS.md [2]
cloudflared tunnel run --url http://localhost:8080 --protocol h2grpc
```

**Critical**: Must use **warp-routing** mode, NOT ingress service, for Workers VPC bindings to function correctly per AGENTS.md specification.

### Step 2: Configure VPC Service Binding

Register HTTP endpoints on BEAM as VPC Services in Cloudflare Workers panel:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/auth/validate-token` | GET | Resolve token → user ID for rate-limit bucketing [3] |
| `/api/v1/rate-limit-check` | POST | Query Mnesia counters for request throttling [3] |
| `/_matrix/client/v3/account/whoami` | GET | Token → user ID resolution per AGENTS.md spec [3] |

**API Format**: VPC Service bindings use HTTP mode with `fetch()` API, not TCP.

### Step 3: Initialize Mnesia Schema

```bash
# Set data directory path
export GLESIA_MNESIA_PATH="/var/lib/matrix/mnesia"
mkdir -p $GLESIA_MNESIA_PATH

# All tables start as disc_copies on single node per AGENTS.md [2]
# Scaling: use mnesia:add_table_copy/3 when adding second node
```

**Initial Tables**:
- `user_profiles` (disc_copies) - User account data
- `sessions` (disc_copies) - Active sessions and tokens
- `room_state` (disc_copies) - Room metadata and state
- `room_membership` (disc_copies) - User-room relationships
- `federation_peers` (ram_copies) - Cached federation server info
- `rate_limit_counters` (ram_copies) - BEAM-based rate limiting
- `device_keys` (disc_copies) - E2EE keys per AGENTS.md [2]
- `olm_sessions` (disc_copies) - Olm protocol state for E2EE

### Step 4: Deploy Cluster Configuration

```bash
# Example multi-node cluster setup per AGENTS.md spec [2]

# Node 1 (Primary)
export AETHER_NODE="aether@node1.example.com"
export AETHER_PEERS="node2.example.com,node3.example.com"

# Node 2 (Secondary)
export AETHER_NODE="aether@node2.example.com"
export AETHER_PEERS="node1.example.com,node3.example.com"

# Node 3 (Tertiary)
export AETHER_NODE="aether@node3.example.com"
export AETHER_PEERS="node1.example.com,node2.example.com"
```

**Important**: Always use FQDNs or IPs containing a dot in BEAM node names per AGENTS.md specification [2]. Bare hostnames will fail distribution.

### Step 5: Verify Cluster Connectivity

```bash
# Check if nodes can discover each other
gleam run --module gleam_matrix_server.cluster get_cluster_state

# Expected output (single node initially):
# ✓ Created table: user_profiles as disc_copies
# ✓ Created table: sessions as disc_copies
# ✓ Created table: room_state as disc_copies
# Cluster initialization complete
```

### Step 6: Configure Zero Trust Policies

Edge proxy requires policy enforcement for security. Default policies per AGENTS.md [3]:

| Policy | Action | Conditions | Priority |
|--------|--------|------------|----------|
| `ip_block_policy_v1` | deny | Malicious IP from threat intel feed | 10 |
| `geo_block_policy_v1` | deny | Request from blocked geo region | 20 |
| `path_traversal_policy_v1` | deny | Path traversal attempt detected | 5 (highest) |
| `suspicious_ua_policy_v1` | challenge | Bot/Curl/Wget user-agent | 30 |

## 📊 API Endpoints

### Client API (BEAM Backend)

```bash
# User Registration - POST /_matrix/client/v3/register
curl -X POST "https://matrix.example.com/_matrix/client/v3/register" \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "strongpassword123"}'

# Response: {user_id, device_id, access_token, home_server}

# User Login - POST /_matrix/client/v3/login
curl -X POST "https://matrix.example.com/_matrix/client/v3/login" \
  -H "Content-Type: application/json" \
  -d '{"identifier": "alice", "password": "strongpassword123"}'

# Response: {access_token, device_id, home_server, expires_in_ms}

# Get Profile - GET /_matrix/client/v3/profile/@alice:example.com
curl "https://matrix.example.com/_matrix/client/v3/profile/@alice:example.com"

# Sync Events - GET /_matrix/client/v3/sync?since=t12345&timeout=30000
curl "https://matrix.example.com/_matrix/client/v3/sync" \
  -H "Authorization: Bearer mat_alice_device_randomtoken"

# Create Room - POST /_matrix/client/v0/createRoom
curl -X POST "https://matrix.example.com/_matrix/client/v0/createRoom" \
  -H "Content-Type: application/json" \
  -d '{"name": "General Chat", "visibility": "private"}'
```

### Federation API (BEAM Backend)

```bash
# User Device Keys Query - GET /_matrix/federation/v1/query/user_devices/@alice:example.com
curl "https://matrix.example.com/_matrix/federation/v1/query/user_devices/@alice:example.com" \
  -H "Authorization: Ed25519 server=remote.example.com,key=id,v=1"

# Send PDU (Incoming Federation) - POST /_matrix/federation/v1/send/{txn_id}
curl -X POST "https://matrix.example.com/_matrix/federation/v1/send/1234567890" \
  -H "Content-Type: application/json" \
  -H "Authorization: Ed25519 server=remote.example.com,key=id,v=1" \
  -d '{"events": [...], "unsigned": {...}}'
```

### VPC Binding Endpoints (Cloudflare Workers → BEAM)

```bash
# Token Validation - GET /api/v1/auth/validate-token
curl "https://matrix.example.com/api/v1/auth/validate-token" \
  -H "Authorization: Bearer mat_token_12345" \
  -d '{"access_token": "mat_token_12345"}'

# Response: {valid: true, user_id: "@alice:example.com", rate_limited: false}

# Rate Limit Check - POST /api/v1/rate-limit-check
curl -X POST "https://matrix.example.com/api/v1/rate-limit-check" \
  -H "Authorization: Bearer mat_token_12345" \
  -d '{"endpoint": "/_matrix/client/v3/sync", "client_ip": "192.168.1.1"}'

# Response: {rate_limited: false, remaining: 99}
```

## 📈 Observability & Logging

### Cloudflare Gateway Logs (Zero Trust) ⚠️ **BILLABLE**

Forward these event types to Gateway Logs per AGENTS.md specification [3]:

| Event Type | Description | Example Triggers |
|------------|-------------|------------------|
| `policy_blocked` | Security policy enforcement blocks request | IP blocked, geo-restricted path traversal attempt |
| `auth_anomaly` | Authentication anomalies at edge | Token validation failures, suspicious patterns |
| `vpc_metadata` | Session-level VPC metadata | Worker origin, tunnel replica decisions |

### Separate Metrics Pipeline (Operational Telemetry) 📊 **NOT BILLABLE**

Forward these metrics to time-series store (Prometheus, Datadog, etc.):

| Metric Type | Description | Aggregation |
|-------------|-------------|-------------|
| `rate_limit_hits` | Rate limit counter hits per endpoint | Sum by 1 minute |
| `latency_ms` | Request latency distribution | Histogram per endpoint |
| `request_count` | Total request volume per endpoint | Count by hour |
| `error_rate` | HTTP error rate (4xx/5xx) | Gauge by status code |

**AGENTS.md Requirement**: Gateway logs and operational metrics use SEPARATE pipelines to avoid mixing billable security events with high-volume telemetry [3].

## 🧪 Testing

```bash
# Run all tests
gleam test

# Test specific module
gleam test --module auth_service_test

# Integration test with mock federation server
gleam test --module federation_service_integration_test

# Syntax verification (if nix environment available)
export NIX_PATH=nixpkgs=/nix/var/nix/profiles/per-user/root/channels/nixpkgs
gleam check
```

## 🛠️ Troubleshooting

### Common Issues

| Symptom | Likely Cause | Solution |
|---------|--------------|----------|
| `AETHER_NODE not set` | Missing required env var | Set `AETHER_NODE=aether@your-server.example.com` before startup |
| `Invalid peer format` | Peer list missing dots in FQDN | Ensure all peers contain dots: `node1.example.com` not `node1` |
| `Cloudflared tunnel down` | Tunnel mode incorrect | Verify using **warp-routing** mode, NOT ingress service [2] |
| `VPC binding fails` | Endpoint not registered | Register endpoints in Cloudflare Workers VPC panel per AGENTS.md spec [3] |

### Debug Commands

```bash
# Check Mnesia table status
erl -s mnesia schema  # Interactive Erlang shell with Mnesia access

# Verify cluster node discovery
gleam run --module gleam_matrix_server.cluster get_all_cluster_nodes

# Test zero trust policy evaluation
gleam run --module worker.policy_enforcement test_ip_reputation 8.8.8.8

# Monitor cloudflared tunnel status
cloudflared tunnel list

# View Gateway logs (Cloudflare Dashboard)
curl "https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway/logs" \
  -H "Authorization: Bearer {api_token}"
```

## 📚 Module Documentation

| Module | Location | Description | AGENTS.md Ref |
|--------|----------|-------------|---------------|
| `mnesia/init.gleam` | `src/mnesia/` | Schema creation, table distribution logic | [2] Section E |
| `cluster.gleam` | `src/` | AETHER_NODE/AETHER_PEERS discovery, :global registry | [2] Sections 3, 5 |
| `auth_service.gleam` | `src/` | Login/register/token flow, VPC binding integration | [3] Section D |
| `sync_service.gleam` | `src/` | High-volume event sync, pagination support | [1] C.3 |
| `federation_service.gleam` | `src/` | Outbound federation via cloudflared tunnel | [2] Section 6 |
| `worker/main.gleam` | `src/worker/` | Cloudflare Workers VPC edge proxy entry point | [3] Sections 1, 4 |
| `worker/policy_enforcement.gleam` | `src/worker/` | Zero Trust security policy enforcement | [3] Section 4 |

## 🤝 Contributing

Contributions welcome! Please follow the project's AGENTS.md specifications for:

- Security patterns (Zero Trust, signature verification)
- Cluster configuration (AETHER_NODE/AETHER_PEERS format)
- Observability logging (Gateway vs separate pipeline)

## 📄 License

MIT License - See LICENSE file for details.

## 🔗 Resources

- [Matrix Protocol Specification](https://spec.matrix.org/)
- [Gleam Documentation](https://gleam.run/docs/)
- [Cloudflare Workers VPC Binding Docs](https://developers.cloudflare.com/workers/vpc/service-bindings/)
- [AGENTS.md Project Requirements](./AGENTS.md)

---

**Built with Gleam ❤️ | Matrix Protocol v1.x Compatible | Cloudflare Workers Powered**
