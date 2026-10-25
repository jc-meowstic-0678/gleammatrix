# PROJECT TARGETS: Gleam Matrix Server (Hybrid BEAM + Cloudflare Workers VPC)

## 1. Project Overview
- **Goal:** Build a fully functional Matrix Homeserver using Gleam with hybrid runtime architecture
- **Runtime:** On-premises BEAM VM (primary stateful logic) + Cloudflare Workers VPC (edge proxy & policy enforcement) [2]
- **Protocol:** Matrix Protocol v1.x (Synapse compatible)
- **Deployment Target:** Private BEAM cluster with public ingress via Cloudflare Tunnel and Workers VPC Service bindings [2]

## 2. Architecture Constraints & Technology Stack
### Primary Runtime: BEAM VM
- **HTTP Server Library:** Mist for all HTTP server functionality
- **Mnesia Wrappers:** Glesia for ACID transaction handling [3]
- **Storage:** Mnesia with disc copies on disk (`GLESIA_MNESIA_PATH` path-based) [2]
- **Cluster Discovery:** Environment variables `AETHER_NODE` and `AETHER_PEERS` for node names (FQDNs or IPs required) [2]

### Edge Layer: Cloudflare Workers VPC
- **Binding Type:** HTTP VPC Service bindings for Worker → BEAM communication [3]
- **Tunnel Mode:** Use `cloudflared` warp-routing service (not ingress service) for VPC bindings to function [2]
- **Rate Limiting:** Stateless IP-based at edge, token-bucket via Mnesia through BEAM callback [2]

### Key Integration Points:
| Worker Feature | BEAM Endpoint | Purpose |
|---|---|---|
| Token validation | `/_matrix/client/v3/account/whoami` or `/api/v1/auth/validate-token` | Resolve token → user ID for logging/rate buckets [3] |
| Rate limit check | `/api/v1/rate-limit-check` | Query Mnesia counters before request processing [3] |
| Authenticated requests | `/_matrix/client/v3/login`, `/register` | BEAM remains authoritative credential verifier [3] |
| Device management | `PUT /_matrix/client/v3/devices/{deviceId}` | E2EE key state must be handled by BEAM [3] |

## 3. Cluster Configuration Guidelines
- **Initial Setup:** Single node holds schema and all table copies; all nodes are peers in Mnesia (no master) [2]
- **Scaling Strategy:** Use `mnesia:add_table_copy/3` when adding second node for fault tolerance [2]
- **Node Naming:** Always use FQDNs or IPs containing a dot (e.g., `aether@node1.example.com`)—bare hostnames will fail distribution [2]
- **Cluster Discovery:** Use `AETHER_PEERS` env var with comma-separated peer list for static configuration; DNS polling via `AETHER_DNS_QUERY` available as fallback [2]
- **Process Registry:** Use `:global` module for distributed process naming (e.g., room processes) if distribution is needed later [2]

## 4. Observability & Logging Strategy
### Forward to Cloudflare Gateway Logs (Zero Trust):
- Policy enforcement events (blocked/challenged/allowed requests) [3]
- Auth anomalies at edge (Access/Gateway HTTP policy triggers) [3]
- Session-level VPC metadata (Worker origin, tunnel replica, allow/deny decisions) [3]

### Separate Pipeline (NOT Zero Trust logs):
- Rate limiting counters and throttle metrics → Time-series store [3]
- High-volume operational telemetry from BEAM (latency, Mnesia rates, queue depths) [3]
- Debug-level security events (sampled before export to avoid billable log cost) [3]

## 5. AI Assistance Guidelines for Developers
### When writing database logic:
- Always use `Glesia.transaction()` wrappers for ACID guarantees
- Assume cluster-aware execution; functions should be idempotent and not assume single-node operation [2]
- Use `mnesia:add_table_copy/3` when scaling beyond initial single-node setup [2]

### When writing edge proxy logic:
- Workers make `fetch()` requests to VPC Service endpoints on BEAM via HTTP VPC binding API [3]
- Stateless rate limiting at Worker level should use IP-based caching; token-based limits require synchronous BEAM callback [2]
- Cloudflared tunnel mode must be **warp-routing** (not ingress) for Workers VPC Service bindings to function correctly [2]

### When writing cluster code:
- Node discovery via environment variables (`AETHER_NODE`, `AETHER_PEERS`), not hard-coded hostnames [2]
- Use fully qualified domain names or IPs with dots in BEAM node names (required for distribution) [2]
- Start all tables as disc copies on single node; add copies to new nodes for fault tolerance [2]

## 6. Deployment Configuration Summary
| Component | Configuration |
|---|---|
| **Workers VPC Binding** | HTTP mode (`fetch()` API), warp-routing tunnel service |
| **BEAM Outbound Federation** | `cloudflared` outbound daemon (HTTPS to remote homeservers) |
| **Private Cluster Network** | Direct TCP over private network (EPMD, distribution ports) |
| **Mnesia Path** | `$GLESIA_MNESIA_PATH` on disk (disc copies) |
| **Rate Limiting Cache** | Worker-side TTL via `$RATE_LIMIT_CACHE_TTL` (default 30s) |

## 7. Success Metrics
- Latency < 200ms for non-federation API requests from edge
- Data consistency (ACID) guaranteed during room state updates
- Zero manual configuration files; deployment via environment variables and Wrangler TOML
- Observability logs properly routed to Gateway vs. separate pipeline as specified
