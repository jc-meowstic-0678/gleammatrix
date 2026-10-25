# Gleam Matrix Server - Deployment Guide

## Prerequisites

1. **BEAM VM (Erlang OTP)** installed on all nodes:
   ```bash
   # Ubuntu/Debian
   sudo apt install erlang
  
   # macOS with Homebrew
   brew install erlang
   
   # NixOS
   nix-shell -p erlangPackagesOTP26.erlang
   ```

2. **Nix Development Environment** (optional but recommended):
   ```bash
   # Ensure nix-shell is available
   sudo apt install nix
   ```

3. **Cloudflare Workers VPC** (for edge security layer):
   - Configure Cloudflare access rules for token validation
   - Set up rate limiting policies via API or dashboard

## Environment Configuration

### Required Environment Variables

| Variable | Description | Example Value |
|----------|-------------|---------------|
| `AETHER_NODE` | Unique node identifier | `"matrix-node-1"` |
| `AETHER_PEERS` | Comma-separated list of peer FQDNs | `"matrix-peer1.example.com,matrix-peer2.example.com"` |
| `AETHER_DOMAIN` | Domain for DNS SRV fallback resolution | `example.com` |
| `MATRIX_PORT` | HTTP server port (Mist framework) | `8080` |
| `CLUSTER_RPC_PORT` | BEAM VM RPC port for clustering | `4369` |
| `CLUSTER_HEARTBEAT_INTERVAL_MS` | Peer health check interval | `5000` |

### Sample `.envrc` file (for Direnv):
```bash
export AETHER_NODE="matrix-node-1"
export AETHER_PEERS="matrix-peer1.example.com,matrix-peer2.example.com"
export AETHER_DOMAIN="example.com"
export MATRIX_PORT=8080
export CLUSTER_RPC_PORT=4369
export CLUSTER_HEARTBEAT_INTERVAL_MS=5000

# Cloudflare VPC configuration (for auth middleware)
export CLOUDFLARE_WORKERS_VPC_ID="vpc-12345"
export CLOUDFLARE_TOKEN_SECRET_KEY="your-secret-key-here"
```

## Compilation & Verification

### Option A: Using Nix Development Environment (Recommended)
```bash
# Ensure nix-shell is installed and configured
which nix-shell  # Should return path to binary

# Enter development environment
nix-shell

# Verify project compiles
gleam check

# Run linter
gleam fmt --check

# Build release
gleam build --target erlang
```

### Option B: Local Gleam Installation (Fallback)
```bash
# Install Gleam compiler
curl -L https://gleam.run/install.sh | sh

# Add to PATH (example for bash)
export PATH="$HOME/.local/bin:$PATH"

# Verify installation
gleam --version

# Check project compiles
cd /path/to/gleam-matrix-server
gleam check
```

## Cluster Formation & Startup

### Step 1: Initialize Primary Node
```bash
# On primary node (matrix-node-1.example.com)
export AETHER_NODE="matrix-node-1"
export AETHER_PEERS=""  # Empty for first node (forms new cluster)
export CLUSTER_RPC_PORT=4369

# Start BEAM VM application
mix run -e "MatrixServer.start()"
```

### Step 2: Join Existing Cluster
```bash
# On secondary nodes (matrix-node-2.example.com, etc.)
export AETHER_NODE="matrix-node-2"
export AETHER_PEERS="matrix-node-1.example.com"
export CLUSTER_RPC_PORT=4369

# Start with peer discovery enabled
mix run -e "MatrixServer.start()"
```

### Step 3: Verify Cluster Formation
Access the cluster topology endpoint:
```bash
curl http://localhost:8080/_matrix/internal/v1/cluster/topology
```

Expected response structure:
```json
{
  "own_node_id": "!matrix_node_abc123",
  "cluster_state": "connected",
  "total_nodes": 2,
  "connected_nodes": [
    {
      "name": "matrix-node-1.example.com",
      "is_connected": true,
      "last_heartbeat_ms": 42,
      "load_score": 100.0
    }
  ]
}
```

## HTTP Server Testing

### Basic API Endpoints (via Mist framework)

#### Create User Account
```bash
curl -X POST http://localhost:8080/_matrix/client/v3/register \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "username": "alice",
    "password": "secure_password_123"
  }'
```

#### Create Room
```bash
curl -X POST http://localhost:8080/_matrix/client/v3/createRoom \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "name": "General Chat",
    "is_direct": false,
    "preset": "public_chat"
  }'
```

#### Join Room
```bash
curl -X PUT http://localhost:8080/_matrix/client/v3/rooms/{ROOM_ID}/join \
  -H "Authorization: Bearer YOUR_TOKEN"
```

#### Send Message
```bash
curl -X POST http://localhost:8080/_matrix/client/v3/rooms/{ROOM_ID}/send/m.room.message \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "msgtype": "m.text",
    "body": "Hello, world!"
  }'
```

## Security Considerations

### Cloudflare Workers VPC Integration

1. **Token Validation Middleware**:
   ```bash
   # Configure in Cloudflare Dashboard or via API:
   POST /cdn/v1/workers/{worker_id}/endpoints/{endpoint_id}/rules
   
   Body:
   {
     "match": {
       "header": "authorization",
       "pattern": "^Bearer \w+_\w+$"
     },
     "action": "authenticate",
     "token_key": "your-secret-key-here"
   }
   ```

2. **Rate Limiting**:
   ```bash
   # Implement via Cloudflare Rules:
   POST /cdn/v1/workers/{worker_id}/rules
   
   Body:
   {
     "expression": "http.request.uri.path ~ \"^/_matrix/client/v[0-9]+.*\"" ,
     "action": "ratelimit",
     "parameters": {
       "request_count_threshold": 100,
       "duration_seconds": 60
     }
   }
   ```

## Monitoring & Observability

### Health Check Endpoint
```bash
curl http://localhost:8080/health
```

Expected response:
```json
{
  "status": "healthy",
  "cluster_state": "connected",
  "node_id": "!matrix_node_abc123",
  "uptime_seconds": 3600,
  "peer_count": 1
}
```

### Mnesia Transaction Logs
Access transaction statistics via BEAM VM shell:
```bash
# SSH into node and attach to running BEAM VM
erl -name matrix-node@localhost

# Connect to running node
-i cluster_node_name

# Query Mnesia tables
mnesia:table_info(mnesia_table, type).
mnesia:table_info(mnesia_table, size).
```

## Troubleshooting

### Common Issues

#### 1. Nix Environment Not Found
**Error**: `[Errno 2] No such file or directory: 'nix-shell'`

**Solution**: 
- Install Nix package manager: https://nixos.org/download.html
- Verify installation: `which nix-shell` should return `/nix/store/.../nix-shell`

#### 2. DNS Resolution Failure in Discovery
**Error**: `DNS resolution failed for matrix-peer1.example.com`

**Solution**:
- Ensure `/etc/hosts` has entries or DNS servers are configured correctly
- Check firewall rules allow port 53 (UDP) queries
- Verify domain names match configured AETHER_DOMAIN variable

#### 3. BEAM VM Cluster Formation Failed
**Error**: `No available peers to connect to`

**Solution**:
- Check CLUSTER_RPC_PORT is open on all nodes
- Verify FQDNs in AETHER_PEERS resolve correctly: `nslookup matrix-peer1.example.com`
- Confirm NIX shell environment has Erlang OTP installed

#### 4. Token Authentication Failures
**Error**: `Bearer token invalid or expired`

**Solution**:
- Ensure CLOUDFLARE_TOKEN_SECRET_KEY matches between server and validation endpoint
- Check token format follows expected pattern: `abc_xyz_...`
- Verify Cloudflare Workers VPC binding is correctly configured

## Production Checklist

Before deploying to production, ensure the following:

- [ ] All cluster nodes have unique AETHER_NODE identifiers
- [ ] FQDNs in AETHER_PEERS resolve correctly from all nodes
- [ ] Firewall allows BEAM VM RPC port (default 4369) between nodes
- [ ] Cloudflare Workers VPC bindings configured for token validation
- [ ] Rate limiting policies defined for API endpoints
- [ ] Heartbeat interval tuned to network latency and stability expectations
- [ ] Backup strategy for Mnesia database tables implemented
- [ ] Monitoring dashboards (Prometheus/Grafana) connected
- [ ] Alert rules configured for cluster disconnection events

## Deployment Commands Summary

```bash
# 1. Ensure environment variables are set
source .envrc  # or export all vars manually

# 2. Verify Gleam compiler is available
gleam --version

# 3. Check project compiles
gleam check

# 4. Format code
gleam fmt

# 5. Build release for production (Erlang target)
gleam build --target erlang

# 6. Start application in foreground (for testing)
GLEAM_APP=matrix_server MIX_ENV=prod mix run -e "MatrixServer.start()"

# 7. Or start as background service (systemd example)
sudo systemctl enable gleam-matrix-server
sudo systemctl start gleam-matrix-server
```

## Version Compatibility Notes

- **Gleam**: Requires v1.x or later (for tuple and module alias support)
- **Erlang/OTP**: Minimum version 26.0 (required for Glesia compatibility)
- **Cloudflare Workers API**: Use latest v1 endpoint versions
- **Mist framework**: Compatible with Gleam 1.x

## Contact & Support

For issues or questions:
- GitHub Issues: https://github.com/your-org/gleam-matrix-server/issues
- Matrix Room: `#matrix_server:example.com` (if accessible)
- Documentation: See [AGENTS.md](./AGENTS.md) for project architecture details