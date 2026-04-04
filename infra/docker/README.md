# Docker Deployment for Zero-Trust Agentic Guardian

This directory contains Docker Compose configuration and Dockerfiles for deploying the complete Zero-Trust Agentic Guardian Architecture.

## Architecture Overview

The system consists of 6 microservices plus supporting infrastructure:

### Services
1. **Intent Engine** (port 8001) - Semantic intent verification
2. **Planner** (port 8002) - Task planning and orchestration
3. **Safety Agent** (port 8003) - Policy evaluation
4. **Permission Broker** (port 8004) - Authorization token issuance (externally exposed)
5. **Executor** (port 8005) - Action execution
6. **Audit** (port 8006) - Tamper-evident logging

### Infrastructure
- **PostgreSQL** - Audit log storage
- **Redis** - Token deduplication
- **OPA** - Policy engine

## Prerequisites

1. Docker and Docker Compose installed
2. Auth0 tenant configured with M2M applications
3. Certificates generated (run `infra/certificates/generate_all_certs.sh`)
4. DPoP and signing keys generated
5. Environment variables configured

## Setup Instructions

### 1. Generate Certificates

```bash
cd infra/certificates
./generate_all_certs.sh
```

This creates:
- Root CA certificate
- Client and server certificates for all 6 services

### 2. Configure Auth0

Run the Auth0 configuration script:

```bash
cd infra/auth0
python setup_auth0.py
```

This creates:
- 5 M2M applications
- DPoP keypairs
- Token Vault configuration
- Outputs `auth0_manifest.json`

### 3. Create Environment File

Copy the example environment file and fill in your values:

```bash
cd infra/docker
cp .env.example .env
```

Edit `.env` with your Auth0 credentials from the manifest.

### 4. Start Services

```bash
cd infra/docker
docker-compose up -d
```

### 5. Verify Deployment

Check service health:

```bash
# Check all services are running
docker-compose ps

# Check individual service health
curl http://localhost:8004/health  # Permission Broker (only externally exposed)
```

## Service Communication

All services communicate using:
- **mTLS**: Mutual certificate authentication
- **JWT**: Auth0 access tokens
- **DPoP**: Token binding to prevent theft

Only the Permission Broker is exposed externally on port 8004. All other services communicate over the internal Docker network.

## Configuration

### Environment Variables

Each service requires:
- `AUTH0_DOMAIN` - Your Auth0 tenant domain
- `AUTH0_CLIENT_ID` - Service-specific client ID
- `AUTH0_CLIENT_SECRET` - Service-specific client secret
- `AUTH0_AUDIENCE` - API audience identifier
- Certificate paths (mounted from host)
- DPoP key paths (mounted from host)

### Volumes

The following directories are mounted read-only:
- `../certificates` → `/certs` - mTLS certificates
- `../../keys` → `/keys` - DPoP and signing keys
- `../opa/policies` → `/policies` - OPA policy files

### Networks

All services run on the `ztag-internal` bridge network. In production, set `internal: true` to isolate services from external access.

## Health Checks

Each service exposes a `/health` endpoint:
- Intent Engine: http://intent-engine:8001/health
- Planner: http://planner:8002/health
- Safety Agent: http://safety-agent:8003/health
- Permission Broker: http://permission-broker:8004/health
- Executor: http://executor:8005/health
- Audit: http://audit:8006/health

Docker Compose automatically monitors these endpoints and restarts unhealthy services.

## Logs

View logs for all services:

```bash
docker-compose logs -f
```

View logs for a specific service:

```bash
docker-compose logs -f permission-broker
```

All services output structured JSON logs with correlation IDs.

## Stopping Services

```bash
docker-compose down
```

To also remove volumes (database and cache data):

```bash
docker-compose down -v
```

## Production Considerations

### Security

1. **Network Isolation**: Set `internal: true` for the `ztag-internal` network
2. **Secrets Management**: Use Docker secrets or external secret managers instead of environment variables
3. **Certificate Rotation**: Implement automated certificate rotation
4. **Token Lifetimes**: Configure short-lived tokens (5 minutes for JWTs)

### Scaling

Services can be scaled horizontally:

```bash
docker-compose up -d --scale executor=3
```

Note: The Audit Service should remain a single instance to maintain hash chain integrity.

### Monitoring

Integrate with monitoring tools:
- Prometheus metrics (add `/metrics` endpoints)
- Distributed tracing (OpenTelemetry)
- Log aggregation (ELK stack, Splunk)

### High Availability

For production:
- Use managed PostgreSQL (AWS RDS, Azure Database)
- Use managed Redis (AWS ElastiCache, Azure Cache)
- Deploy across multiple availability zones
- Implement load balancing for the Permission Broker

## Troubleshooting

### Service Won't Start

Check logs:
```bash
docker-compose logs <service-name>
```

Common issues:
- Missing certificates
- Invalid Auth0 credentials
- Database connection failures

### Certificate Errors

Verify certificates are mounted correctly:
```bash
docker-compose exec intent-engine ls -la /certs
```

### Database Connection Issues

Check PostgreSQL is healthy:
```bash
docker-compose exec postgres pg_isready -U audit_user
```

### OPA Policy Errors

Verify policies are loaded:
```bash
docker-compose exec opa wget -O- http://localhost:8181/v1/policies
```

## Development Mode

For development with hot-reload:

1. Mount source code as volumes in docker-compose.yml
2. Add `--reload` flag to uvicorn commands
3. Use `docker-compose up` (without `-d`) to see logs in real-time

## Testing

Run integration tests against the deployed services:

```bash
cd tests/integration
pytest test_full_pipeline.py
```

## Support

For issues or questions, refer to:
- Main README.md
- Design document: `.kiro/specs/zero-trust-agentic-guardian/design.md`
- Requirements: `.kiro/specs/zero-trust-agentic-guardian/requirements.md`
