# Audit Service

The Audit Service maintains cryptographically chained, append-only audit logs for the Zero-Trust Agentic Guardian Architecture. It provides tamper-evident logging with hash chain integrity verification.

## Features

- **Cryptographic Hash Chaining**: Each log entry is cryptographically linked to the previous entry using SHA256
- **Append-Only Storage**: Logs cannot be modified or deleted, only appended
- **Tamper Detection**: Any modification to the log chain is immediately detectable
- **PostgreSQL Backend**: Persistent storage with indexing for fast queries
- **RESTful API**: FastAPI-based endpoints for logging and querying

## Architecture

### Components

1. **Database Module** (`database.py`): PostgreSQL storage with SQLAlchemy ORM
2. **Hash Chain Computer** (`hash_chain.py`): Cryptographic hash computation and verification
3. **Log Storage** (`log_storage.py`): High-level interface for storing and retrieving logs
4. **Chain Verifier** (`chain_verifier.py`): Integrity verification and tampering detection
5. **FastAPI Application** (`main.py`): REST API endpoints

### Hash Chain Structure

```
Entry 0: hash = SHA256("genesis" || entry_data_0)
Entry 1: hash = SHA256(hash_0 || entry_data_1)
Entry 2: hash = SHA256(hash_1 || entry_data_2)
...
```

Each entry contains:
- `log_id`: Unique identifier
- `component`: Service that generated the log
- `event_type`: Type of event
- `action_metadata`: Event-specific data
- `zt_at`: Optional Zero-Trust Authorization Token
- `dpop_fingerprint`: DPoP key fingerprint
- `timestamp`: Event timestamp
- `hash`: Current entry hash
- `previous_hash`: Previous entry hash

## API Endpoints

### POST /log

Log a new audit entry.

**Request:**
```json
{
  "component": "executor",
  "event_type": "action_executed",
  "action_metadata": {
    "action": "create_branch",
    "provider": "github",
    "result": "success"
  },
  "zt_at": { ... },
  "dpop_fingerprint": "fp_abc123"
}
```

**Response:**
```json
{
  "log_id": "log_a1b2c3d4",
  "hash": "e5f6g7h8...",
  "previous_hash": "i9j0k1l2...",
  "timestamp": "2024-01-15T10:33:00Z"
}
```

### GET /verify

Verify the integrity of the complete audit log chain.

**Response:**
```json
{
  "chain_valid": true,
  "total_entries": 1234,
  "first_hash": "a1b2c3d4...",
  "last_hash": "e5f6g7h8..."
}
```

If chain is broken:
```json
{
  "chain_valid": false,
  "total_entries": 1234,
  "first_hash": "a1b2c3d4...",
  "last_hash": "e5f6g7h8...",
  "broken_index": 567,
  "tampered_indices": [567, 568]
}
```

### GET /logs

Query audit log entries with optional filters.

**Query Parameters:**
- `plan_id`: Filter by plan ID
- `component`: Filter by component
- `limit`: Maximum entries to return (default: 100, max: 1000)

**Response:**
```json
{
  "logs": [
    {
      "log_id": "log_a1b2c3d4",
      "component": "executor",
      "event_type": "action_executed",
      "action_metadata": { ... },
      "zt_at": { ... },
      "dpop_fingerprint": "fp_abc123",
      "timestamp": "2024-01-15T10:33:00Z",
      "hash": "e5f6g7h8...",
      "previous_hash": "i9j0k1l2..."
    }
  ],
  "total_count": 1234
}
```

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "database_healthy": true,
  "total_entries": 1234
}
```

## Configuration

Configuration is managed through `config.py` and environment variables:

```python
# Service settings
host: str = "0.0.0.0"
port: int = 8006

# Database settings
database_url: str = "postgresql://audit_user:audit_pass@localhost:5432/audit_db"

# Genesis hash for hash chain
genesis_hash: str = "genesis"
```

## Database Setup

### PostgreSQL

1. Create database and user:
```sql
CREATE DATABASE audit_db;
CREATE USER audit_user WITH PASSWORD 'audit_pass';
GRANT ALL PRIVILEGES ON DATABASE audit_db TO audit_user;
```

2. Tables are created automatically on first run.

### Schema

```sql
CREATE TABLE audit_log_entries (
    id SERIAL PRIMARY KEY,
    log_id VARCHAR UNIQUE NOT NULL,
    component VARCHAR NOT NULL,
    event_type VARCHAR NOT NULL,
    action_metadata JSON NOT NULL,
    zt_at JSON,
    dpop_fingerprint VARCHAR NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    hash VARCHAR UNIQUE NOT NULL,
    previous_hash VARCHAR NOT NULL,
    plan_id VARCHAR
);

CREATE INDEX idx_component ON audit_log_entries(component);
CREATE INDEX idx_event_type ON audit_log_entries(event_type);
CREATE INDEX idx_timestamp ON audit_log_entries(timestamp);
CREATE INDEX idx_plan_id ON audit_log_entries(plan_id);
CREATE INDEX idx_log_id ON audit_log_entries(log_id);
```

## Running the Service

### Development

```bash
cd services/audit
python main.py
```

### Production

```bash
uvicorn services.audit.main:app --host 0.0.0.0 --port 8006
```

### Docker

```bash
docker build -t audit-service .
docker run -p 8006:8006 \
  -e DATABASE_URL=postgresql://... \
  audit-service
```

## Testing

### Unit Tests

```bash
pytest tests/test_audit_integration.py -v
```

### Property-Based Tests

```bash
pytest tests/test_audit_properties.py -v
```

Property tests verify:
- **Property 5**: Hash Chain Integrity
- **Property 13**: Audit Log Completeness
- **Property 32**: Timestamp Monotonicity
- **Property 4**: Round-Trip Consistency

## Security Considerations

1. **Append-Only**: Logs cannot be modified or deleted
2. **Cryptographic Chaining**: Any tampering breaks the hash chain
3. **Timestamp Verification**: Ensures chronological ordering
4. **Database Permissions**: Use read-only credentials for queries
5. **Access Control**: Implement authentication middleware in production

## Requirements

Validates the following requirements:
- **10.1**: Append-only log structure with cryptographic linking
- **10.2**: Store component identity, action metadata, ZT-AT, DPoP fingerprint
- **10.3**: Compute hash chain where each entry includes previous hash
- **10.4**: Expose POST /log, GET /verify, GET /logs endpoints
- **10.5**: Provide verification that hash chain is intact and unmodified
- **22.2**: Hash chain validation
- **22.3, 22.4, 22.5**: Timestamp monotonicity validation
- **23.5**: Round-trip consistency for audit logs
