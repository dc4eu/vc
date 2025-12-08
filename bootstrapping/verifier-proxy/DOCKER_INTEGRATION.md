# Verifier Proxy - Docker Compose Integration

## MongoDB Bootstrap Integration

The verifier-proxy database bootstrap is now fully integrated into docker-compose.

### How It Works

When you run `docker compose up`, the following happens automatically:

1. **MongoDB starts** with a healthcheck
2. **mongo-init-verifier-proxy** service waits for MongoDB to be healthy
3. **Bootstrap scripts execute** automatically (indexes + sample clients)
4. **verifier-proxy service starts** after bootstrap completes successfully

### Services Added

#### mongo (updated)
- Added healthcheck to ensure MongoDB is ready
- Healthcheck: `mongosh --eval "db.adminCommand('ping')"`
- Interval: 10s, Timeout: 5s, Retries: 5

#### mongo-init-verifier-proxy (new)
- One-shot container that runs bootstrap scripts
- Uses official `mongo:7.0` image (includes mongosh)
- Mounts `bootstrapping/verifier-proxy/` directory
- Runs `bootstrap.sh` which executes:
  - `init_mongodb.sh` - Creates indexes
  - `register_clients.sh` - Registers sample clients
- Exits after completion (restart: no)

#### verifier-proxy (updated)
- Now depends on both `mongo` (healthy) and `mongo-init-verifier-proxy` (completed)
- Won't start until database is bootstrapped

### Usage

#### Start All Services (Including Bootstrap)
```bash
docker compose up
```

The bootstrap will run automatically on first startup.

#### Start Only Specific Services
```bash
# Start MongoDB and bootstrap
docker compose up mongo mongo-init-verifier-proxy

# Start verifier-proxy (bootstrap will run if not already done)
docker compose up verifier-proxy
```

#### Re-run Bootstrap Manually
```bash
# Remove the init container to force re-run
docker compose rm -f mongo-init-verifier-proxy

# Start services again
docker compose up mongo-init-verifier-proxy
```

#### Check Bootstrap Logs
```bash
# View bootstrap execution logs
docker compose logs mongo-init-verifier-proxy
```

#### Verify Bootstrap Results
```bash
# Connect to MongoDB
docker compose exec mongo mongosh verifier_proxy

# Check indexes
db.sessions.getIndexes()
db.clients.getIndexes()

# Check registered clients
db.clients.find({}, {client_id:1, client_name:1})
```

### Environment Variables

The init container uses these environment variables (pre-configured):
```yaml
environment:
  - MONGO_HOST=mongo
  - MONGO_PORT=27017
  - MONGO_DB=verifier_proxy
```

### Troubleshooting

#### Bootstrap Failed
```bash
# Check logs
docker compose logs mongo-init-verifier-proxy

# Common issues:
# 1. MongoDB not ready - healthcheck should prevent this
# 2. Script permissions - ensure scripts are executable
# 3. Script errors - check script syntax
```

#### Re-bootstrap After Changes
```bash
# Stop and remove containers
docker compose down

# Remove MongoDB data volume (WARNING: deletes all data)
docker volume rm vc_mongo_data

# Start fresh
docker compose up
```

#### Manual Bootstrap (Alternative)
```bash
# If automated bootstrap fails, run manually:
docker compose exec mongo bash

# Inside container:
cd /path/to/scripts
./bootstrap.sh
```

### Production Considerations

For production, consider:

1. **Remove init container** - Bootstrap once during deployment
2. **Use secrets** - Don't use default client secrets
3. **External MongoDB** - Bootstrap before deploying services
4. **Idempotent scripts** - Ensure scripts can run multiple times safely

### Script Modifications for Idempotency

The bootstrap scripts are designed to be idempotent:
- `init_mongodb.sh` - Creates indexes only if they don't exist
- `register_clients.sh` - Deletes and recreates sample clients

This means you can safely re-run the bootstrap without issues.

### Integration with CI/CD

In CI/CD pipelines:

```bash
# Start MongoDB
docker compose up -d mongo

# Wait for health
docker compose up -d --wait mongo

# Run bootstrap
docker compose up mongo-init-verifier-proxy

# Deploy application
docker compose up -d verifier-proxy
```

### Customizing Bootstrap

To add custom clients or modify bootstrap behavior:

1. Edit scripts in `bootstrapping/verifier-proxy/`
2. Remove init container: `docker compose rm -f mongo-init-verifier-proxy`
3. Restart: `docker compose up verifier-proxy`

The updated scripts will be mounted and executed automatically.
