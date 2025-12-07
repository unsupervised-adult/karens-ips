# SLIPS Upstream Patches

These patches fix issues in the upstream StratosphereLinuxIPS project.

## slips-redis-db1-connection.patch

**Issue**: SLIPS webui connects to Redis database 0 but SLIPS writes persistent data (like ml_detector:stats) to database 1, causing the dashboard to show stale/zero values.

**Fix**: Changed webui connection from database 0 to database 1.

**Location**: `slips_files/core/database/redis_db/database.py` line ~353

**Application**: This patch is automatically applied during Karen's IPS installation.

**Upstream Status**: Not yet submitted to StratosphereLinuxIPS project.
