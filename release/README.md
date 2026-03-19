# Apex C2 - Release Binaries

Pre-built binaries for Linux x86_64.

| Binary | Description |
|--------|-------------|
| `teamserver` | Go team server - run with `./teamserver -config ../teamserver/config.yaml` (or copy `config.yaml` here) |
| `apex-client` | Tauri desktop operator client |

**Requirements:**
- PostgreSQL and Redis running (see main README)
- Config: copy `../teamserver/config.yaml` to this dir or pass `-config /path/to/config.yaml`

**Run from project root (recommended):**
```bash
cd /path/to/Apex
./release/teamserver -config teamserver/config.yaml   # in one terminal
./release/apex-client                                  # in another
```
