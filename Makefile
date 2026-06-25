.PHONY: all proto server client agent db db-down run clean package

# ─── Paths ────────────────────────────────────────────────────

PROTO_DIR    := proto
GO_PROTO_OUT := teamserver/pkg/proto/apexpb
SERVER_BIN   := bin/teamserver

# ─── Default ──────────────────────────────────────────────────

all: proto server

# ─── Protobuf ─────────────────────────────────────────────────

proto:
	@mkdir -p $(GO_PROTO_OUT)
	@echo "[*] Generating protobuf code..."
	protoc \
		--proto_path=/usr/include \
		--proto_path=$(PROTO_DIR) \
		--go_out=$(GO_PROTO_OUT) \
		--go_opt=paths=source_relative \
		--go-grpc_out=$(GO_PROTO_OUT) \
		--go-grpc_opt=paths=source_relative \
		$(PROTO_DIR)/*.proto
	@echo "[+] Proto generation complete"

# ─── Team Server ──────────────────────────────────────────────

server:
	@echo "[*] Building team server..."
	cd teamserver && go build -o ../$(SERVER_BIN) ./cmd/teamserver
	@echo "[+] Binary: $(SERVER_BIN)"

server-run: server
	./$(SERVER_BIN) -config teamserver/config.yaml

# Run: start db (if needed) + team server
run:
	@chmod +x scripts/start.sh 2>/dev/null || true
	./scripts/start.sh

# ─── Client ───────────────────────────────────────────────────

client-install:
	cd client && npm install

client-dev:
	cd client && npm run dev

client-build:
	cd client && npm run build

client-tauri:
	cd client && npm run tauri dev

# Build Tauri client and copy to release/ (needs: npm, cargo; unset CI if in CI env)
client-release:
	@chmod +x scripts/build-client-release.sh 2>/dev/null || true
	@./scripts/build-client-release.sh

# ─── Agent (payload generation) ────────────────────────────────

agent:
	@echo "[*] Building agent..."
	cd agent && make exe
	@echo "[+] Agent: agent/agent.exe"

# ─── Database ─────────────────────────────────────────────────

# Rootless Podman needs the user socket (creates /run/user/$UID/podman/podman.sock).
# Run once: systemctl --user enable --now podman.socket
# Use docker compose if available, else podman compose; fail with a clear message if neither exists
db:
	@systemctl --user start podman.socket 2>/dev/null || true
	@if command -v docker >/dev/null 2>&1; then \
		docker compose -f deployments/docker-compose.yml up -d; \
	elif command -v podman >/dev/null 2>&1; then \
		podman compose -f deployments/docker-compose.yml up -d; \
	else \
		echo "Error: neither docker nor podman found. Install docker.io (or podman) and try again."; exit 1; \
	fi

db-down:
	@systemctl --user start podman.socket 2>/dev/null || true
	@if command -v docker >/dev/null 2>&1; then docker compose -f deployments/docker-compose.yml down; \
	elif command -v podman >/dev/null 2>&1; then podman compose -f deployments/docker-compose.yml down; \
	else echo "Error: neither docker nor podman found."; exit 1; fi

db-reset:
	@systemctl --user start podman.socket 2>/dev/null || true
	@if command -v docker >/dev/null 2>&1; then \
		docker compose -f deployments/docker-compose.yml down -v && docker compose -f deployments/docker-compose.yml up -d; \
	elif command -v podman >/dev/null 2>&1; then \
		podman compose -f deployments/docker-compose.yml down -v && podman compose -f deployments/docker-compose.yml up -d; \
	else echo "Error: neither docker nor podman found."; exit 1; fi

# ─── Package (release bundle) ────────────────────────────────

RELEASE_DIR := release

package: server client-release
	@echo "[*] Packaging release bundle..."
	@cp $(SERVER_BIN) $(RELEASE_DIR)/teamserver
	@chmod +x $(RELEASE_DIR)/teamserver $(RELEASE_DIR)/apex-client
	@cp deployments/docker-compose.yml $(RELEASE_DIR)/docker-compose.yml
	@rm -rf $(RELEASE_DIR)/migrations
	@mkdir -p $(RELEASE_DIR)/migrations
	@cp migrations/*.sql $(RELEASE_DIR)/migrations/
	@rm -rf $(RELEASE_DIR)/profiles
	@mkdir -p $(RELEASE_DIR)/profiles
	@cp profiles/*.yaml $(RELEASE_DIR)/profiles/
	@rm -rf $(RELEASE_DIR)/agent
	@mkdir -p $(RELEASE_DIR)/agent
	@cp agent/Makefile agent/*.c agent/*.h $(RELEASE_DIR)/agent/
	@rm -rf $(RELEASE_DIR)/bofs
	@cp -r bofs $(RELEASE_DIR)/bofs
	@echo "[+] Release bundle ready in $(RELEASE_DIR)/"
	@echo "    Contents:"
	@ls -1 $(RELEASE_DIR)/ | sed 's/^/      /'

# ─── Clean ────────────────────────────────────────────────────

clean:
	rm -rf bin/
	rm -rf client/dist/
	rm -rf $(GO_PROTO_OUT)/*.go
	cd agent && make clean 2>/dev/null || true
