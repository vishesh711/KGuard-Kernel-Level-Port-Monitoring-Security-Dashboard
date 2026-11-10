# KGuard: top-level targets. Component details are in kernel/, agent/,
# backend/ and frontend/ (each has its own Makefile or scripts and README).

COMPOSE ?= docker compose

.PHONY: help setup build clean test test-kernel dev prod down install uninstall status logs \
	attack-demo lab bench

help:
	@echo "KGuard"
	@echo ""
	@echo "  setup        Check prerequisites; create .env and backend/.env from the examples"
	@echo "  build        Build the kernel module, the agent and the containers"
	@echo "  test         Backend and frontend tests (local Python and Node)"
	@echo "  test-kernel  The kernel suite in a throwaway VM (virtme-ng; see kernel/README.md)"
	@echo "  dev          Start the development stack (backend :8000, frontend :3000)"
	@echo "  prod         Start the production stack (docs/DEPLOYMENT.md)"
	@echo "  down         Stop whichever stack is running (data volumes are kept)"
	@echo "  install      Load the kernel module (root)"
	@echo "  uninstall    Unload the kernel module (root)"
	@echo "  status       Module and container status"
	@echo "  logs         Recent module and container logs"
	@echo "  clean        Remove build output (not containers' data)"
	@echo "  attack-demo  Run every attack against KGuard in a VM, print pass/fail"
	@echo "  lab          Victim and attacker VMs with KGuard and attack tools"
	@echo "  bench        Packet-rate and CPU benchmarks in a VM (docs/BENCHMARKS.md)"

setup:
	@command -v docker >/dev/null || { echo "Docker is required"; exit 1; }
	@$(COMPOSE) version >/dev/null || { echo "Docker Compose v2 ('docker compose') is required"; exit 1; }
	@test -d /lib/modules/$(shell uname -r)/build || \
		{ echo "Kernel headers are required: sudo apt install linux-headers-$(shell uname -r)"; exit 1; }
	@test -f .env || { cp .env.example .env; echo "Created .env: fill in the secrets it lists"; }
	@test -f backend/.env || cp backend/.env.example backend/.env
	@echo "Setup done"

build:
	$(MAKE) -C kernel
	$(MAKE) -C kernel tools
	$(MAKE) -C agent
	$(COMPOSE) build

test:
	cd backend && python -m pytest
	cd frontend && npm test

test-kernel:
	kernel/tests/run_in_vm.sh

dev:
	$(COMPOSE) up -d --build
	@echo "Frontend http://localhost:3000, API http://localhost:8000 (docs at /docs)"

prod:
	$(COMPOSE) -f docker-compose.prod.yml up -d --build
	@echo "Dashboard on port 80, Grafana on port 3001"

down:
	-$(COMPOSE) down
	-$(COMPOSE) -f docker-compose.prod.yml down

install:
	$(MAKE) -C kernel install

uninstall:
	$(MAKE) -C kernel uninstall

status:
	@$(MAKE) -s -C kernel status
	@$(COMPOSE) ps

logs:
	@$(MAKE) -s -C kernel logs
	@$(COMPOSE) logs --tail=50

clean:
	$(MAKE) -C kernel clean
	$(MAKE) -C agent clean

# Real attacks against KGuard in a VM, each checked for its alert (roadmap P8.2)
attack-demo:
	scripts/attack_demo.sh

lab:
	scripts/lab.sh

bench:
	scripts/bench_vm.sh --flame
