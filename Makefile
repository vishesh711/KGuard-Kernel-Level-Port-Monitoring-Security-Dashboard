# KGuard Project Makefile

.PHONY: help setup build clean test install uninstall dev prod logs

# Default target
help:
	@echo "KGuard Security Monitoring System"
	@echo ""
	@echo "Available targets:"
	@echo "  setup     - Set up development environment"
	@echo "  build     - Build all components"
	@echo "  clean     - Clean build artifacts"
	@echo "  test      - Run all tests"
	@echo "  dev       - Start development environment"
	@echo "  prod      - Start production environment"
	@echo "  install   - Install kernel module (requires root)"
	@echo "  uninstall - Uninstall kernel module (requires root)"
	@echo "  logs      - View system logs"
	@echo "  help      - Show this help message"

# Setup development environment
setup:
	@echo "Setting up KGuard development environment..."
	@echo "Checking prerequisites..."
	@which docker > /dev/null || (echo "Docker is required" && exit 1)
	@which docker-compose > /dev/null || (echo "Docker Compose is required" && exit 1)
	@ls /lib/modules/$(shell uname -r)/build > /dev/null || (echo "Kernel headers are required: sudo apt install linux-headers-$(shell uname -r)" && exit 1)
	@echo "Creating environment files..."
	@cp backend/.env.example backend/.env 2>/dev/null || true
	@cp frontend/.env.example frontend/.env 2>/dev/null || true
	@echo "Setup complete!"

# Build all components
build:
	@echo "Building KGuard components..."
	$(MAKE) -C kernel clean all
	docker-compose build

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	$(MAKE) -C kernel clean
	docker-compose down --volumes --remove-orphans
	docker system prune -f

# Run all tests
test:
	@echo "Running tests..."
	$(MAKE) -C kernel test || true
	docker-compose run --rm backend pytest
	docker-compose run --rm frontend npm test

# Start development environment
dev:
	@echo "Starting development environment..."
	docker-compose up -d
	@echo "Services starting..."
	@echo "Frontend: http://localhost:3000"
	@echo "Backend API: http://localhost:8000"
	@echo "API Docs: http://localhost:8000/docs"

# Start production environment
prod:
	@echo "Starting production environment..."
	docker-compose -f docker-compose.prod.yml up -d
	@echo "Production services started"

# Install kernel module
install:
	@echo "Installing KGuard kernel module..."
	$(MAKE) -C kernel install

# Uninstall kernel module
uninstall:
	@echo "Uninstalling KGuard kernel module..."
	$(MAKE) -C kernel uninstall

# View logs
logs:
	@echo "KGuard system logs:"
	@echo "=== Kernel Module Logs ==="
	$(MAKE) -C kernel logs
	@echo ""
	@echo "=== Docker Logs ==="
	docker-compose logs --tail=50

# Status check
status:
	@echo "KGuard system status:"
	@echo "=== Kernel Module ==="
	$(MAKE) -C kernel status
	@echo ""
	@echo "=== Docker Services ==="
	docker-compose ps