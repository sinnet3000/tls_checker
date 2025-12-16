# Binary name
BINARY=tls_checker

# Version information
VERSION=0.10.0
BUILD_TIME=$(shell date +%FT%T%z)

# Build flags
LDFLAGS=-ldflags "-X main.version=${VERSION}"

# Platforms
PLATFORMS=linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64 windows/amd64

# Output directories
DIST_DIR=bin

.PHONY: all clean help

all: clean build

build:
	@mkdir -p ${DIST_DIR}
	@for platform in ${PLATFORMS}; do \
		OS=$$(echo $$platform | cut -f1 -d'/'); \
		ARCH=$$(echo $$platform | cut -f2 -d'/'); \
		echo "Building for $$OS/$$ARCH..."; \
		if [ "$$OS" = "windows" ]; then \
			GOOS=$$OS GOARCH=$$ARCH go build ${LDFLAGS} -o ${DIST_DIR}/${BINARY}_$${OS}_$${ARCH}.exe .; \
		else \
			GOOS=$$OS GOARCH=$$ARCH go build ${LDFLAGS} -o ${DIST_DIR}/${BINARY}_$${OS}_$${ARCH} .; \
		fi; \
	done
	@echo "Build complete! Binaries are in ${DIST_DIR}/"

clean:
	@rm -rf ${DIST_DIR}
	@echo "Cleaned ${DIST_DIR}/ directory"

# Show help
help:
	@echo "Available targets:"
	@echo "  all      - Clean and build all binaries (default)"
	@echo "  build    - Build binaries for all platforms"
	@echo "  clean    - Remove build artifacts"
	@echo "  help     - Show this help message"


