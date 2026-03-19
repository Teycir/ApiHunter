SHELL := /bin/bash
.ONESHELL:
.SHELLFLAGS := -e -o pipefail -c

APP_NAME := apihunter

.PHONY: release
release:
	mkdir -p dist
	cargo build --release --bin $(APP_NAME)
	VERSION="$$(./target/release/$(APP_NAME) --version | awk '{print $$2}')"
	TARGET="$$(rustc -vV | awk '/^host:/ {print $$2}')"
	PKG="$(APP_NAME)-v$${VERSION}-$${TARGET}"
	STAGE="dist/$${PKG}"
	ARCHIVE="dist/$${PKG}.tar.gz"
	rm -rf "$${STAGE}" "$${ARCHIVE}" "$${ARCHIVE}.sha256"
	mkdir -p "$${STAGE}"
	install -m 0755 "target/release/$(APP_NAME)" "$${STAGE}/$(APP_NAME)"
	install -m 0644 Readme.md "$${STAGE}/README.md"
	install -m 0644 CHANGELOG.md "$${STAGE}/CHANGELOG.md"
	install -m 0644 Licence "$${STAGE}/LICENSE"
	tar -C dist -czf "$${ARCHIVE}" "$${PKG}"
	sha256sum "$${ARCHIVE}" > "$${ARCHIVE}.sha256"
	@echo "Release artifact: $${ARCHIVE}"
	@echo "Checksum file:   $${ARCHIVE}.sha256"
