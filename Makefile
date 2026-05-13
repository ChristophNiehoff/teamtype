# SPDX-FileCopyrightText: 2026 TNG Technology Consulting GmbH <christoph.niehoff@tngtech.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

DIST_DIR := dist

$(DIST_DIR):
	mkdir -p $(DIST_DIR)

# ── Linux x64 ──────────────────────────────────────────────────────────────────
#
# Produces a dynamically linked binary for x86_64 Linux systems.
#
# Prerequisites (one-time setup):
#   rustup target add x86_64-unknown-linux-gnu

.PHONY: build-linux-x64
build-linux-x64: $(DIST_DIR)
	cargo build --release \
		--manifest-path daemon/Cargo.toml \
		--target x86_64-unknown-linux-gnu
	cp daemon/target/x86_64-unknown-linux-gnu/release/teamtype \
		$(DIST_DIR)/teamtype-linux-x64
	@echo "Binary written to $(DIST_DIR)/teamtype-linux-x64"

# ── Linux ARM64 ────────────────────────────────────────────────────────────────
#
# Produces a statically linked binary for ARM64 Linux systems using musl.
#
# Prerequisites (one-time setup):
#   rustup target add aarch64-unknown-linux-musl
#   apt-get install gcc-aarch64-linux-gnu  # or equivalent for your distro

.PHONY: build-linux-arm64
build-linux-arm64: $(DIST_DIR)
	cargo build --release \
		--manifest-path daemon/Cargo.toml \
		--target aarch64-unknown-linux-musl
	cp daemon/target/aarch64-unknown-linux-musl/release/teamtype \
		$(DIST_DIR)/teamtype-linux-arm64
	@echo "Binary written to $(DIST_DIR)/teamtype-linux-arm64"

# ── Darwin x64 (macOS Intel) ───────────────────────────────────────────────────
#
# Produces a binary for Intel-based macOS systems.
#
# Note: Cross-compiling to Darwin from Linux requires osxcross or similar.
# If building on macOS, this will work directly. On Linux, you may need to
# build these on a macOS machine or use a CI/CD system.
#
# Prerequisites (one-time setup):
#   rustup target add x86_64-apple-darwin

.PHONY: build-darwin-x64
build-darwin-x64: $(DIST_DIR)
	cargo build --release \
		--manifest-path daemon/Cargo.toml \
		--target x86_64-apple-darwin
	cp daemon/target/x86_64-apple-darwin/release/teamtype \
		$(DIST_DIR)/teamtype-darwin-x64
	@echo "Binary written to $(DIST_DIR)/teamtype-darwin-x64"

# ── Darwin ARM64 (macOS Apple Silicon) ─────────────────────────────────────────
#
# Produces a binary for Apple Silicon (M1/M2/M3) macOS systems.
#
# Note: Cross-compiling to Darwin from Linux requires osxcross or similar.
# If building on macOS, this will work directly. On Linux, you may need to
# build these on a macOS machine or use a CI/CD system.
#
# Prerequisites (one-time setup):
#   rustup target add aarch64-apple-darwin

.PHONY: build-darwin-arm64
build-darwin-arm64: $(DIST_DIR)
	cargo build --release \
		--manifest-path daemon/Cargo.toml \
		--target aarch64-apple-darwin
	cp daemon/target/aarch64-apple-darwin/release/teamtype \
		$(DIST_DIR)/teamtype-darwin-arm64
	@echo "Binary written to $(DIST_DIR)/teamtype-darwin-arm64"

# ── Darwin Universal (macOS Intel + Apple Silicon) ────────────────────────────
#
# Produces a universal ("fat") binary that runs natively on both Intel and
# Apple Silicon Macs.  Must be built on macOS (lipo is a macOS-only tool).
#
# Prerequisites (one-time setup):
#   rustup target add x86_64-apple-darwin
#   rustup target add aarch64-apple-darwin

.PHONY: build-darwin-universal
build-darwin-universal: $(DIST_DIR)
	cargo build --release \
		--manifest-path daemon/Cargo.toml \
		--target x86_64-apple-darwin
	cargo build --release \
		--manifest-path daemon/Cargo.toml \
		--target aarch64-apple-darwin
	lipo -create -output $(DIST_DIR)/teamtype-darwin-universal \
		daemon/target/x86_64-apple-darwin/release/teamtype \
		daemon/target/aarch64-apple-darwin/release/teamtype
	@echo "Universal binary written to $(DIST_DIR)/teamtype-darwin-universal"

# ── Android / Termux (ARM64) ───────────────────────────────────────────────────
#
# Produces an ET_DYN PIE binary accepted by Android's Bionic linker.
# The aarch64-unknown-linux-musl target produces a statically linked ET_EXEC
# (e_type=2) which Bionic rejects; aarch64-linux-android produces ET_DYN
# (e_type=3) natively.
#
# Prerequisites (one-time setup):
#   rustup target add aarch64-linux-android
#   export ANDROID_NDK_HOME=/path/to/ndk
#
# After building, the PT_TLS p_align field must be patched from 8 to 64 as
# required by Bionic on ARM64. Use the patch-tls-alignment utility for this
# (see the deployment instructions for the exact command).
#
# Verification:
#   file dist/teamtype-android-arm64
#     → ELF 64-bit LSB pie executable, ARM aarch64 ...
#   readelf -lW dist/teamtype-android-arm64 | grep TLS
#     → TLS ... 0x40     ← must be 0x40 (64), not 0x8

ANDROID_NDK_TOOLCHAIN ?= $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin
ANDROID_CLANG         := $(ANDROID_NDK_TOOLCHAIN)/aarch64-linux-android21-clang
ANDROID_AR            := $(ANDROID_NDK_TOOLCHAIN)/llvm-ar

.PHONY: build-android-arm64
build-android-arm64: $(DIST_DIR)
	@test -n "$(ANDROID_NDK_HOME)" || (echo "ERROR: ANDROID_NDK_HOME is not set"; exit 1)
	@test -x "$(ANDROID_CLANG)"   || (echo "ERROR: NDK clang not found at $(ANDROID_CLANG)"; exit 1)
	# CC_aarch64_linux_android  — used by the cc crate (ring, libgit2-sys, etc.)
	# AR_aarch64_linux_android  — used by the cc crate for archiving
	# CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER — used by Cargo for the final link step
	CC_aarch64_linux_android=$(ANDROID_CLANG) \
	AR_aarch64_linux_android=$(ANDROID_AR) \
	CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$(ANDROID_CLANG) \
	cargo build --release \
		--manifest-path daemon/Cargo.toml \
		--target aarch64-linux-android
	cp daemon/target/aarch64-linux-android/release/teamtype \
		$(DIST_DIR)/teamtype-android-arm64
	@echo "Binary written to $(DIST_DIR)/teamtype-android-arm64"
	@echo "Remember to patch PT_TLS p_align with patch-tls-alignment before deploying."
