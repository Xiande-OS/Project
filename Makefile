# xiande-os — entry Makefile for the 2026 OS-Kernel contest.
#
# The contest harness:
#   1. Clones the repo, strips every hidden file/dir (.git, .cargo, ...).
#   2. Runs `make all` at the project root.
#   3. Boots the produced `kernel-rv` / `kernel-la` ELFs under QEMU.
#
# Step 1 means we can't ship a `.cargo/config.toml` directly — they'd be
# deleted before make sees them. We keep them under `cargo/` (no dot) and
# the `prepare` target rebuilds the hidden tree before invoking cargo.
#
# Toolchain policy: we deliberately do NOT ship a rust-toolchain.toml.
# Having one with `channel = "stable"` triggered rustup to upgrade the
# grader's already-installed stable, and on the grader machine
# /root/.rustup/toolchains and /root/.rustup/tmp sit on different mount
# points — the rename-replace during the upgrade failed with EXDEV
# (Invalid cross-device link) and aborted the build. We just use whatever
# toolchain the grader has set as default. The kernel uses zero unstable
# features and offset_of! (the only "modern" feature) is stable since
# 1.77, so any recent stable works.

CARGO        := cargo
TARGET_RV    := riscv64gc-unknown-none-elf
KERNEL_PKG   := kernel
RELEASE_DIR  := target/$(TARGET_RV)/release
KERNEL_ELF   := $(RELEASE_DIR)/$(KERNEL_PKG)

# Belt-and-suspenders: even without rust-toolchain.toml, refuse implicit
# toolchain installs/updates. Anything that tries to mutate the toolchain
# directory will just fail fast instead of half-replacing components.
export RUSTUP_AUTO_INSTALL := 0

# --- China detection + rustup-mirror swap --------------------------------
# If the build host is in mainland China, switch rustup to a domestic
# mirror so `rustup target add` (the one rustup operation we may need)
# isn't crawling out over the Great Firewall. Detection: one 3-second
# curl to Cloudflare's geo trace, look for "loc=CN". If detection fails
# (no curl, no network, timeout) we fall through to the default
# static.rust-lang.org — never blocking the build.
#
# Mirror selection: probe TUNA -> USTC -> rsproxy and pick the first that
# answers 200 on a tiny HEAD request (4s budget each). All three were
# verified live at the time this Makefile was written.
#
# Cargo itself doesn't need a mirror (all crates are vendored under
# vendor/), so only RUSTUP_* env vars are touched.
IS_CN := $(shell curl -fsS --max-time 3 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -c '^loc=CN')
ifeq ($(IS_CN),1)
RUSTUP_DIST_SERVER := $(shell \
  for m in https://mirrors.tuna.tsinghua.edu.cn/rustup \
           https://mirrors.ustc.edu.cn/rust-static \
           https://rsproxy.cn; do \
    if [ "$$(curl -fsSI --max-time 4 -o /dev/null -w '%{http_code}' \
        $$m/dist/channel-rust-stable.toml 2>/dev/null)" = "200" ]; then \
      echo $$m; break; \
    fi; \
  done)
ifneq ($(RUSTUP_DIST_SERVER),)
RUSTUP_UPDATE_ROOT := $(RUSTUP_DIST_SERVER)/rustup
export RUSTUP_DIST_SERVER RUSTUP_UPDATE_ROOT
$(info [mirror] CN host detected, using $(RUSTUP_DIST_SERVER))
else
$(info [mirror] CN host detected but no mirror responded; falling back to default)
endif
endif
# -------------------------------------------------------------------------

.PHONY: all prepare kernel-rv kernel-la clean

all: kernel-rv kernel-la

# Recreate the hidden cargo configuration the contest harness stripped,
# and best-effort ensure the riscv64 target std is installed.
prepare:
	@if [ -d cargo ] && [ ! -d .cargo ]; then cp -r cargo .cargo; fi
	@if [ -d kernel/cargo ] && [ ! -d kernel/.cargo ]; then cp -r kernel/cargo kernel/.cargo; fi
	@# Add the precompiled riscv64 std target IF it's missing AND rustup is
	@# present. Silenced + best-effort: if rustup isn't installed, or the
	@# target is already there, or the operation fails (e.g. read-only
	@# toolchain root), we just move on and let `cargo build` produce a
	@# clear error if the target really is unavailable. We do NOT call
	@# `rustup update` or `rustup toolchain install` — those are the
	@# operations that fail on the grader's split-filesystem layout.
	@command -v rustup >/dev/null 2>&1 || exit 0; \
	 rustup target list --installed 2>/dev/null | grep -qx '$(TARGET_RV)' || \
	   rustup target add $(TARGET_RV) >/dev/null 2>&1 || true

kernel-rv: prepare
	$(CARGO) build --release -p $(KERNEL_PKG) --target $(TARGET_RV) --offline
	cp $(KERNEL_ELF) kernel-rv

# LoongArch port is not yet implemented. Produce a minimal LoongArch64
# ELF so `make all` succeeds and the RV side can still be evaluated. The
# stub has no real code — when QEMU loads it the loongarch evaluator
# will immediately fail / time out, but `make all` will not.
kernel-la: scripts/build_la_stub.sh
	bash scripts/build_la_stub.sh kernel-la

clean:
	rm -rf target kernel-rv kernel-la .cargo kernel/.cargo
