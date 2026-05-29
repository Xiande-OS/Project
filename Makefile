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

CARGO        := cargo
TARGET_RV    := riscv64gc-unknown-none-elf
KERNEL_PKG   := kernel
RELEASE_DIR  := target/$(TARGET_RV)/release
KERNEL_ELF   := $(RELEASE_DIR)/$(KERNEL_PKG)

# --- China detection + rustup-mirror swap --------------------------------
# If the build host is in mainland China, switch rustup to a domestic
# mirror so the toolchain / target-std download isn't crawling out over the
# Great Firewall. Detection: one 3-second curl to Cloudflare's geo trace,
# look for "loc=CN". If detection fails (no curl, no network, timeout) we
# fall through to the default static.rust-lang.org — never blocking the
# build.
#
# Mirror selection: probe TUNA -> USTC -> rsproxy and pick the first that
# answers 200 on a tiny HEAD request (4s budget each). All three were
# verified live at the time this Makefile was written; the probe protects
# against any one being down on the day.
#
# Cargo itself doesn't need a mirror (all crates are vendored under
# vendor/), so only RUSTUP_* env vars are touched. They're export'd so
# every recipe — and the rustup proxy that cargo spawns — inherits them.
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

# Recreate the hidden cargo configuration the contest harness stripped.
prepare:
	@if [ -d cargo ] && [ ! -d .cargo ]; then cp -r cargo .cargo; fi
	@if [ -d kernel/cargo ] && [ ! -d kernel/.cargo ]; then cp -r kernel/cargo kernel/.cargo; fi

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
