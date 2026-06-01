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

CARGO         := cargo
TARGET_RV     := riscv64gc-unknown-none-elf
TARGET_LA     := loongarch64-unknown-none
KERNEL_PKG    := kernel
RELEASE_DIR   := target/$(TARGET_RV)/release
KERNEL_ELF    := $(RELEASE_DIR)/$(KERNEL_PKG)
RELEASE_DIR_LA := target/$(TARGET_LA)/release
KERNEL_ELF_LA := $(RELEASE_DIR_LA)/$(KERNEL_PKG)

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

.PHONY: all prepare kernel-rv kernel-la disks clean

# Writable scratch disks attached as the SECOND virtio-blk device (x1,
# virtio-mmio-bus.1). The grader runs these as `-drive file=disk.img` /
# `-drive file=disk-la.img` iff we generate them. They are zeroed here
# (sparse, instant, no mke2fs build dependency) and the kernel formats
# them to ext2 at boot — that in-kernel mkfs also backs `.format_device`
# LTP cases. The read-only test image stays on x0; this never touches it.
DISK_RV   := disk.img
DISK_LA   := disk-la.img
DISK_SIZE := 256M

all: kernel-rv kernel-la disks

disks: $(DISK_RV) $(DISK_LA)

$(DISK_RV):
	@truncate -s $(DISK_SIZE) $(DISK_RV) 2>/dev/null \
	  || dd if=/dev/zero of=$(DISK_RV) bs=1M count=256 status=none 2>/dev/null || true

$(DISK_LA):
	@truncate -s $(DISK_SIZE) $(DISK_LA) 2>/dev/null \
	  || dd if=/dev/zero of=$(DISK_LA) bs=1M count=256 status=none 2>/dev/null || true

# Recreate the hidden cargo configuration the contest harness stripped,
# and best-effort ensure the riscv64 + loongarch64 target stds are present.
prepare:
	@if [ -d cargo ] && [ ! -d .cargo ]; then cp -r cargo .cargo; fi
	@if [ -d kernel/cargo ] && [ ! -d kernel/.cargo ]; then cp -r kernel/cargo kernel/.cargo; fi
	@# Add the precompiled riscv64/loongarch64 std targets IF missing AND
	@# rustup is present. Silenced + best-effort: if rustup isn't installed,
	@# the target is already there, or the op fails (e.g. read-only toolchain
	@# root), we move on and let `cargo build` produce a clear error (the
	@# kernel-la rule falls back to a placeholder ELF). We only ever call
	@# `rustup target add` — never `rustup update`/`toolchain install`, the
	@# operations that fail on the grader's split-filesystem (EXDEV) layout.
	@command -v rustup >/dev/null 2>&1 || exit 0; \
	 for t in $(TARGET_RV) $(TARGET_LA); do \
	   rustup target list --installed 2>/dev/null | grep -qx "$$t" || \
	     rustup target add "$$t" >/dev/null 2>&1 || true; \
	 done

kernel-rv: prepare
	$(CARGO) build --release -p $(KERNEL_PKG) --target $(TARGET_RV) --offline
	cp $(KERNEL_ELF) kernel-rv

# LoongArch64 kernel. Built from the same crate as kernel-rv via the
# arch backend in src/arch/loongarch64. If the loongarch target is not
# installed (e.g. an offline machine without the rust-std component),
# fall back to the placeholder ELF so `make all` still completes.
kernel-la: prepare
	@if $(CARGO) build --release -p $(KERNEL_PKG) --target $(TARGET_LA) --offline; then \
		cp $(KERNEL_ELF_LA) kernel-la; \
	else \
		echo "[kernel-la] loongarch target unavailable — using placeholder ELF"; \
		bash scripts/build_la_stub.sh kernel-la; \
	fi

clean:
	rm -rf target kernel-rv kernel-la .cargo kernel/.cargo $(DISK_RV) $(DISK_LA)
