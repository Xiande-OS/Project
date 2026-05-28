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
