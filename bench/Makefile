# Makefile for the Argon2id / EPC benchmark manifests.
# Derived from the project's Phase 3b Makefile (abspath venv fix retained).
#
# One manifest per experimental arm, named by TAG:
#   make TAG=direct
#   make SGX=1 TAG=static-8G ENCLAVE_SIZE=8G EDMM=0
#   make SGX=1 TAG=edmm      ENCLAVE_SIZE=default EDMM=1
# Invoke with:  gramine-direct bench-<TAG> /bench_kdf.py --m ...
#               gramine-sgx    bench-<TAG> /bench_kdf.py --m ...
#
# Anti-stale-build guard: every setting that changes the manifest is written
# to a stamp file (.cfg-<TAG>); the manifest depends on it, so changing a
# variable with an unchanged TAG still rebuilds (the original template read
# EDMM via env.get() at render time, which make could not see).

TAG ?= default
NAME := bench-$(TAG)

ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
else
GRAMINE_LOG_LEVEL = error
endif

RA_TYPE      ?= none
ENCLAVE_SIZE ?= default
MAX_THREADS  ?= 32
EDMM         ?= 0
SGX_DEBUG    ?= 1
ENABLE_STATS ?= 0
PREHEAT      ?= 0
SGX_SIGNER_KEY ?= $(HOME)/.config/gramine/enclave-key.pem

# Do NOT realpath: the venv python3 is a symlink and resolving it silently
# drops the venv's site-packages (Phase 2 issue 1).
VENV_PYTHON := $(abspath venv/bin/python3)
VENV_DIR    := $(abspath venv)
PY_VER      := $(shell $(VENV_PYTHON) -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null)
# Fail loudly: an empty PY_VER would silently produce a wrong PYTHONPATH.
ifeq ($(strip $(PY_VER)),)
$(error cannot run $(VENV_PYTHON); create the venv first: python3 -m venv venv && venv/bin/pip install --no-compile -r requirements-bench.txt)
endif

# no bytecode may be written during the
# build, since .pyc headers embed source mtime and enter sgx.trusted_files.
export PYTHONDONTWRITEBYTECODE := 1

CFG := tag=$(TAG) log=$(GRAMINE_LOG_LEVEL) ra=$(RA_TYPE) enc=$(ENCLAVE_SIZE) \
       thr=$(MAX_THREADS) edmm=$(EDMM) dbg=$(SGX_DEBUG) stats=$(ENABLE_STATS) \
       preheat=$(PREHEAT) py=$(PY_VER) arch=$(ARCH_LIBDIR)

.PHONY: all
all: $(NAME).manifest
ifeq ($(SGX),1)
all: $(NAME).manifest.sgx
endif

.PHONY: FORCE
FORCE:

.cfg-$(TAG): FORCE
	@echo '$(CFG)' | cmp -s - $@ || echo '$(CFG)' > $@

$(NAME).manifest: bench.manifest.template .cfg-$(TAG)
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dentrypoint=$(VENV_PYTHON) \
		-Dvenv_dir=$(VENV_DIR) \
		-Dpy_ver=$(PY_VER) \
		-Dra_type=$(RA_TYPE) \
		-Denclave_size=$(ENCLAVE_SIZE) \
		-Dmax_threads=$(MAX_THREADS) \
		-Dedmm=$(EDMM) \
		-Dsgx_debug=$(SGX_DEBUG) \
		-Denable_stats=$(ENABLE_STATS) \
		-Dpreheat=$(PREHEAT) \
		$< >$@

# Purge bytecode caches immediately before signing so MRENCLAVE depends only
# on source. The purge reaches the venv: its site-packages are trusted dirs.
$(NAME).manifest.sgx $(NAME).sig &: $(NAME).manifest bench_kdf.py
	find . $(VENV_DIR) -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
	find . $(VENV_DIR) -name '*.pyc' -delete 2>/dev/null || true
	gramine-sgx-sign \
		--key $(SGX_SIGNER_KEY) \
		--manifest $< \
		--output $<.sgx

.PHONY: clean
clean:
	$(RM) bench-*.manifest bench-*.manifest.sgx bench-*.sig .cfg-*
	$(RM) -r __pycache__

.PHONY: distclean
distclean: clean
