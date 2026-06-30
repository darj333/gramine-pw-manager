# Makefile for building the Gramine manifest for vault_crypto.py
# Adapted from gramine-src/CI-Examples/python/Makefile
 
ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)
 
ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
else
GRAMINE_LOG_LEVEL = error
endif
 
.PHONY: all
all: vault.manifest
ifeq ($(SGX),1)
all: vault.manifest.sgx vault.sig
endif
 
RA_TYPE ?= none
 
# Must point at the venv's own interpreter, not the system python3 —
# `command -v python3` resolves through the venv shim and realpath
# follows it straight back to /usr/bin/python3, which silently drops
# the venv's site-packages (argon2-cffi, cryptography) from the
# manifest's trusted/mounted paths.
# Must point at the venv's own python3 path AS-IS — do NOT realpath/resolve
# this. venv/bin/python3 is a symlink to the system interpreter, but Python
# detects "I'm in a venv" by checking for pyvenv.cfg relative to the path
# it was *invoked with* (sys.executable), not the resolved binary. Running
# the resolved system path silently drops venv site-packages from sys.path.
VENV_PYTHON := $(abspath venv/bin/python3)
VENV_DIR := $(abspath venv)
 
vault.manifest: vault.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dentrypoint=$(VENV_PYTHON) \
		-Dvenv_dir=$(VENV_DIR) \
		-Dra_type=$(RA_TYPE) \
		$< >$@
 
vault.manifest.sgx vault.sig &: vault.manifest
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx
 
.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.sig OUTPUT* *.PID TEST_STDOUT TEST_STDERR
	$(RM) -r __pycache__
 
.PHONY: distclean
distclean: clean
