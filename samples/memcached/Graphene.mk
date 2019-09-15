# Build Memcached as follows:
#
# - make               -- create non-SGX no-debug-log manifest
# - make SGX=1         -- create SGX no-debug-log manifest
# - make SGX=1 DEBUG=1 -- create SGX debug-log manifest
#
# Any of these invocations clones Memcached git repository and builds Memcached
# in default configuration and in the latest (master branch) version.
#
# Use `make clean` to remove Graphene-generated files and `make distclean` to
# additionally remove the cloned Memcached git repository.

################################# CONSTANTS ###################################

# Relative path to Graphene root
GRAPHENEDIR = ../../../../..

SRCDIR = src
COMMIT = master

ifeq ($(DEBUG),1)
GRAPHENEDEBUG = inline
else
GRAPHENEDEBUG = none
endif

.PHONY=all
all: memcached memcached.manifest pal_loader
ifeq ($(SGX),1)
all: memcached.manifest.sgx
endif

############################ MEMCACHED EXECUTABLE #############################

# Memcached is built as usual, without any changes to the build process. The
# source is cloned from a public GitHub repo (master tip) and built via classic
# ./autogen.sh && ./configure && make. The result of this build process is
# the final executable "src/memcached".

$(SRCDIR)/configure:
	git clone --recursive https://github.com/memcached/memcached $(SRCDIR)
	cd $(SRCDIR) && git checkout $(COMMIT)
	cd $(SRCDIR) && ./autogen.sh

$(SRCDIR)/memcached: $(SRCDIR)/configure
	cd $(SRCDIR) && ./configure
	cd $(SRCDIR) && make

############################## MEMCACHED MANIFEST #############################

# The template file contains almost all necessary information to run Memcached
# under Graphene / Graphene-SGX. We create memcached.manifest (to be run under
# non-SGX Graphene) by simply replacing variables in the template file via sed.

memcached.manifest: memcached.manifest.template
	sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
		-e 's|$$(GRAPHENEDEBUG)|'"$(GRAPHENEDEBUG)"'|g' \
		$< > $@

# Manifest for Graphene-SGX requires special "pal-sgx-sign" procedure. This
# procedure measures all Memcached dependencies (shared libraries and trusted
# files), measures Memcached code/data pages, and adds measurements in the
# resulting manifest.sgx file (among other, less important SGX options).
#
# Additionally, Graphene-SGX requires EINITTOKEN and SIGSTRUCT objects (see
# SGX hardware ABI, in particular EINIT instruction). The "pal-sgx-get-token"
# script generates these objects and puts them in files .token and .sig
# respectively. Note that filenames must be the same as the executable/manifest
# name (i.e., "memcached").

memcached.manifest.sgx: memcached.manifest memcached_suvm_orig
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem \
		-manifest $< -output $@ \
		-exec memcached_suvm_orig
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token \
		-output memcached.token -sig memcached.sig

########################### COPIES OF EXECUTABLES #############################

# Memcached build process creates the final executable as src/memcached. For
# simplicity, copy it into our root directory.
# Also, create a link to pal_loader for simplicity.

memcached: memcached_suvm_orig
	cp $< $@

pal_loader:
	ln -s $(GRAPHENEDIR)/Runtime/pal_loader $@

################################## CLEANUP ####################################

.PHONY=clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest pal_loader memcached

.PHONY=distclean
distclean: clean
	$(RM) -r $(SRCDIR)
