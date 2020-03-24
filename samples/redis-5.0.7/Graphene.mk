# Sign REDIS-server for Graphene-SGX usage:
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
GRAPHENEDIR = /home/user/dev/graphene

SRCDIR = src
COMMIT = master

ifeq ($(DEBUG),1)
GRAPHENEDEBUG = inline
else
GRAPHENEDEBUG = none
endif

.PHONY=all
all: redis-server_suvm redis-server_suvm.manifest pal_loader
ifeq ($(SGX),1)
all: redis-server_suvm.manifest.sgx
endif

redis-server_suvm.manifest: redis-server_suvm.manifest.template
	sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
		-e 's|$$(GRAPHENEDEBUG)|'"$(GRAPHENEDEBUG)"'|g' \
		$< > $@

redis-server_suvm.manifest.sgx: redis-server_suvm.manifest src/redis-server_suvm
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem \
		-manifest $< -output $@ \
		-exec src/redis-server_suvm
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token \
		-output redis-server_suvm.token -sig redis-server_suvm.sig

########################### COPIES OF EXECUTABLES #############################

redis-server_suvm: src/redis-server_suvm
	cp $< $@

pal_loader:
	ln -s $(GRAPHENEDIR)/Runtime/pal_loader $@

################################## CLEANUP ####################################

.PHONY=clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest pal_loader redis-server_suvm

.PHONY=distclean
distclean: clean
	$(RM) -r $(SRCDIR)
