# 
# Compiler Information
#
include ../config.mk

#
# Using mbedtls instead of openSSL
#
OE_CRYPTO_LIB?= mbedtls

# This selects seal plug-ins to be linked into an enclave
OE_SEAL_PLUGINS?= gcmaes

#
# Seal plug-ins are located in BUILD_TYPE specific locations.
# This Makefile searches plug-ins in the following order.
#
OE_SDK_BUILD_TYPES?= Release RelWithDebInfo MinSizeRel Debug

#
# Set up compiler + source files
#
CFLAGS=$(shell pkg-config oeenclave-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --libs)
INCDIR=$(shell pkg-config oeenclave-$(C_COMPILER) --variable=includedir)
CRYPTO_LDFLAGS=$(shell pkg-config oeenclave-$(COMPILER) --variable=${OE_CRYPTO_LIB}libs)

CRYPTO_SRC = $(OE_CRYPTO_LIB)_src
CXXINCDIR = -I. -I../ -I../..
CXXSRCS = ecalls.cpp \
	  dispatcher.cpp \
	  random.cpp \
	  encrypt.cpp \
	  signature.cpp \

#
# Seal plug-ins are searched in two steps.
#

# Step 1 - Determine BUILD_TYPE (hence the directory containing seal plug-ins)
SEAL_PLUGIN_DIR:= $(or $(firstword $(wildcard $(addsuffix /,	\
	$(addprefix $(LIBDIR)/enclave/objects-,$(OE_SDK_BUILD_TYPES))))),	\
	$(error Cannot determine CMAKE_BUILD_TYPE. Object paths:	\
		$(shell find $(LIBDIR)/enclave -type d -name objects-*)))

# Step 2 - Locate seal plug-in object files.
SEAL_PLUGINS:= $(foreach p,$(OE_SEAL_PLUGINS),$(or	\
	$(wildcard $(SEAL_PLUGIN_DIR)oeseal_$p/*.o),	\
	$(wildcard $(SEAL_PLUGIN_DIR)oeseal_$p-lvi-cfg/*.o),	\
	$(error Seal plug-in \'$p\' missing in $(SEAL_PLUGIN_DIR))))



all:
	$(MAKE) build
	$(MAKE) keys
	$(MAKE) sign

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../safekeeper.edl --trusted \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CXX) -g -c $(CXXFLAGS) -DOE_API_VERSION=2 -std=c++11 $(CXXINCDIR) \
		$(CXXSRCS)
	$(CC) -g -c $(CFLAGS) -DOE_API_VERSION=2 safekeeper_t.c -o safekeeper_t.o
	$(CXX) -o safekeeperenc ecalls.o dispatcher.o random.o encrypt.o signature.o safekeeper_t.o $(LDFLAGS) $(CRYPTO_LDFLAGS)

sign:
	oesign sign -e safekeeperenc -c safekeeper.conf -k private.pem

clean:
	rm -f safekeeperenc safekeeperenc.signed *.o safekeeper_t.* safekeeper_args.h private.pem public.pem

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem