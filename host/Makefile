include ../config.mk

CFLAGS=$(shell pkg-config oehost-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --libs)
INCDIR=$(shell pkg-config oehost-$(C_COMPILER) --variable=includedir)

all: build

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../safekeeper.edl --untrusted \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CXX) -g -c $(CXXFLAGS) host.cpp
	$(CC) -g -c $(CFLAGS) safekeeper_u.c
	$(CXX) -o safekeeperhost host.o safekeeper_u.o $(LDFLAGS)

clean:
	rm -f safekeeperhost safekeeper_u.* safekeeper_args.h *.o