PHONY: all build clean run debug

OE_CRYPTO_LIB := mbedtls
export OE_CRYPTO_LIB

all: build

build:
	$(MAKE) -C enclave
	$(MAKE) -C host

clean:
	$(MAKE) -C enclave clean
	$(MAKE) -C host clean

run:
	host/safekeeperhost enclave/safekeeperenc.signed

debug:
	/opt/openenclave/bin/oegdb -arg ./host/safekeeperhost ./enclave/safekeeperenc.signed