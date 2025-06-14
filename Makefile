# Top-level Makefile for Kiteshield (ARM64 only, no tests)

.PHONY: all loader packer clean

all: loader packer

loader:
	$(MAKE) -C loader

packer:
	$(MAKE) -C packer

clean:
	$(MAKE) -C loader clean
	$(MAKE) -C packer clean
