# Kiteshield

A packer/protector for ARM64 ELF binaries on Linux. Kiteshield wraps ELF
binaries with RC4 encryption and injects them with loader code that decrypts,
maps, and executes the packed binary entirely in userspace. The loader also
implements anti-debugging techniques to make packed binaries harder to reverse-engineer.

## Building Kiteshield

Kiteshield no longer depends on the Bitdefender disassembler (bddisasm) and is now ARM64-only.
To build the packer:

```
cd packer
make
```

You can build in debug mode with:

```
make debug
```

## Using Kiteshield

To pack a binary called `program` and output the packed binary to `packed.ks`,
run:

```
./kiteshield program packed.ks
```

The packed binary will be RC4-encrypted, have obfuscated section names, and include junk data for obfuscation.

## Codebase Layout

Kiteshield is composed of two separate parts. The packer is a regular C
application that reads and encrypts input binaries. The loader is a freestanding C application responsible for decryption and anti-debugging functionality that is injected into input binaries by the packer. Code that is common to both can be found in the `common/` directory.

## Limitations

Kiteshield is intended for academic and research purposes. Packed binaries may not be portable across all ARM64 Linux environments.

## License

[MIT](LICENSE)
