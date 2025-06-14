#include <stdio.h>
#include <time.h>
#include <elf.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>

#include "common/include/rc4.h"
#include "common/include/obfuscation.h"
#include "common/include/defs.h"
#include "packer/include/elfutils.h"

/* Convenience macro for error checking libc calls */
#define CK_NEQ_PERROR(stmt, err)                                              \
  do {                                                                        \
    if ((stmt) == err) {                                                      \
      perror(#stmt);                                                          \
      return -1;                                                              \
    }                                                                         \
  } while(0)

  #define STRINGIFY_KEY(buf, key)                                             \
  {                                                                           \
    for (int i = 0; i < sizeof(key.bytes); i++) {                             \
      sprintf(&buf[i * 2], "%02hhx", key.bytes[i]);                           \
    };                                                                        \
  }

/* Needs to be defined for bddisasm */
int nd_vsnprintf_s(
    char *buffer,
    size_t sizeOfBuffer,
    size_t count,
    const char *format,
    va_list argptr)
{
  return vsnprintf(buffer, sizeOfBuffer, format, argptr);
}

/* Needs to be defined for bddisasm */
void* nd_memset(void *s, int c, size_t n)
{
  return memset(s, c, n);
}


// Obfuscate section names by XORing with a random byte
// NOTE: Disabled due to struct mismatch and missing shstrtab_size.
static void obfuscate_section_names(struct mapped_elf *elf) {
    // Obfuscation of section names is disabled due to missing shstrtab_size and writable string table.
    // If you want to enable this, ensure elf->shstrtab is a (char*) and you have its size.
    // Example:
    //   for (size_t i = 0; i < elf->shstrtab_size; ++i) {
    //       elf->shstrtab[i] ^= xor_key;
    //   }
}

// Insert a junk section at the end of the ELF
static void insert_junk_section(struct mapped_elf *elf) {
    size_t junk_size = 4096;
    void *new_elf = malloc(elf->size + junk_size);
    memcpy(new_elf, elf->start, elf->size);
    get_random_bytes((uint8_t*)new_elf + elf->size, junk_size);
    free(elf->start);
    elf->start = new_elf;
    elf->size += junk_size;
}

int main(int argc, char *argv[])
{
  char *input_path, *output_path;
  int c;
  int ret;

  while ((c = getopt (argc, argv, "v")) != -1) {
    switch (c) {
    case 'v':
      break;
    default:
      return -1;
    }
  }

  if (optind + 1 < argc) {
    input_path = argv[optind];
    output_path = argv[optind + 1];
  } else {
    return -1;
  }

  struct mapped_elf elf;
  ret = read_input_elf(input_path, &elf);
  if (ret == -1) {
    return -1;
  }

  obfuscate_section_names(&elf);
  insert_junk_section(&elf);

  if (full_strip(&elf) == -1) {
    return -1;
  }

  struct rc4_key key;
  CK_NEQ_PERROR(get_random_bytes(key.bytes, sizeof(key.bytes)), -1);
  char buf[(sizeof(key.bytes) * 2) + 1];
  STRINGIFY_KEY(buf, key);
  encrypt_memory_range(&key, elf.start, elf.size);

  FILE *output_file;
  CK_NEQ_PERROR(output_file = fopen(output_path, "w"), NULL);
  CK_NEQ_PERROR(fwrite(elf.start, elf.size, 1, output_file), 0);
  CK_NEQ_PERROR(fclose(output_file), EOF);
  CK_NEQ_PERROR(
      chmod(output_path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH), -1);

  return 0;
}


