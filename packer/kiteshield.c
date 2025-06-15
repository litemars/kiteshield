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
#include <libgen.h>

#include "common/include/rc4.h"
#include "common/include/obfuscation.h"
#include "common/include/defs.h"
#include "packer/include/elfutils.h"

#include "loader/out/generated_loader_rt.h"

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



// --- Utility implementations for packer ---
#include <stdint.h>

static int get_random_bytes(void *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, len, f);
    fclose(f);
    return n == len ? 0 : -1;
}

static int read_input_elf(char *path, struct mapped_elf *elf) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    void *buf = malloc(size);
    if (!buf) { fclose(f); return -1; }
    if (fread(buf, 1, size, f) != size) { free(buf); fclose(f); return -1; }
    fclose(f);
    parse_mapped_elf(buf, size, elf);
    return 0;
}

static void encrypt_memory_range(struct rc4_key *key, void *start, size_t len) {
    struct rc4_state rc4;
    rc4_init(&rc4, key->bytes, sizeof(key->bytes));
    uint8_t *curr = (uint8_t *)start;
    for (size_t i = 0; i < len; i++) {
        curr[i] ^= rc4_get_byte(&rc4);
    }
}

#define LOADER_ELF_PATH "/../loader/out/rt/loader-elf"

static char* get_loader_path() {
    char exec_path[4096];
    ssize_t len = readlink("/proc/self/exe", exec_path, sizeof(exec_path)-1);
    if (len == -1) return NULL;
    exec_path[len] = '\0';
    
    char* dir = dirname(exec_path);
    char* full_path = malloc(strlen(dir) + strlen(LOADER_ELF_PATH) + 1);
    if (!full_path) return NULL;
    
    strcpy(full_path, dir);
    strcat(full_path, LOADER_ELF_PATH);
    return full_path;
}

int main(int argc, char *argv[])
{
  char *input_path, *output_path;
  int c, ret;

  while ((c = getopt(argc, argv, "v")) != -1) {
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

  // Read loader ELF file
  char* loader_path = get_loader_path();
  if (!loader_path) {
    perror("Failed to resolve loader path");
    return -1;
  }
  
  FILE *f_loader = fopen(loader_path, "rb");
  if (!f_loader) {
    perror("fopen loader");
    free(loader_path);
    return -1;
  }
  free(loader_path);

  fseek(f_loader, 0, SEEK_END);
  size_t loader_size = ftell(f_loader);
  fseek(f_loader, 0, SEEK_SET);
  void *loader = malloc(loader_size);
  if (!loader) { fclose(f_loader); return -1; }
  if (fread(loader, 1, loader_size, f_loader) != loader_size) {
    free(loader); fclose(f_loader); return -1;
  }
  fclose(f_loader);

  // Read input ELF to be packed
  struct mapped_elf elf;
  ret = read_input_elf(input_path, &elf);
  if (ret == -1) {
    free(loader);
    return -1;
  }

  // Generate RC4 key and inject into loader (at offset 0)
  struct rc4_key key;
  CK_NEQ_PERROR(get_random_bytes(key.bytes, sizeof(key.bytes)), -1);
  memcpy(loader, &key, sizeof(key));

  // Encrypt the payload
  encrypt_memory_range(&key, elf.start, elf.size);

  // Write output ELF: loader ELF + encrypted payload
  FILE *output_file = fopen(output_path, "wb");
  CK_NEQ_PERROR(output_file, NULL);
  CK_NEQ_PERROR(fwrite(loader, loader_size, 1, output_file), 0);
  CK_NEQ_PERROR(fwrite(elf.start, elf.size, 1, output_file), 0);
  CK_NEQ_PERROR(fclose(output_file), EOF);
  CK_NEQ_PERROR(
      chmod(output_path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH), -1);

  free(loader);
  return 0;
}


