// WARNING: This is not cryptographically secure

#include "ldpfuse.h"
#include <errno.h>
#include <unistd.h>

#define KEY 0b11110000

ssize_t encrypted_read(int fd, void *buf, size_t count, off_t offset,
                       orig_pread_t read_fn) {

  ssize_t read_bytes = read_fn(fd, buf, count, offset);
  for (size_t i = 0; i < read_bytes; i++) {
    ((unsigned char *)buf)[i] ^= KEY;
  }
  return read_bytes;
}

ssize_t encrypted_write(int fd, const void *buf, size_t count, off_t offset,
                        orig_pwrite_t write_fn) {

  for (size_t i = 0; i < count; i++) {
    ((unsigned char *)buf)[i] ^= KEY;
  }

  return write_fn(fd, buf, count, offset);
}

LDPRELOAD_FUSE_MAIN {
  struct ldp_fuse_funcs funcs;
  memset(&funcs, 0, sizeof(funcs));
  funcs.read = encrypted_read;
  funcs.write = encrypted_write;
  ldp_fuse_init(&funcs);
}