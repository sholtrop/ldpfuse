// Static version of the passthrough file system for testing purposes.
#include "ldpfuse.h"
#include <err.h>

ssize_t simple_read(int fd, void *buf, size_t count, off_t offset,
                    orig_pread_t pread_fn) {
  LDP_FUSE_DEBUG_PRINT("simple_read\n");
  return pread_fn(fd, buf, count, offset);
}

int simple_stat(int dirfd, const char *restrict pathname,
                struct stat *restrict statbuf, int flags,
                orig_fstatat_t fstatat_fn) {

  LDP_FUSE_DEBUG_PRINT("simple_stat\n");
  return fstatat_fn(dirfd, pathname, statbuf, flags);
}

int simple_open(int dirfd, const char *pathname, int flags, mode_t mode,
                orig_openat_t openat_fn) {
  LDP_FUSE_DEBUG_PRINT("simple_open\n");
  return openat_fn(dirfd, pathname, flags, mode);
}

ssize_t simple_write(int fd, const void *buf, size_t count, off_t offset,
                     orig_pwrite_t pwrite_fn) {
  return pwrite_fn(fd, buf, count, 0);
}

ssize_t simple_readlink(const char *path, char *buf, size_t bufsize,
                        orig_readlink_t readlink_fn) {
  LDP_FUSE_DEBUG_PRINT("simple_readlink\n");
  return readlink_fn(path, buf, bufsize);
}

int simple_mknod(int fd, const char *path, mode_t mode, dev_t dev,
                 orig_mknodat_t mknod_fn) {
  LDP_FUSE_DEBUG_PRINT("simple_mknod\n");
  return mknod_fn(fd, path, mode, dev);
}

int simple_mkdir(const char *path, mode_t mode, orig_mkdir_t mkdir_fn) {
  LDP_FUSE_DEBUG_PRINT("simple_mkdir\n");
  return mkdir_fn(path, mode);
}

int simple_rmdir(const char *path, orig_rmdir_t rmdir_fn) {
  LDP_FUSE_DEBUG_PRINT("simple_rmdir\n");
  return rmdir_fn(path);
}

int simple_symlink(const char *path1, const char *path2,
                   orig_symlink_t symlink_fn) {
  LDP_FUSE_DEBUG_PRINT("simple_symlink\n");
  return symlink_fn(path1, path2);
}

int simple_rename(const char *path1, const char *path2,
                  orig_rename_t rename_fn) {
  LDP_FUSE_DEBUG_PRINT("simple_rename\n");
  return rename_fn(path1, path2);
}

int simple_link(const char *path1, const char *path2, orig_link_t link_fn) {
  LDP_FUSE_DEBUG_PRINT("simple_link\n");
  return link_fn(path1, path2);
}

int simple_chmod(const char *path, mode_t mode, orig_chmod_t chmod_fn) {
  LDP_FUSE_DEBUG_PRINT("simple_chmod\n");
  return chmod_fn(path, mode);
}

int simple_chown(const char *path, uid_t owner, gid_t group,
                 orig_chown_t chown_fn) {
  LDP_FUSE_DEBUG_PRINT("simple_chown\n");
  return chown_fn(path, owner, group);
}

int simple_truncate(const char *path, off_t size, orig_truncate_t truncate_fn) {
  LDP_FUSE_DEBUG_PRINT("simple_truncate\n");
  return truncate_fn(path, size);
}

int simple_close(int fd, orig_close_t close_fn) {
  LDP_FUSE_DEBUG_PRINT("simple_close\n");
  return close_fn(fd);
}

DIR *simple_opendir(const char *path, orig_opendir_t opendir_fn) {
  LDP_FUSE_DEBUG_PRINT("simple_opendir\n");
  return opendir_fn(path);
}

int simple_faccessat(const char *path, int mode, orig_faccessat_t access_fn) {
  LDP_FUSE_DEBUG_PRINT("simple_faccessat\n");
  return access_fn(path, mode);
}

int simple_unlink(const char *path, orig_unlink_t unlink_fn) {
  LDP_FUSE_DEBUG_PRINT("simple_unlink\n");
  return unlink_fn(path);
}

ssize_t simple_getxattr(const char *path, const char *name, void *value,
                        size_t size, orig_getxattr_t getxattr_fn) {
  LDP_FUSE_DEBUG_PRINT("simple_getxattr\n");
  return getxattr_fn(path, name, value, size);
}

void init_test_fuse() {
  struct ldp_fuse_funcs funcs = {.read = simple_read,
                                 .stat = simple_stat,
                                 .open = simple_open,
                                 .write = simple_write,
                                 .readlink = simple_readlink,
                                 .mknod = simple_mknod,
                                 .mkdir = simple_mkdir,
                                 .unlink = simple_unlink,
                                 .rmdir = simple_rmdir,
                                 .symlink = simple_symlink,
                                 .rename = simple_rename,
                                 .link = simple_link,
                                 .chmod = simple_chmod,
                                 .chown = simple_chown,
                                 .truncate = simple_truncate,
                                 .close = simple_close,
                                 .opendir = simple_opendir,
                                 .access = simple_faccessat,
                                 .getxattr = simple_getxattr};
  ldp_fuse_init(&funcs);
}