#ifndef LDP_FUSE_H
#define LDP_FUSE_H
#define _GNU_SOURCE
#define __USE_GNU

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <execinfo.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
  fcntl.h contains constant definitions that we need, but also `open` and
  `openat` This causes conflicts as symbols with those names are also
  necessarily defined here. We therefore overwrite them using #define.
*/
#define openat __renamed_openat
#define open __renamed_open
#include <fcntl.h>
#undef openat
#undef open

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/*
  from version GLIBC 2.32 unistd.h contains constant definitions that we need, but also `close_range`
  This causes conflicts as symbols with those names are also
  necessarily defined here. We therefore overwrite them using #define.
*/
#if (__GLIBC__ > 1 && __GLIBC_MINOR__ > 32)
#define close_range __renamed_close_range
#include <unistd.h>
#undef close_range
#else 
#include <unistd.h>
#endif

// Include `cwalk` directly as this lib is header-only
#include "./cwalk.c"

#ifdef LDP_FUSE_DEBUG
#define LDP_FUSE_DEBUG_PRINT(...) \
  do {                            \
    fprintf(stderr, __VA_ARGS__); \
  } while (false)
#else
#define LDP_FUSE_DEBUG_PRINT(...) \
  do {                            \
  } while (false)
#endif

#ifdef LDP_FUSE_THREAD_SAFE
#include <pthread.h>
#endif

// `readdir` function types
#define READDIR_ARGS DIR* dirp
typedef struct dirent* (*orig_readdir_t)(READDIR_ARGS);
typedef struct dirent* (*ldp_fuse_readdir_t)(READDIR_ARGS,
                                             orig_readdir_t readdir_fn);

// `read` function types
#define READ_ARGS int fd, void *buf, size_t count
typedef ssize_t (*orig_read_t)(READ_ARGS);

// `pread` function types.
#define PREAD_ARGS int fd, void *buf, size_t count, off_t offset
typedef ssize_t (*orig_pread_t)(PREAD_ARGS);
typedef ssize_t (*ldp_fuse_pread_t)(PREAD_ARGS, orig_pread_t read_fn);

// `open` function types
#define OPEN_ARGS const char *pathname, ...
typedef int (*orig_open_t)(OPEN_ARGS);

// `openat` function types
#define OPENAT_ARGS int dirfd, const char *pathname, int flags, mode_t mode
typedef int (*orig_openat_t)(OPENAT_ARGS);
typedef int (*ldp_fuse_openat_t)(OPENAT_ARGS, orig_openat_t open_fn);

// `fstatat` function typs
#define FSTATAT_ARGS                                                       \
  int dirfd, const char *restrict pathname, struct stat *restrict statbuf, \
      int flags
typedef int (*orig_fxstatat_t)(int ver, FSTATAT_ARGS);
typedef int (*orig_fstatat_t)(FSTATAT_ARGS);
typedef int (*ldp_fuse_fstatat_t)(FSTATAT_ARGS, orig_fstatat_t stat_fn);

// `getxattr` function types
#define GETXATTR_ARGS \
  const char *path, const char *name, void *value, size_t size
typedef ssize_t (*orig_getxattr_t)(GETXATTR_ARGS);
typedef ssize_t (*ldp_fuse_getxattr_t)(GETXATTR_ARGS,
                                       orig_getxattr_t getxattr_fn);

// `lgetxattr` function types
#define LGETXATTR_ARGS \
  const char *path, const char *name, void *value, size_t size
typedef ssize_t (*orig_lgetxattr_t)(LGETXATTR_ARGS);

// `fgetxattr` function types
#define FGETXATTR_ARGS int fd, const char *name, void *value, size_t size
typedef ssize_t (*orig_fgetxattr_t)(FGETXATTR_ARGS);

// `write` function types
#define WRITE_ARGS int fd, const void *buf, size_t count
typedef ssize_t (*orig_write_t)(WRITE_ARGS);

// `creat` function types
#define CREAT_ARGS const char *pathname, mode_t mode
typedef int (*orig_creat_t)(CREAT_ARGS);

// `pwrite` function types
#define PWRITE_ARGS int fd, const void *buf, size_t count, off_t offset
typedef ssize_t (*orig_pwrite_t)(PWRITE_ARGS);
typedef ssize_t (*ldp_fuse_pwrite_t)(PWRITE_ARGS, orig_pwrite_t write_fn);

// `readlink` function types
#define READLINK_ARGS const char *pathname, char *buf, size_t bufsiz
typedef ssize_t (*orig_readlink_t)(READLINK_ARGS);
typedef ssize_t (*ldp_fuse_readlink_t)(READLINK_ARGS,
                                       orig_readlink_t readlink_fn);

// `mknod` function types
#define MKNOD_ARGS const char *pathname, mode_t mode, dev_t dev
typedef int (*orig_mknod_t)(MKNOD_ARGS);
typedef int (*ldp_fuse_mknod_t)(MKNOD_ARGS, orig_mknod_t mknod_fn);

// `mknodat` function types
#define MKNODAT_ARGS int dirfd, const char *pathname, mode_t mode, dev_t dev
typedef int (*orig_mknodat_t)(MKNODAT_ARGS);
typedef int (*ldp_fuse_mknodat_t)(MKNODAT_ARGS, orig_mknodat_t mknodat_fn);

// `mkdir` function types
#define MKDIR_ARGS const char *pathname, mode_t mode
typedef int (*orig_mkdir_t)(MKDIR_ARGS);
typedef int (*ldp_fuse_mkdir_t)(MKDIR_ARGS, orig_mkdir_t mkdir_fn);

// `unlink` function types
#define UNLINK_ARGS const char* pathname
typedef int (*orig_unlink_t)(UNLINK_ARGS);
typedef int (*ldp_fuse_unlink_t)(UNLINK_ARGS, orig_unlink_t unlink_fn);

// `rmdir` function types
#define RMDIR_ARGS const char* pathname
typedef int (*orig_rmdir_t)(RMDIR_ARGS);
typedef int (*ldp_fuse_rmdir_t)(RMDIR_ARGS, orig_rmdir_t rmdir_fn);

// `symlink` function types
#define SYMLINK_ARGS const char *target, const char *linkpath
typedef int (*orig_symlink_t)(SYMLINK_ARGS);
typedef int (*ldp_fuse_symlink_t)(SYMLINK_ARGS, orig_symlink_t symlink_fn);

// `rename` function types
#define RENAME_ARGS const char *oldpath, const char *newpath
typedef int (*orig_rename_t)(RENAME_ARGS);
typedef int (*ldp_fuse_rename_t)(RENAME_ARGS, orig_rename_t rename_fn);

// `link` function types
#define LINK_ARGS const char *oldpath, const char *newpath
typedef int (*orig_link_t)(LINK_ARGS);
typedef int (*ldp_fuse_link_t)(LINK_ARGS, orig_link_t link_fn);

// `chmod` function types
#define CHMOD_ARGS const char *path, mode_t mode
typedef int (*orig_chmod_t)(CHMOD_ARGS);
typedef int (*ldp_fuse_chmod_t)(CHMOD_ARGS, orig_chmod_t chmod_fn);

// `chown` function types
#define CHOWN_ARGS const char *path, uid_t owner, gid_t group
typedef int (*orig_chown_t)(CHOWN_ARGS);
typedef int (*ldp_fuse_chown_t)(CHOWN_ARGS, orig_chown_t chown_fn);

// `truncate` function types
#define TRUNCATE_ARGS const char *path, off_t length
typedef int (*orig_truncate_t)(TRUNCATE_ARGS);
typedef int (*ldp_fuse_truncate_t)(TRUNCATE_ARGS, orig_truncate_t truncate_fn);

// `close` function types
#define CLOSE_ARGS int fd
typedef int (*orig_close_t)(CLOSE_ARGS);
typedef int (*ldp_fuse_close_t)(CLOSE_ARGS, orig_close_t close_fn);

// `opendir` function types
#define OPENDIR_ARGS const char* pathname
typedef DIR* (*orig_opendir_t)(OPENDIR_ARGS);
typedef DIR* (*ldp_fuse_opendir_t)(OPENDIR_ARGS, orig_opendir_t opendir_fn);

// `faccessat` function types
#define FACCESSAT_ARGS const char *pathname, int mode
typedef int (*orig_faccessat_t)(FACCESSAT_ARGS);
typedef int (*ldp_fuse_faccessat_t)(FACCESSAT_ARGS, orig_faccessat_t access_fn);

// `access` function types
#define ACCESS_ARGS const char *pathname, int mode
typedef int (*orig_access_t)(ACCESS_ARGS);

// `euidaccess` function types
#define EUIDACCESS_ARGS const char *pathname, int mode
typedef int (*orig_euidaccess_t)(EUIDACCESS_ARGS);

// `__xstat` function types
#define XSTAT_ARGS int ver, const char *path, struct stat *buf
typedef int (*orig_xstat_t)(XSTAT_ARGS);

// `__lxstat` function types
#define LXSTAT_ARGS int ver, const char *path, struct stat *buf
typedef int (*orig_lxstat_t)(LXSTAT_ARGS);

// `__fxstat` function types
#define FXSTAT_ARGS int ver, int fd, struct stat *buf
typedef int (*orig_fxstat_t)(FXSTAT_ARGS);

struct ldp_fuse_funcs {
  ldp_fuse_fstatat_t stat;
  ldp_fuse_readdir_t readdir;
  ldp_fuse_openat_t open;
  ldp_fuse_pread_t read;
  ldp_fuse_pwrite_t write;
  ldp_fuse_readlink_t readlink;
  ldp_fuse_mknodat_t mknod;
  ldp_fuse_mkdir_t mkdir;
  ldp_fuse_unlink_t unlink;
  ldp_fuse_rmdir_t rmdir;
  ldp_fuse_symlink_t symlink;
  ldp_fuse_rename_t rename;
  ldp_fuse_link_t link;
  ldp_fuse_chmod_t chmod;
  ldp_fuse_chown_t chown;
  ldp_fuse_truncate_t truncate;
  ldp_fuse_close_t close;
  ldp_fuse_opendir_t opendir;
  ldp_fuse_faccessat_t access;
  ldp_fuse_getxattr_t getxattr;
} funcs = {
    .stat = NULL,
    .readdir = NULL,
    .open = NULL,
    .read = NULL,
    .write = NULL,
    .readlink = NULL,
    .mknod = NULL,
    .mkdir = NULL,
    .unlink = NULL,
    .rmdir = NULL,
    .symlink = NULL,
    .rename = NULL,
    .link = NULL,
    .chmod = NULL,
    .chown = NULL,
    .truncate = NULL,
    .close = NULL,
    .opendir = NULL,
    .access = NULL,
    .getxattr = NULL,
};

orig_read_t orig_read;
orig_pread_t orig_pread;

orig_fxstat_t orig_fxstat;
orig_lxstat_t orig_lxstat;
orig_xstat_t orig_xstat;
orig_fxstatat_t orig_fxstatat;

orig_getxattr_t orig_getxattr;
orig_lgetxattr_t orig_lgetxattr;
orig_fgetxattr_t orig_fgetxattr;

orig_open_t orig_open;
orig_openat_t orig_openat;
orig_pwrite_t orig_pwrite;
orig_creat_t orig_creat;
orig_write_t orig_write;
orig_readlink_t orig_readlink;
orig_mknod_t orig_mknod;
orig_mknodat_t orig_mknodat;
orig_mkdir_t orig_mkdir;
orig_unlink_t orig_unlink;
orig_rmdir_t orig_rmdir;
orig_symlink_t orig_symlink;
orig_rename_t orig_rename;
orig_link_t orig_link;
orig_chmod_t orig_chmod;
orig_chown_t orig_chown;
orig_truncate_t orig_truncate;
orig_close_t orig_close;
orig_opendir_t orig_opendir;
orig_xstat_t orig_xstat;
orig_lxstat_t orig_lxstat;
orig_fxstat_t orig_fxstat;
orig_access_t orig_access;
orig_faccessat_t orig_faccessat;
orig_euidaccess_t orig_euidaccess;

#define LDP_FUSE_PATH "LDP_FUSE_PATH"
#define LDP_FUSE_DELIM ":"

// PID_MAX_LIMIT is ~4 million
#define MAX_PID_DIGITS 7

// Size of the open file descriptor table
#ifndef LDP_FUSE_OFT_SIZE
#define LDP_FUSE_OFT_SIZE 200
#endif

typedef enum fd_partof_fs {
  UNKNOWN = 0,
  NOT_IN_FS,
  IN_FS,
} fd_partof_fs;

// LDP_FUSE manually keeps track of open file descriptors and their offsets.
// Also caches whether this fd is part of the LDP_FUSE file system. Conditional
// compilation flag `LDP_FUSE_THREAD_SAFE` adds a pthread readers-writers lock.
typedef struct ldp_fuse_open_fd {
  off_t file_position;
  char* path;
  fd_partof_fs in_fs;
#ifdef LDP_FUSE_THREAD_SAFE
  pthread_rwlock_t rw_lock;
#endif
} ldp_fuse_open_fd;

// Initialized by `ldp_fuse_init`
typedef struct ldp_fuse_open_file_table {
  ldp_fuse_open_fd* table;
} ldp_fuse_open_file_table;

ldp_fuse_open_file_table _oft;

// LDP_FUSE_PATH environment variable. Initialized in `ldp_fuse_init`.
char* ldp_fuse_path;

// Open a file descriptor in the `open_file_table`.
// Every opened file is tracked, even if not in the LDP_FUSE filesystem.
static void open_fd(int fd, const char* path) {
  unsigned int idx = fd;
  ldp_fuse_open_file_table* oft = &_oft;
  if (idx >= LDP_FUSE_OFT_SIZE) {
    fprintf(stderr,
            "ERROR: File descriptor %d exceeds maximum size of LDP_FUSE's open "
            "file descriptor table (max: %d",
            fd, LDP_FUSE_OFT_SIZE);
    exit(-1);
  }
  oft->table[idx].file_position = 0;
  oft->table[idx].in_fs = UNKNOWN;

  if (oft->table[idx].path != NULL)
    free(oft->table[idx].path);
  oft->table[idx].path = malloc(strlen(path) + 1);
  strcpy(oft->table[idx].path, path);
}

static inline const struct ldp_fuse_open_fd* get_open_fd_read(int fd) {
#ifdef LDP_FUSE_THREAD_SAFE
  ldp_fuse_open_fd* entry = &_oft.table[fd];
  int error;
  if ((error = pthread_rwlock_rdlock(&entry->rw_lock) != 0))
    fprintf(stderr,
            "LDP_FUSE: Error applying read lock on fd %d. Error value: %d\n",
            fd, error);
#endif
  return &_oft.table[fd];
}

static inline struct ldp_fuse_open_fd* get_open_fd_write(int fd) {
#ifdef LDP_FUSE_THREAD_SAFE
  ldp_fuse_open_fd* entry = &_oft.table[fd];
  int error;
  if ((error = pthread_rwlock_wrlock(&entry->rw_lock) != 0))
    fprintf(stderr,
            "LDP_FUSE: Error applying write lock on fd %d. Error value: %d\n",
            fd, error);
#endif
  return &_oft.table[fd];
}

static inline void unlock_open_fd(int fd) {
#ifdef LDP_FUSE_THREAD_SAFE
  int error;
  ldp_fuse_open_fd* entry = &_oft.table[fd];
  if ((error = pthread_rwlock_unlock(&entry->rw_lock) != 0))
    fprintf(stderr,
            "LDP_FUSE: Error releasing lock for fd %d. Error value: %d\n", fd,
            error);
#endif
}

static inline off_t get_file_position(int fd) {
  off_t pos = get_open_fd_read(fd)->file_position;
  unlock_open_fd(fd);
  return pos;
}

// Increase the file position of the open fd
static inline void increase_file_position(int fd, off_t offset) {
  get_open_fd_write(fd)->file_position += offset;
  unlock_open_fd(fd);
}

static bool is_subpath(const char* parent, const char* child) {
  int i = 0;
  char parent_char, child_char;
  while ((child_char = child[i])) {
    parent_char = parent[i];
    if (!parent_char)
      return true;
    if (child_char != parent_char)
      return false;
    i += 1;
  }
  return parent[i] == '\0';
}

// Return value must be freed.
static char* resolve_fd(int fd) {
  char* path = strdup(get_open_fd_read(fd)->path);
  unlock_open_fd(fd);
  return path;
}

#define LDP_FUSE_PATH_MAX_LEN 256

/*
  from version 2.32 glibc does not have the _STAT_VER macro
  defined in "sys/stat.h"
*/
#if (__GLIBC__ > 1 && __GLIBC_MINOR__ > 32)
#define STAT_VER 0 
#else
#define STAT_VER _STAT_VER
#endif

// Whether `path` is in the LDP_FUSE filesystem. The LDP_FUSE filesystem is
// mounted under the LDP_FUSE_PATH env variable.
static bool path_in_fs(const char* path) {
  if (!path)
    return false;
  bool in_fs = false;
  char* cwd = NULL;
  char* fs_paths = getenv(LDP_FUSE_PATH);
  if (!fs_paths) {
    in_fs = true;
    goto out;
  }
  cwd = getcwd(NULL, 0);
  char full_path[PATH_MAX + 1];
  cwk_path_get_absolute(cwd, path, full_path, sizeof(full_path));
  char* fs_path;
  while ((fs_path = strtok(fs_paths, LDP_FUSE_DELIM))) {
    fs_paths = NULL;  // Must be set to NULL for strtok
    if (full_path == NULL) {
      LDP_FUSE_DEBUG_PRINT("Error resolving path %s: %s\n", fs_path,
                           strerror(errno));
      in_fs = false;
      goto out;
    }
    if (is_subpath(fs_path, full_path)) {
      in_fs = true;
      goto out;
    }
  }

out:
  if (in_fs)
    LDP_FUSE_DEBUG_PRINT("Path %s is in filesystem. \n", path);
  else
    LDP_FUSE_DEBUG_PRINT("Path %s is NOT in the filesystem\n", path);
  // getchar();
  if (cwd != NULL)
    free(cwd);
  return in_fs;
}

// Whether file descriptor `fd` is in the LDP_FUSE filesystem. The LDP_FUSE
// filesystem is mounted under the LDP_FUSE_PATH env variable.
static bool fd_in_fs(int fd) {
  LDP_FUSE_DEBUG_PRINT("fd %d in fs? ", fd);
  bool in_fs;
  const ldp_fuse_open_fd* open_fd = get_open_fd_read(fd);
  bool cached_available = open_fd->in_fs != UNKNOWN;
  if (cached_available) {
    in_fs = open_fd->in_fs;
  }
  unlock_open_fd(fd);
  if (!cached_available) {
    ldp_fuse_open_fd* open_fd = get_open_fd_write(fd);
    // Cache whether an opened fd is in this filesystem
    // through the `in_fs` field
    in_fs = path_in_fs(open_fd->path);
    open_fd->in_fs = in_fs ? IN_FS : NOT_IN_FS;
    unlock_open_fd(fd);
  }
  if (in_fs)
    LDP_FUSE_DEBUG_PRINT("YES\n");
  else
    LDP_FUSE_DEBUG_PRINT("NO\n");
  return in_fs;
}

ssize_t pread_impl(int fd, void* buf, size_t count, off_t offset) {
  if (!orig_pread)
    orig_pread = (orig_pread_t)dlsym(RTLD_NEXT, "pread");
  return funcs.read(fd, buf, count, offset, orig_pread);
}

// Calls user-provided `pread` function
ssize_t pread(int fd, void* buf, size_t count, off_t offset) {
  LDP_FUSE_DEBUG_PRINT("pread(%d, %p, %zu, %ld)\n", fd, buf, count, offset);
  if (!orig_pread)
    orig_pread = (orig_pread_t)dlsym(RTLD_NEXT, "pread");

  if (!funcs.read || !fd_in_fs(fd)) {
    return orig_pread(fd, buf, count, offset);
  }
  return pread_impl(fd, buf, count, offset);
}

ssize_t pread64(int fd, void* buf, size_t count, off_t offset)
    __attribute__((alias("pread")));

// Redirect to `pread`
ssize_t read(int fd, void* buf, size_t count) {
  if (!orig_read)
    orig_read = (orig_read_t)dlsym(RTLD_NEXT, "read");
  // It is important to NOT redirect to `pread` if the fd is not in the
  // filesystem, as non-seekable fds are not supported by `pread`.
  if (!fd_in_fs(fd)) {
    return orig_read(fd, buf, count);
  }
  // Seeking needs to be manually tracked as `pread`
  // does not increase the open fd offset
  off_t offset = get_file_position(fd);
  ssize_t nread = pread_impl(fd, buf, count, offset);
  increase_file_position(fd, nread);
  return nread;
}

int fstatat_wrapper(int dirfd,
                    const char* restrict pathname,
                    struct stat* restrict statbuf,
                    int flags) {
  LDP_FUSE_DEBUG_PRINT("fstatat_wrapper: %s\n", pathname);
  if (!orig_fxstatat)
    orig_fxstatat = (orig_fxstatat_t)dlsym(RTLD_NEXT, "__fxstatat");
  int ret = orig_fxstatat(STAT_VER, dirfd, pathname, statbuf, flags);
  LDP_FUSE_DEBUG_PRINT("fstatat_wrapper: %s -> %d\n", pathname, ret);
  return ret;
}

int fstatat_impl(int ver,
                 int dirfd,
                 const char* restrict pathname,
                 struct stat* restrict statbuf,
                 int flags) {
  return funcs.stat(dirfd, pathname, statbuf, flags, fstatat_wrapper);
}

// Calls user-provided `fstatat` function
int __fxstatat(int ver,
               int dirfd,
               const char* restrict pathname,
               struct stat* restrict statbuf,
               int flags) {
  if (!orig_fxstatat)
    orig_fxstatat = (orig_fxstatat_t)dlsym(RTLD_NEXT, "__fxstatat");

  if (!funcs.stat || !path_in_fs(pathname))
    return orig_fxstatat(STAT_VER, dirfd, pathname, statbuf, flags);
  return fstatat_impl(STAT_VER, dirfd, pathname, statbuf, flags);
}

// Redirect to `__fxstatat`
int __xstat(int ver,
            const char* restrict pathname,
            struct stat* restrict statbuf) {
  if (!orig_xstat)
    orig_xstat = (orig_xstat_t)dlsym(RTLD_NEXT, "__xstat");
  if (!path_in_fs(pathname))
    return orig_xstat(ver, pathname, statbuf);
  int ret = fstatat_impl(ver, AT_FDCWD, pathname, statbuf, 0);
  LDP_FUSE_DEBUG_PRINT("__xstat: %s -> %d\n", pathname, ret);
  return ret;
}

// Redirect to `__fxstatat`
int __fxstat(int ver, int fd, struct stat* statbuf) {
  if (!orig_fxstat)
    orig_fxstat = (orig_fxstat_t)dlsym(RTLD_NEXT, "__fxstat");
  if (!fd_in_fs(fd))
    return orig_fxstat(ver, fd, statbuf);
  const char* path = resolve_fd(fd);
  int ret = fstatat_impl(ver, AT_FDCWD, path, statbuf, 0);
  LDP_FUSE_DEBUG_PRINT("__fxstat: %s -> %d\n", path, ret);
  return ret;
}

// Redirect to `__fxstatat`
int __lxstat(int ver,
             const char* restrict pathname,
             struct stat* restrict statbuf) {
  if (!orig_lxstat)
    orig_lxstat = (orig_lxstat_t)dlsym(RTLD_NEXT, "__lxstat");
  if (!path_in_fs(pathname))
    return orig_lxstat(ver, pathname, statbuf);
  int ret = fstatat_impl(ver, AT_FDCWD, pathname, statbuf, AT_SYMLINK_NOFOLLOW);
  LDP_FUSE_DEBUG_PRINT("__lxstat: %s -> %d\n", pathname, ret);
  return ret;
}

ssize_t getxattr_impl(const char* path,
                      const char* name,
                      void* value,
                      size_t size) {
  if (!orig_getxattr)
    orig_getxattr = (orig_getxattr_t)dlsym(RTLD_NEXT, "getxattr");
  return funcs.getxattr(path, name, value, size, orig_getxattr);
}

// Calls user-provided `getxattr` function
ssize_t getxattr(const char* path, const char* name, void* value, size_t size) {
  LDP_FUSE_DEBUG_PRINT("getxattr: %s\n", path);
  if (!orig_getxattr)
    orig_getxattr = (orig_getxattr_t)dlsym(RTLD_NEXT, "getxattr");
  if (!path_in_fs(path) || !funcs.getxattr)
    return orig_getxattr(path, name, value, size);
  return funcs.getxattr(path, name, value, size, orig_getxattr);
}

// Redirect to `getxattr_impl`. Does NOT do anything special for symbolic links,
// contrary to the `getxattr` documentation.
ssize_t lgetxattr(const char* path,
                  const char* name,
                  void* value,
                  size_t size) {
  LDP_FUSE_DEBUG_PRINT("lgetxattr: %s\n", path);
  if (!orig_lgetxattr)
    orig_lgetxattr = (orig_lgetxattr_t)dlsym(RTLD_NEXT, "lgetxattr");
  if (!path_in_fs(path))
    return orig_lgetxattr(path, name, value, size);
  return getxattr_impl(path, name, value, size);
}

// Redirect to `getxattr_impl`.
ssize_t fgetxattr(int fd, const char* name, void* value, size_t size) {
  LDP_FUSE_DEBUG_PRINT("fgetxattr: %d\n", fd);
  if (!orig_fgetxattr)
    orig_fgetxattr = (orig_fgetxattr_t)dlsym(RTLD_NEXT, "fgetxattr");
  if (!fd_in_fs(fd))
    return orig_fgetxattr(fd, name, value, size);
  const char* path = resolve_fd(fd);
  return getxattr_impl(path, name, value, size);
}

int openat_impl(int dirfd, const char* pathname, int flags, mode_t mode) {
  if (!orig_openat)
    orig_openat = (orig_openat_t)dlsym(RTLD_NEXT, "openat");
  int fd = funcs.open(dirfd, pathname, flags, mode, orig_openat);
  open_fd(fd, pathname);
  return fd;
}

// Redirect to `openat_impl`
int openat(int dirfd, const char* pathname, int flags, ...) {
  LDP_FUSE_DEBUG_PRINT("openat_wrapper: %s\n", pathname);
  int fd;
  if (!orig_openat)
    orig_openat = (orig_openat_t)dlsym(RTLD_NEXT, "openat");
  mode_t mode = 0;

  if ((flags & O_CREAT) != 0 || (flags & O_TMPFILE) != 0) {
    va_list args;
    va_start(args, flags);
    mode = va_arg(args, mode_t);
    va_end(args);
  }

  if (!funcs.open)
    fd = orig_openat(dirfd, pathname, flags, mode);
  else
    fd = openat_impl(dirfd, pathname, flags, mode);
  return fd;
}

int openat64(int fd, const char* path, int flags, ...)
    __attribute__((alias("openat")));

int __openat64(int fd, const char* path, int flags, ...)
    __attribute__((alias("openat")));

int __openat64_2(int fd, const char* path, int flags, ...)
    __attribute__((alias("openat")));

// Redirect to `openat_impl`
int open(const char* pathname, int flags, ...) {
  LDP_FUSE_DEBUG_PRINT("open_wrapper: %s\n", pathname);
  int fd;
  if (!orig_open) {
    orig_open = (orig_open_t)dlsym(RTLD_NEXT, "open");
  }
  // Additional variadic arg `mode` is only supplied
  // when either of these bits are set
  if ((flags & O_CREAT) != 0 || (flags & O_TMPFILE) != 0) {
    va_list args;
    va_start(args, flags);
    mode_t mode = va_arg(args, mode_t);
    if (!path_in_fs(pathname))
      return orig_open(pathname, flags, mode);
    fd = openat_impl(AT_FDCWD, pathname, flags, mode);
    va_end(args);
  } else {
    if (!path_in_fs(pathname))
      return orig_open(pathname, flags);
    fd = openat_impl(AT_FDCWD, pathname, flags, 0);
  }
  return fd;
}

int __open(const char* pathname, int flags, ...) __attribute__((alias("open")));
int __open64(const char* pathname, int flags, ...)
    __attribute__((alias("open")));
int __open64_2(const char* pathname, int flags, ...)
    __attribute__((alias("open")));
int __open_2(const char* pathname, int flags, ...)
    __attribute__((alias("open")));
int __open_nocancel(const char* pathname, int flags, ...)
    __attribute__((alias("open")));
int open64(const char* pathname, int flags, ...) __attribute__((alias("open")));

// Redirect to `openat_impl`
int creat(const char* pathname, mode_t mode) {
  LDP_FUSE_DEBUG_PRINT("creat_wrapper: %s\n", pathname);
  if (!orig_creat) {
    orig_creat = (orig_creat_t)dlsym(RTLD_NEXT, "creat");
  }
  if (!path_in_fs(pathname))
    return orig_creat(pathname, mode);
  return openat_impl(AT_FDCWD, pathname, O_CREAT | O_WRONLY | O_TRUNC, mode);
}

int creat64(const char* pathname, mode_t mode) __attribute__((nonnull))
__attribute__((alias("creat")));

ssize_t pwrite_impl(int fd, const void* buf, size_t count, off_t offset) {
  if (!orig_pwrite)
    orig_pwrite = (orig_pwrite_t)dlsym(RTLD_NEXT, "pwrite");
  return funcs.write(fd, buf, count, offset, orig_pwrite);
}

ssize_t pwrite(int fd, const void* buf, size_t count, off_t offset) {
  if (!orig_pwrite)
    orig_pwrite = (orig_pwrite_t)dlsym(RTLD_NEXT, "pwrite");
  if (!funcs.write || !fd_in_fs(fd))
    return orig_pwrite(fd, buf, count, offset);
  return pwrite_impl(fd, buf, count, offset);
}

// Redirect to `pwrite_impl`
ssize_t write(int fd, const void* buf, size_t count) {
  LDP_FUSE_DEBUG_PRINT("write_wrapper: %d\n", fd);
  if (!orig_write)
    orig_write = (orig_write_t)dlsym(RTLD_NEXT, "write");
  if (!fd_in_fs(fd))
    return orig_write(fd, buf, count);
  return pwrite_impl(fd, buf, count, 0);
}

ssize_t readlink(const char* restrict pathname,
                 char* restrict buf,
                 size_t bufsiz) {
  LDP_FUSE_DEBUG_PRINT("readlink_wrapper: %s\n", pathname);
  if (!orig_readlink)
    orig_readlink = (orig_readlink_t)dlsym(RTLD_NEXT, "readlink");
  if (!funcs.readlink || !path_in_fs(pathname))
    return orig_readlink(pathname, buf, bufsiz);

  return funcs.readlink(pathname, buf, bufsiz, orig_readlink);
}

int mknodat(int dirfd, const char* pathname, mode_t mode, dev_t dev) {
  LDP_FUSE_DEBUG_PRINT("mknodat_wrapper: %s\n", pathname);
  if (!orig_mknodat)
    orig_mknodat = (orig_mknodat_t)dlsym(RTLD_NEXT, "mknodat");
  if (!funcs.mknod || !path_in_fs(pathname))
    return orig_mknodat(dirfd, pathname, mode, dev);
  return funcs.mknod(dirfd, pathname, mode, dev, orig_mknodat);
}

int mknod(const char* pathname, mode_t mode, dev_t dev) {
  LDP_FUSE_DEBUG_PRINT("mknod_wrapper: %s\n", pathname);
  if (!orig_mknod)
    orig_mknod = (orig_mknod_t)dlsym(RTLD_NEXT, "mknod");

  if (!funcs.mknod || !path_in_fs(pathname))
    return orig_mknod(pathname, mode, dev);
  return mknodat(AT_FDCWD, pathname, mode, dev);
}

int mkdir(const char* pathname, mode_t mode) {
  LDP_FUSE_DEBUG_PRINT("mkdir_wrapper: %s\n", pathname);
  if (!orig_mkdir)
    orig_mkdir = (orig_mkdir_t)dlsym(RTLD_NEXT, "mkdir");

  if (!funcs.mkdir || !path_in_fs(pathname))
    return orig_mkdir(pathname, mode);

  return funcs.mkdir(pathname, mode, orig_mkdir);
}

int unlink(const char* pathname) {
  LDP_FUSE_DEBUG_PRINT("unlink_wrapper: %s\n", pathname);
  if (!orig_unlink)
    orig_unlink = (orig_unlink_t)dlsym(RTLD_NEXT, "unlink");
  if (!funcs.unlink || !path_in_fs(pathname))
    return orig_unlink(pathname);
  return funcs.unlink(pathname, orig_unlink);
}

int rmdir(const char* pathname) {
  LDP_FUSE_DEBUG_PRINT("rmdir_wrapper: %s\n", pathname);
  if (!orig_rmdir)
    orig_rmdir = (orig_rmdir_t)dlsym(RTLD_NEXT, "rmdir");

  if (!funcs.rmdir || !path_in_fs(pathname))
    return orig_rmdir(pathname);

  return funcs.rmdir(pathname, orig_rmdir);
}

int symlink(const char* target, const char* linkpath) {
  LDP_FUSE_DEBUG_PRINT("symlink_wrapper: %s\n", linkpath);
  if (!orig_symlink)
    orig_symlink = (orig_symlink_t)dlsym(RTLD_NEXT, "symlink");
  if (!funcs.symlink || !path_in_fs(target))
    return orig_symlink(target, linkpath);
  return funcs.symlink(target, linkpath, orig_symlink);
}

int rename(const char* oldpath, const char* newpath) {
  LDP_FUSE_DEBUG_PRINT("rename_wrapper: %s\n", newpath);
  if (!orig_rename)
    orig_rename = (orig_rename_t)dlsym(RTLD_NEXT, "rename");

  if (!funcs.rename || !path_in_fs(oldpath))
    return orig_rename(oldpath, newpath);
  return funcs.rename(oldpath, newpath, orig_rename);
}

int link(const char* oldpath, const char* newpath) {
  LDP_FUSE_DEBUG_PRINT("link_wrapper: %s\n", newpath);
  if (!orig_link)
    orig_link = (orig_link_t)dlsym(RTLD_NEXT, "link");

  if (!funcs.link || !path_in_fs(oldpath))
    return orig_link(oldpath, newpath);
  return funcs.link(oldpath, newpath, orig_link);
}

int chmod(const char* path, mode_t mode) {
  LDP_FUSE_DEBUG_PRINT("chmod_wrapper: %s\n", path);
  if (!orig_chmod)
    orig_chmod = (orig_chmod_t)dlsym(RTLD_NEXT, "chmod");

  if (!funcs.chmod || !path_in_fs(path))
    return orig_chmod(path, mode);
  return funcs.chmod(path, mode, orig_chmod);
}

int chown(const char* path, uid_t owner, gid_t group) {
  LDP_FUSE_DEBUG_PRINT("chown_wrapper: %s\n", path);
  if (!orig_chown)
    orig_chown = (orig_chown_t)dlsym(RTLD_NEXT, "chown");

  if (!funcs.chown || !path_in_fs(path))
    return orig_chown(path, owner, group);
  return funcs.chown(path, owner, group, orig_chown);
}

int truncate(const char* path, off_t length) {
  LDP_FUSE_DEBUG_PRINT("truncate: %s\n", path);
  if (!orig_truncate)
    orig_truncate = (orig_truncate_t)dlsym(RTLD_NEXT, "truncate");

  if (!funcs.truncate || !path_in_fs(path))
    return orig_truncate(path, length);
  return funcs.truncate(path, length, orig_truncate);
}

int close(int fd) {
  LDP_FUSE_DEBUG_PRINT("close(%d)\n", fd);
  if (!orig_close)
    orig_close = (orig_close_t)dlsym(RTLD_NEXT, "close");

  if (!funcs.close || !fd_in_fs(fd))
    return orig_close(fd);
  return funcs.close(fd, orig_close);
}

// Translated to multiple `close` calls. `flags` argument is ignored.
int close_range(unsigned int first, unsigned int last, unsigned int flags) {
  LDP_FUSE_DEBUG_PRINT("close_range(%d, %d)\n", first, last);
  int retval = 0;
  if (first > last)
    return -EINVAL;
  for (unsigned int current = first; current <= last; current++) {
    // If one of the `close` calls errors with -1, try closing the other fd's,
    // then return the error value.
    retval |= close(current);
  }
  return retval;
}

DIR* opendir(const char* name) {
  LDP_FUSE_DEBUG_PRINT("opendir_wrapper: %s\n", name);
  if (!orig_opendir)
    orig_opendir = (orig_opendir_t)dlsym(RTLD_NEXT, "opendir");

  if (!funcs.opendir || !path_in_fs(name))
    return orig_opendir(name);
  return funcs.opendir(name, orig_opendir);
}

int faccessat_impl(int dirfd, const char* pathname, int mode, int flags) {
  LDP_FUSE_DEBUG_PRINT("faccessat impl: %s\n", pathname);
  if (!orig_faccessat)
    orig_faccessat = (orig_faccessat_t)dlsym(RTLD_NEXT, "faccessat");
  return funcs.access(pathname, mode, orig_faccessat);
}

// Redirect to `faccessat_impl`
int faccessat(int dirfd, const char* pathname, int mode, int flags) {
  LDP_FUSE_DEBUG_PRINT("faccessat_wrapper: %s\n", pathname);
  if (!orig_faccessat)
    orig_faccessat = (orig_faccessat_t)dlsym(RTLD_NEXT, "faccessat");

  if (!funcs.access || !path_in_fs(pathname))
    return orig_faccessat(pathname, mode);
  return faccessat_impl(dirfd, pathname, mode, flags);
}

// Redirect to `faccessat_impl`
int access(const char* pathname, int mode) {
  LDP_FUSE_DEBUG_PRINT("access_wrapper: %s\n", pathname);
  if (!orig_access)
    orig_access = (orig_access_t)dlsym(RTLD_NEXT, "access");
  if (!funcs.access || !path_in_fs(pathname))
    return orig_access(pathname, mode);

  return faccessat_impl(AT_FDCWD, pathname, mode, 0);
}

// Redirect to `faccessat_impl`
int euidaccess(const char* pathname, int mode) {
  LDP_FUSE_DEBUG_PRINT("euidaccess_wrapper: %s\n", pathname);
  if (!orig_euidaccess)
    orig_euidaccess = (orig_euidaccess_t)dlsym(RTLD_NEXT, "euidaccess");
  if (!funcs.access || !path_in_fs(pathname))
    return orig_euidaccess(pathname, mode);
  return faccessat_impl(AT_FDCWD, pathname, mode, AT_EACCESS);
}

// Redirect to `euidaccess`
int eaccess(const char* pathname, int mode) {
  return euidaccess(pathname, mode);
}

// User can not provide `lseek` implementation at the moment.
// Call the original `lseek` and increment LDP_FUSE's own OFT.
typedef off_t (*orig_lseek_t)(int fd, off_t offset, int whence);
orig_lseek_t orig_lseek = NULL;
off_t lseek(int fd, off_t offset, int whence) {
  if (!orig_lseek)
    orig_lseek = (orig_lseek_t)dlsym(RTLD_NEXT, "lseek");
  int retval = orig_lseek(fd, offset, whence);
  ldp_fuse_open_fd* open_fd = NULL;
  struct stat statbuf;
  if (retval != -1) {
    switch (whence) {
      case SEEK_SET:
        open_fd = get_open_fd_write(fd);
        open_fd->file_position = offset;
        unlock_open_fd(fd);
        break;
      case SEEK_CUR:
        open_fd = get_open_fd_write(fd);
        open_fd->file_position += offset;
        unlock_open_fd(fd);
        break;
      case SEEK_END:
        if (fstat(fd, &statbuf) == -1) {
          fprintf(stderr,
                  "LDP_FUSE: Could not determine size of file with fd %d - "
                  "`stat` failed\n",
                  fd);
          exit(1);
        }
        int size = statbuf.st_size;
        open_fd = get_open_fd_write(fd);
        open_fd->file_position = size + offset;
        unlock_open_fd(fd);
        break;
      // SEEK_DATA and SEEK_HOLE are not supported currently
      case SEEK_DATA:
        fprintf(stderr,
                "LDP_FUSE - `SEEK_DATA` is not supported for `lseek`'s "
                "`whence` parameter\n");
        exit(1);
      case SEEK_HOLE:
        fprintf(stderr,
                "LDP_FUSE - `SEEK_DATA` is not supported for `lseek`'s "
                "`whence` parameter\n");
        exit(1);
    }
  }
  return retval;
}

off_t lseek64(int fd, off_t offset, int whence) __attribute__((nonnull))
__attribute__((nothrow)) __attribute__((leaf)) __attribute__((alias("lseek")));

void ldp_fuse_init_rw_locks() {
#ifdef LDP_FUSE_THREAD_SAFE
  for (int i = 0; i < LDP_FUSE_OFT_SIZE; i++) {
    pthread_rwlock_init(&_oft.table[i].rw_lock, NULL);
  }
#endif
}

void ldp_fuse_init(const struct ldp_fuse_funcs* args) {
  _oft.table = malloc(LDP_FUSE_OFT_SIZE * sizeof(struct ldp_fuse_open_fd));
  memset(_oft.table, '\0', LDP_FUSE_OFT_SIZE * sizeof(struct ldp_fuse_open_fd));
  ldp_fuse_path = getenv(LDP_FUSE_PATH);
  funcs = *args;

#ifdef LDP_FUSE_DEBUG
  pid_t pid = getpid();
  char str[80];
  sprintf(str, "/tmp/.ldp_fuse_mounted_%d", pid);
  mkdir(str, 0777);
#endif

#ifdef LDP_FUSE_THREAD_SAFE
  ldp_fuse_init_rw_locks();
#endif
}

#define LDPRELOAD_FUSE_MAIN \
  static void __attribute__((constructor)) _ldpreload_fuse_main_()
#endif