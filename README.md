# Introduction

LDP_FUSE (`LD_PRELOAD` Filesystem in Userspace) is a header-only C library for writing file systems, leveraging the [`LD_PRELOAD` trick](https://www.goldsborough.me/c/low-level/kernel/2016/08/29/16-48-53-the_-ld_preload-_trick/). Explained briefly, you write a shared library (.so file) using the API that LDP_FUSE provides, and then run a binary with your shared library `LD_PRELOAD`ed. LDP_FUSE will take care of several low level details for you (see [Documentation](#documentation)).

**Important note**: This project is mostly a proof-of-concept. All of the current [limitations](#known-issues--limitations) make it not feasible to run in production. 

# Installation

Include all of the files under the `include/` folder in your build system.

To manage LDP_FUSE file systems more easily, you can optionally install a Rust-based CLI tool:

```bash
cargo install ldpfuse
```

# Usage

## Example

An example of how to write an LDP_FUSE file system:

```c
#include <stdio.h>
#include "ldpfuse.h"

ssize_t my_read(int fd, void *buf, size_t count, off_t offset,
                    orig_pread_t pread_fn) {
  printf("Read called!\n");
  return pread_fn(fd, buf, count, offset);
}

LDPRELOAD_FUSE_MAIN {
  struct ldp_fuse_funcs funcs = {.read = my_read };
  ldp_fuse_init(&funcs);
}
```

Compile this to a shared object (.so) file using `gcc`. You must dynamically link `libdl`, e.g. by specifying `-ldl`.

## Using the CLI

If you have installed the CLI, you can now run your file system like this:

```bash
ldpfuse -m <mount_path> -s <so_file_path> -- myprogram
```

Where `<mount_path>` is the path your file system is mounted under. File system operations on paths that do not have this mount path as an ancestor are ignored by LDP_FUSE and passed to the original functions instead.
The `<so_file_path>` is your LDP_FUSE file system shared object. Paths may be relative.

Full example, reading directory contents:

```bash
ldpfuse -m /tmp/test -s ./my_fs.so -- ls -la /tmp/test
```

## Environment variables

Rather than using the CLI to manage the environment variables and run the program, you can also set them yourself:

- `LD_PRELOAD` - Must be the absolute path to your LDP_FUSE file system shared library.
- `LDP_FUSE_PATH` - Must be set to the absolute path your file system is 'mounted' under. E.g. `/tmp/ldpfuse`. If not set, any path is treated as if it were in the file system.

# Documentation

## Functions, macros and structs

### `LDPRELOAD_FUSE_MAIN`

Define any setup code within the scope of this function macro. This macro should be called in any LDP_FUSE file system, and include a call to `ldp_fuse_init`.

```c
LDPRELOAD_FUSE_MAIN {
  // Any one-time setup code...
  ldp_fuse_init(&funcs);
}
```

### `ldp_fuse_init`

```c
void ldp_fuse_init(ldp_fuse_funcs* funcs)
```

Initializes the file system and sets its functions to those described in the `funcs` parameter. This should be called at some point during `LDPRELOAD_FUSE_MAIN`.

### `ldp_fuse_funcs`

A struct that defines LDP_FUSE's operations. Each member is a pointer to a function you wish to replace the regular filesystem I/O function with. See the [Overwritten functions overview](#overwritten_functions) to see what original functions you can overwrite.

## Overwritten functions overview

Next is an overview of the file system functions you can overwrite using LDP_FUSE. Similar system calls are redirected to a single user function - the most generic one. E.g., `stat`, `lstat`, `fstat` and `fstatat` are all redirected to `fstatat`. You will therefore only have to write an `fstatat` implementation.

| Original function | LDP_FUSE function | Notes                                                                                   |
| ----------------- | ----------------- | --------------------------------------------------------------------------------------- |
| access            | access            |                                                                                         |
| faccessat         | access            |                                                                                         |
| euidaccess        | access            |                                                                                         |
| mkdir             | mkdir             |                                                                                         |
| close             | close             |                                                                                         |
| close_range       | close             | Flags argument is ignored. Will call close once on each fd in the range.                |
| opendir           | opendir           |                                                                                         |
| creat             | open              |                                                                                         |
| open              | open              |                                                                                         |
| openat            | openat            |                                                                                         |
| truncate          | truncate          |                                                                                         |
| chmod             | chmod             |                                                                                         |
| chown             | chown             |                                                                                         |
| symlink           | symlink           |                                                                                         |
| rename            | rename            |                                                                                         |
| link              | link              |                                                                                         |
| rmdir             | rmdir             |                                                                                         |
| unlink            | unlink            |                                                                                         |
| mknod             | mknod             |                                                                                         |
| readlink          | readlink          |                                                                                         |
| write             | write             |                                                                                         |
| pwrite            | write             |                                                                                         |
| stat              | stat              |                                                                                         |
| lstat             | stat              |                                                                                         |
| fstat             | stat              |                                                                                         |
| fstatat           | stat              |                                                                                         |
| read              | read              |                                                                                         |
| pread             | read              |                                                                                         |
| getxattr          | getxattr          |                                                                                         |
| lgetxattr         | getxattr          | WILL follow symbolic links, contrary to the default which interrogates the link itself. |
| fgetxattr         | getxattr          |                                                                                         |

## Conditional compilation

You may specify any of the following flags:

- `-D LDP_FUSE_DEBUG` - Log debug output to stderr.
- `-D LDP_FUSE_THREAD_SAFE` - Make LDP_FUSE's internal datastructures thread safe. Should be included if the LDP_FUSE file system will be used to run programs that perform multithreaded file I/O. If included, `pthreads` must be dynamically linked.
- `-D LDP_FUSE_OFT_SIZE <size>` - Set the size of LDP_FUSE's open file descriptor table (see [Open File Descriptor Table](#open-file-descriptor-table-oft)). Defaults to 200.

## Open File Descriptor Table (OFT)

LDP_FUSE has its own open file descriptor table to keep track of read offsets, cache whether a path is in the file system, and read-write locking if necessary. Users of the library should not have to interact with this directly.
The maximum amount of entries is determined at compile time (`LDP_FUSE_OFT_SIZE`), and when it is exceeded the application will exit with an error message.

## Pitfalls

In your custom file system functions, do NOT use the original function. E.g., in `my_read`, do not call `read`. Doing so will cause an infinite loop, as LDP_FUSE redirects `read` to `my_read`.
Instead, use the last argument, which is a function pointer to the original `pread` function.

If the program that uses the LDP_FUSE is multithreaded, include the `LDP_FUSE_THREAD_SAFE` flag (see [Conditional Compilation](#conditional-compilation)]

# Known issues & limitations

LDP_FUSE may not work with certain binaries. A non-exhaustive list of reasons is given here.

## Mmap

Memory-mapped file I/O cannot be intercepted using `LD_PRELOAD`. Any program that uses `mmap` to access files can therefore not use LDP_FUSE.

## Inlined syscalls, statically linked glibc

Any program with either inlined syscalls (e.g. using `syscall` directly) or that statically links glibc, can not use LDP_FUSE.

## Setuid binaries

Linux executes setuid binaries in secure execution mode. Under this mode, `LD_PRELOAD` is ignored for safety reasons. As a result, you cannot use LDP_FUSE with setuid binaries.

## Functions with no glibc wrapper

Certain file system I/O functions do not have a glibc wrapper (e.g. `openat2`). These function calls can therefore not be intercepted.

## LDP_FUSE file systems without a backing regular file system

LDP_FUSE maintains one `OFDT` per process. There is no ipc or r/w mechanism that avoids two processes accessing a file at the same time yet. This means you will still need a regular file system backing it, so that it can take care of this. This issue might be alleviated in the future, with a single `OFDT` in shared memory.

# Credits

This library includes likle's great [cwalk](https://github.com/likle/cwalk) library for path resolution.

# License
MIT
