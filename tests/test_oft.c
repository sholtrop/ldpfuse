// This test statically includes LDP_FUSE to test its inner workings.
// Run this test under valgrind.

#include <assert.h>
#include <stdbool.h>
#include "./passthrough_test_fs.c"

#define N_OPENED_FILES 103
#define WRITE_AMT 10
#define START_FD 3

int opened_fds[N_OPENED_FILES - START_FD];

void test_oft_alloc() {
  char* path = malloc(sizeof("/tmp/file@@@.txt"));
  for (int i = START_FD; i < N_OPENED_FILES; i++) {
    int result = sprintf(path, "/tmp/file%d.txt", i);
    assert(result > 0);
    int fd = open(path, O_CREAT | O_RDWR | O_APPEND, 0644);
    fprintf(stderr, "%d - fd: %d\n", i, fd);
    assert(fd != -1);
    assert(_oft.table[fd].in_fs == UNKNOWN);
    assert(_oft.table[fd].path != NULL);
    opened_fds[i - START_FD] = fd;
  }
  free(path);
}

void test_oft_caching() {
  char* path = malloc(sizeof("/tmp/file@@@.txt"));
  char* readbuff = malloc(1);
  for (int i = START_FD; i < N_OPENED_FILES; i++) {
    int fd = opened_fds[i - START_FD];
    int result = sprintf(path, "/tmp/file%d.txt", fd);
    assert(result > 0);
    ssize_t n_read = read(fd, readbuff, 0);
    LDP_FUSE_DEBUG_PRINT("n_read %zd fd:%d\n", n_read, fd);
    assert(n_read == 0);
    assert(_oft.table[fd].in_fs == IN_FS);
  }
  free(readbuff);
  free(path);
}

void test_oft_offset() {
  int fd = opened_fds[0];
  for (int i = 0; i < WRITE_AMT; i++) {
    ssize_t n_written = write(fd, "a", 1);
    assert(n_written == 1);
  }
  char contents[WRITE_AMT];
  int n_read = read(fd, contents, WRITE_AMT);
  assert(strcmp(contents, "aaaaaaaaaa") == 0);
  assert(n_read == WRITE_AMT);
  assert(_oft.table[fd].file_position == WRITE_AMT);
}

int main() {
  init_test_fuse();
  test_oft_alloc();
  test_oft_caching();
  test_oft_offset();
  return 0;
}