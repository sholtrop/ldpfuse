#include "ldpfuse.h"
#include <assert.h>

void test_slash() {
  setenv(LDP_FUSE_PATH, "/", 1);
  assert(path_in_fs("/") == true);
  assert(path_in_fs("/tmp") == true);
  assert(path_in_fs("/tmp/") == true);
  assert(path_in_fs("/tmp/file.txt") == true);
}

void test_path() {
  setenv(LDP_FUSE_PATH, "/some/path", 1);
  assert(path_in_fs("/") == false);
  assert(path_in_fs("/some") == false);
  assert(path_in_fs("/some/") == false);
  assert(path_in_fs("/some/path") == true);
  assert(path_in_fs("/some/path/") == true);
  assert(path_in_fs("/some/path/file.txt") == true);
  assert(path_in_fs("/some/path/sub") == true);
  assert(path_in_fs("/some/path/sub/") == true);
  assert(path_in_fs("/some/path/sub/file.txt") == true);
}

int main() {
  test_slash();
  test_path();
  return 0;
}
