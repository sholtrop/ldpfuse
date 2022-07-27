// This test statically includes LDP_FUSE to test its inner workings.
// Run this test under valgrind.

#ifndef LDP_FUSE_THREAD_SAFE
#define LDP_FUSE_THREAD_SAFE
#endif

#include "./passthrough_test_fs.c"
#include <assert.h>
#include <pthread.h>
#include <stdbool.h>

#define READ_TOTAL 1000
#define N_THREADS 20
#define READ_PER_THREAD (READ_TOTAL / N_THREADS)

pthread_t threads[N_THREADS];
int thread_data[N_THREADS][2];
int read_amount[N_THREADS];

void *read_file(void *arg) {
  int *data = (int *)arg;
  int fd = data[0];
  int thread_nr = data[1];
  char *buf[READ_PER_THREAD];
  int n_read = read(fd, buf, READ_PER_THREAD);
  read_amount[thread_nr] = n_read;
  return NULL;
}

void test_multithread_read() {
  char contents[READ_TOTAL];
  memset(contents, 'a', sizeof(char) * READ_TOTAL);
  int fd = open("/tmp/mt_test.txt", O_CREAT | O_RDWR | O_APPEND, 0644);
  assert(fd != -1);
  int res = write(fd, contents, READ_TOTAL);
  assert(res == READ_TOTAL);
  for (int i = 0; i < N_THREADS; i++) {
    // Set up thread data, so each thread knows its number and what fd to read
    // from
    thread_data[i][0] = fd;
    thread_data[i][1] = i;
    pthread_create(&threads[i], NULL, read_file, &thread_data[i]);
  }

  for (int i = 0; i < N_THREADS; i++) {
    pthread_join(threads[i], NULL);
    assert(read_amount[i] == READ_PER_THREAD);
  }

  LDP_FUSE_DEBUG_PRINT("Final file position: %ld\n",
                       _oft.table[fd].file_position);
  // The threads together should have read exactly this amount, and therefore
  // incremented the file position to `READ_TOTAL`.
  assert(_oft.table[fd].file_position == READ_TOTAL);

  int wr_lock_result = pthread_rwlock_trywrlock(&_oft.table[fd].rw_lock);
  // rw_lock should not be rd or wr locked anymore
  assert(wr_lock_result == 0);
}

int main() {
  init_test_fuse();
  test_multithread_read();
  return 0;
}