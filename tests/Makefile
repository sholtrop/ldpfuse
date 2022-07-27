CC = gcc
CFLAGS = -Wall -g -I../ldp_fuse/include -D LDP_FUSE_DEBUG
LDFLAGS = -ldl -lpthread
PTHREAD_FLAGS = -D LDP_FUSE_THREAD_SAFE
TEST_NAMES = test_path_in_fs test_oft test_multithread


all: st

# single-threaded
st: $(TEST_NAMES)

# multi-threaded
mt: LDFLAGS += -lpthread
mt: CFLAGS += -D LDP_FUSE_THREAD_SAFE
mt: $(TEST_NAMES)

test_%: test_%.o
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
	
%.o: %.c
	$(CC) $(CFLAGS) -c $< $(LDFLAGS)

.PHONY: clean
clean:
	rm -f *.o $(TEST_NAMES)