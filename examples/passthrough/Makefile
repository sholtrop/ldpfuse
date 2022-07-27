CC = gcc
CFLAGS = -Wall -I ../../ldp_fuse/include -fPIC
SOFLAGS = -shared
LDFLAGS = -ldl -pthread
DEF_FLAGS = -D LDP_FUSE_THREAD_SAFE
DEBUG_FLAGS = -D LDP_FUSE_DEBUG -g
RELEASE_FLAGS = -O3
SO_NAME=passthrough

all: $(SO_NAME).so

debug: $(SO_NAME)_debug.so

$(SO_NAME)_debug.so:
	$(CC) $(DEF_FLAGS) $(DEBUG_FLAGS) $(CFLAGS) $(SOFLAGS) -o $@ $(SO_NAME).c $(LDFLAGS)

$(SO_NAME).so: $(SO_NAME).o
	$(CC) $(DEF_FLAGS) $(RELEASE_FLAGS) $(CFLAGS) $(SOFLAGS) -o $@ $< $(LDFLAGS)
	
%.o: %.c
	$(CC) $(DEF_FLAGS) $(CFLAGS) -c $<

.PHONY: clean
clean:
	rm -f *.o $(SO_NAME).so $(SO_NAME)_debug.so