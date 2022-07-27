CC = gcc
CFLAGS = -Wall -g -I /home/sholtrop/development/cpp/bsc/ldpreload_fuse/include
SOFLAGS = -shared -fPIC
LDFLAGS = -ldl
HEADERS = /home/sholtrop/development/cpp/bsc/ldpreload_fuse/include/ldpfuse.h
SO_NAME = encrypted
# TEST_NAME = test

all: $(SO_NAME).so # $(TEST_NAME)

# $(TEST_NAME): $(TEST_NAME).o
# 	$(CC) $(CFLAGS) $(TEST_NAME).o -o $(TEST_NAME)

$(SO_NAME).so: $(SO_NAME).o
	$(CC) $(CFLAGS) $(SOFLAGS) $(HEADERS) -o $@ $(LDFLAGS)
	
%.o: %.c
	$(CC) $(CFLAGS) -c $<

.PHONY: clean
clean:
	rm -f *.o $(SO_NAME).so