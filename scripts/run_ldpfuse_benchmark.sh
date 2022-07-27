mkdir /tmp/filebench &> /dev/null;
cd ./cli && cargo build && cd ..;
# Filebench requires ASLR to be turned off, for some reason...
sudo bash -c "echo 0 > /proc/sys/kernel/randomize_va_space";

sudo ./cli/target/debug/ldpfuse -v -m /tmp/filebench -s ./examples/passthrough/passthrough.so -- filebench -f $1 &> "$1.out"