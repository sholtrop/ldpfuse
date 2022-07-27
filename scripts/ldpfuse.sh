cd ./cli && cargo build && cd ..;

./cli/target/debug/ldpfuse -v -m /tmp/ldpfuse -s ./examples/passthrough/passthrough.so -- $1