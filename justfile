# Default recipe to list available commands
default:
	@just --list

# Build the DNS server
build:
	cargo build

# Run the DNS server
run:
	cargo run

# Test the DNS server with dig (your common command)
test:
	dig @127.0.0.1 -p 2053 +noedns codecrafters.io

# Test with a specific domain
test-domain DOMAIN:
	dig @127.0.0.1 -p 2053 +noedns {{DOMAIN}}

# Test with different query types
test-a DOMAIN:
	dig @127.0.0.1 -p 2053 +noedns {{DOMAIN}} A

test-aaaa DOMAIN:
	dig @127.0.0.1 -p 2053 +noedns {{DOMAIN}} AAAA

# Run and test in one command
run-and-test:
	cargo run & sleep 1 && dig @127.0.0.1 -p 2053 +noedns codecrafters.io
