#!/bin/bash

echo "🚀 Starting Solana Fellowship HTTP Server Test Suite"
echo "=================================================="

# Build the project first
echo "📦 Building project..."
cargo build
if [ $? -ne 0 ]; then
    echo "❌ Build failed!"
    exit 1
fi

# Start the server in the background
echo "🔥 Starting HTTP server..."
cargo run &
SERVER_PID=$!

# Give the server time to start
echo "⏳ Waiting for server to start..."
sleep 3

# Function to cleanup server on exit
cleanup() {
    echo "🛑 Stopping server..."
    kill $SERVER_PID 2>/dev/null
    wait $SERVER_PID 2>/dev/null
}

# Set trap to cleanup on script exit
trap cleanup EXIT

# Run the tests
echo "🧪 Running integration tests..."
cargo test --test integration_tests -- --nocapture

TEST_RESULT=$?

if [ $TEST_RESULT -eq 0 ]; then
    echo "✅ All tests passed!"
else
    echo "❌ Some tests failed!"
fi

# The cleanup function will be called automatically via the trap
exit $TEST_RESULT 