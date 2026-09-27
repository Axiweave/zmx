#!/usr/bin/env bats
# Input must retain every byte and its FIFO order across PTY pressure and EOF.

load test_helper

@test "PTY backpressure preserves bytes, FIFO order, control requests, and sender EOF" {
  run python3 "$BATS_TEST_DIRNAME/backpressure.py" "$ZMX" --zmx-dir "$ZMX_DIR"
  printf '%s\n' "$output"
  [ "$status" -eq 0 ]
}
