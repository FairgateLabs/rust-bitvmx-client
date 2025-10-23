#!/bin/bash

cargo test --release -- --ignored test_aggregation 
RUST_BACKTRACE=1 cargo test --release -- --ignored test_all