#!/usr/bin/env bash
while read in; do echo "$in" | cargo run -r; done < batch.txt