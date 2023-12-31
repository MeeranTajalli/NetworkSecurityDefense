#!/bin/bash

FILE="/home/meeran/Desktop/project/tcpdump_output.txt"  # Replace with your file's absolute path
MAX_LINES=5000

# Trim the file to keep only the last MAX_LINES lines
tail -n $MAX_LINES "$FILE" > "$FILE.tmp" && mv "$FILE.tmp" "$FILE"

