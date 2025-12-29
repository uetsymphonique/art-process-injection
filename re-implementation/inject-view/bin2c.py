#!/usr/bin/env python3
"""
Convert binary file to C-style byte array
Usage: python bin2c.py payload.bin > shellcode.h
"""

import sys
import os

def bin_to_c_array(input_file, array_name="shellcode"):
    """Convert binary file to C array format"""
    
    if not os.path.exists(input_file):
        print(f"Error: File '{input_file}' not found!", file=sys.stderr)
        sys.exit(1)
    
    file_size = os.path.getsize(input_file)
    print(f"// Generated from: {input_file}", file=sys.stderr)
    print(f"// Size: {file_size} bytes ({file_size/1024:.2f} KB)", file=sys.stderr)
    
    with open(input_file, 'rb') as f:
        data = f.read()
    
    # Generate C array
    print(f"unsigned char {array_name}[] = {{", end='')
    
    for i, byte in enumerate(data):
        if i % 12 == 0:  # 12 bytes per line
            print("\n    ", end='')
        print(f"0x{byte:02x}", end='')
        if i < len(data) - 1:
            print(",", end='')
    
    print("\n};")
    print(f"\nunsigned int {array_name}_len = sizeof({array_name});")
    print(f"// Total: {len(data)} bytes")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python bin2c.py <input.bin> [array_name]")
        sys.exit(1)
    
    input_file = sys.argv[1]
    array_name = sys.argv[2] if len(sys.argv) > 2 else "shellcode"
    
    bin_to_c_array(input_file, array_name)

