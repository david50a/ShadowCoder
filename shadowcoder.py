#!/usr/bin/env python3
import sys
import os

# Add current directory to path so engine can be imported
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from engine.shadowcoder import main

if __name__ == "__main__":
    main()
