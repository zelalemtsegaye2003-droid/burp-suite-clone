#!/usr/bin/env python3
"""Run Burp Clone GUI from project root"""
import os
import sys

# Add src to path 
src_path = os.path.join(os.path.dirname(__file__), 'src')
sys.path.insert(0, src_path)

# Run GUI
from ui.gui import main
main()