#!/usr/bin/env python3
"""Run Burp Clone Enhanced GUI"""
import sys
import os

project_root = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.join(project_root, 'src')
sys.path.insert(0, src_path)

from ui.gui_enhanced import main

if __name__ == '__main__':
    main()