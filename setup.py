#!/usr/bin/env python3
"""Setup for Burp Clone"""
from setuptools import setup, find_packages

setup(
    name='burp-clone',
    version='1.0.0',
    description='Web Application Penetration Testing Toolkit',
    author='Burp Clone Team',
    author_email='contact@burpclone.local',
    url='https://github.com/zelalemtsegaye2003-droid/burp-suite-clone',
    packages=find_packages(),
    install_requires=[
        'requests>=2.31.0',
        'httpx>=0.25.0',
        'beautifulsoup4>=4.12',
        'lxml>=4.9',
        'cryptography>=41.0',
    ],
    extras_require={
        'dev': [
            'pytest>=7.4',
            'pytest-cov>=4.1',
        ]
    },
    entry_points={
        'console_scripts': [
            'burp-clone=src.main_cli:main',
        ]
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
    python_requires='>=3.8',
)