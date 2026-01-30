#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="rtf-eff-u-extract",
    version="0.1.0",
    author="coz",
    description="Extract URLs from RTF embedded objects with deobfuscation and exploit detection",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/rtf-eff-u-extract",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "rtf-eff-u-extract=rtf_eff_u_extract.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "rtf_eff_u_extract": ["*.json"],
    },
    zip_safe=False,
)
