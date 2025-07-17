#!/usr/bin/env python3
from setuptools import setup, find_packages

setup(
    name="sssd-spoof",
    version="0.1.0",
    description="abusing domain-joined nix machines for privilege escalation",
    python_requires=">=3.11,<4.0",
    author="Zavier Lee",
    author_email="zavier@gatari.dev",
    url="",
    packages=find_packages(),
    install_requires=[
        "ldap3==2.9.1",
        "impacket @ git+https://github.com/Pennyw0rth/impacket.git",
        "gssapi==1.9.0",
        "paramiko==3.5.1",
    ],
    scripts=[
        "sssd-spoof.py",
    ],
)