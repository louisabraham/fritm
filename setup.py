#!/usr/bin/env python3

import os
from setuptools import setup


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(
    name="fritm",
    version="0.4.1",
    author="Louis Abraham",
    license="MIT",
    author_email="louis.abraham@yahoo.fr",
    description="Minimalist and cross-platform network reverse engineering framework",
    long_description=read("README.md"),
    long_description_content_type='text/markdown',
    url="https://github.com/louisabraham/fritm",
    packages=["fritm"],
    package_data={"": ["script.js"]},
    include_package_data=True,
    install_requires=["frida", "click"],
    python_requires=">=3.5",
    entry_points={
        "console_scripts": [
            "fritm-hook = fritm.hook:_main_hook",
            "fritm-spawn = fritm.hook:_main_spawn",
        ]
    },
    classifiers=[
        "Topic :: Internet :: Proxy Servers",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Security",
    ],
)
