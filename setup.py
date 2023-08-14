from setuptools import (
    setup,
    find_packages,
)

setup(
    name="abi_guesser",
    version="0.2",
    packages=find_packages(),
    install_requires=[
        "eth-abi>=4.1.0", 
        "eth-typing>=3.2.0", 
        "eth-utils>=2.1.0", 
        "hexbytes>=0.3.0", 
    ],
    author="0xSt1ng3R",
    description="Python replication of samczsun's abi-guesser",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/0xSt1ng3R/abi-guesser-py",
)
