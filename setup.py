from setuptools import find_packages, setup

with open("src/README.md", "r") as f:
    long_description = f.read()

setup(
    name="beyondInsight",
    version="1.0.0",
    description="The BeyondInsight Library to fetch secrets from beyondTrust.",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="github.com:quasys-tech/beyondInsight",
    author="quasys-tech",
    author_email="quasys-tech@quasys.com.tr",
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.10",
        "Operating System :: OS Independent",
    ],
    install_requires=["requests >= 2.31.0", "pyOpenSSL >= 23.2.0"],
    python_requires=">=3.10",
)