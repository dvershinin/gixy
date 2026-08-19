import re
from setuptools import setup, find_packages

with open("gixy/__init__.py") as fd:
    version = re.search(
        r'^version\s*=\s*[\'"]([^\'"]*)[\'"]', fd.read(), re.MULTILINE
    ).group(1)

if not version:
    raise RuntimeError("Cannot find version information")

install_requires = [
    "ngxparse>=0.5.16",
    'cached-property>=1.2.0;python_version<"3.8"',
    'argparse>=1.4.0;python_version<"3.2"',
    "Jinja2>=2.8",
    "ConfigArgParse>=0.11.0",
]

tests_requires = [
    "pytest>=7.0.0",
    "pytest-xdist",
]

# README.md is not present in Docker image setup
long_description = None
try:
    with open("README.md", encoding="utf-8") as fh:
        long_description = fh.read()
except FileNotFoundError:
    pass

setup(
    name="gixy-ng",
    version=version,
    description="NGINX configuration [sec]analyzer",
    long_description=long_description,
    long_description_content_type="text/markdown",
    keywords="nginx security lint static-analysis",
    author="Yandex IS Team, GetPageSpeed LLC",
    author_email="buglloc@yandex.ru, info@getpagespeed.com",
    url="https://github.com/dvershinin/gixy",
    install_requires=install_requires,
    extras_require={
        "tests": install_requires + tests_requires,
        "rich": ["rich>=13.0.0"],  # Optional: beautiful terminal output
    },
    entry_points={
        "console_scripts": ["gixy=gixy.cli.main:main"],
    },
    packages=find_packages(exclude=["tests", "tests.*"]),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Software Development :: Testing",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
    include_package_data=True,
)
