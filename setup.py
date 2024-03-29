import os
from setuptools import setup, find_packages
from pip._internal.req import parse_requirements


# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


# Parse requirements.txt
install_reqs = [str(ir.requirement) for
                ir in parse_requirements('./requirements.txt', session={})]

setup(
    name="icinga-check-dns",
    version='0.0.1',
    author="Pieter Lexis",
    author_email="pieter.lexis@powerdns.com",
    description=("Icinga/Nagios check that uses dnsviz to check "
                 "many parameters"),
    license="GPLv2",
    keywords="DNS dnsviz Nagios Icinga check",
    url="https://github.com/pieterlexis/icinga-check-dns",
    packages=find_packages(),
    install_requires=install_reqs,
    scripts=['check_dns.py'],
    include_package_data=True,  # Read MANIFEST.in
    long_description=read('README.md'),
    classifiers=[],
)
