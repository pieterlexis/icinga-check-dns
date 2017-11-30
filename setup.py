import os
from setuptools import setup, find_packages
from pip.req import parse_requirements

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

# Parse requirements.txt
install_reqs=[str(ir.req) for ir in parse_requirements('./requirements.txt', session=False)]

setup(
    name="icinga-check-dns",
    version='0.0.1',
    author="Pieter Lexis",
    author_email="pieter.lexis@powerdns.com",
    description=("PowerDNS Zonecontrol DNS zone managing system"),
    license="Proprietary",
    keywords="PowerDNS Zonecontrol",
    url="https://www.powerdns.com/platform.html",
    packages=find_packages(),
    install_requires=install_reqs,
    scripts=['check_dns.py'],
    include_package_data=True,  # Read MANIFEST.in
    long_description=read('README.md'),
    classifiers=[],
)
