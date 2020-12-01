# Copyright (C) 2019 FireEye, Inc. All Rights Reserved.

from setuptools import setup
import os
import re

__all__ = ['metadata', 'setup']

# Get the base directory
here = os.path.dirname(__file__)
if not here:
    here = os.path.curdir

# Text describing the module
long_description = 'stringsifter is a machine learning-based tool ' + \
                   'that automatically ranks the output of the ' + \
                   '`strings` program for binary triage analysis.'

# Get the version
versfile = os.path.join(here, 'stringsifter', 'version.py')
_version = {}
with open(versfile, 'r') as fid:
    exec(fid.read(), _version)

# Do some Pipfile parsing to avoid two copies of the requirements,
# but this is fragile
reqsfile = os.path.join(here, 'Pipfile')
requirements = []
with open(reqsfile, 'r') as fid:
    in_packages_section = False
    for line in fid.readlines():
        if line.startswith('['):
            in_packages_section = line.rstrip() == '[packages]'
            continue
        if in_packages_section:
            m = re.match(r'([\w-]+) *= *"(.*)"', line)
            if m:
                if m.group(2) == '*':
                    requirements.append(m.group(1))
                else:
                    requirements.append(m.group(1) + m.group(2))

# Get the list of scripts
scripts = []

_packages = ['stringsifter', 'stringsifter/lib']

_package_data = {'stringsifter': ['model/*.pkl',
                                  'lib/*.pkl',
                                  'lib/*.ftz',
                                  'lib/*.json']}

# Set the parameters for the setup script
metadata = {
    # Setup instructions
    'provides': ['stringsifter'],
    'packages': _packages,
    'package_data': _package_data,
    'scripts': scripts,
    'entry_points': {
        'console_scripts': ['rank_strings=stringsifter.rank_strings:argmain',
                            'flarestrings=stringsifter.flarestrings:main']
    },
    'install_requires': requirements,
    'python_requires': '>=3.8',
    # Metadata
    'name': 'stringsifter',
    'version': _version['__version__'],
    'description': 'stringsifter is a machine learning-based tool that ' + \
                   'automatically ranks the output of the `strings` ' + \
                   'program for binary triage analysis.',
    'long_description': long_description,
    'url': 'https://github.com/fireeye/stringsifter',
    'download_url': 'https://github.com/fireeye/stringsifter',
    'keywords': ['stringsifter', 'rank', 'strings', 'binary', 'triage'],
    }

# Execute the setup script
if __name__ == '__main__':
    setup(**metadata)
