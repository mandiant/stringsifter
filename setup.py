#!/usr/bin/python
# -*- coding: utf-8 -*-

from distutils.core import setup
import os

_version = '0.20190905-2'
__all__ = ['metadata', 'setup']

# Get the base directory
here = os.path.dirname(__file__)
if not here:
    here = os.path.curdir

# Text describing the module
try:
    readme = os.path.join(here, 'README.md')
    with open(readme, 'r') as fid:
        long_description = fid.read()
except FileNotFoundError:
    long_description = 'stringsifter is a machine learning-based tool ' + \
                       'that automatically ranks the output of the ' + \
                       '`strings` program for binary triage analysis.'

# requirements.  we use requirements.txt for the Docker build,
# so import it here
requirements = """lightgbm==2.1.2
numpy==1.17.1
scikit-learn==0.21.3
joblib==0.13.2
pytest==3.10.1
fasttext==0.9.1""".split('\n')


# Get the list of scripts
scripts = []

_packages = ['stringsifter', 'stringsifter/lib']

# Set the parameters for the setup script
metadata = {

    # Setup instructions
    'provides': ['stringsifter'],
    'packages': _packages,
    'scripts': scripts,
    'entry_points': {
        'console_scripts': ['rank_strings=stringsifter.rank_strings:argmain',
                            'flarestrings=stringsifter.flarestrings:main']
    },
    'install_requires': requirements,
    'python_requires': '>3.6',
    # Metadata
    'name': 'stringsifter',
    'version': _version,
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
