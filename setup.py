"""setup.py for pkimgr project"""
#!/usr/bin/env python

from setuptools import setup

from pkimgrlib import __version__

with open('requirements.txt', 'r', encoding='UTF-8') as requirements_f:
    requirements = requirements_f.read().splitlines()

setup(name='Pkimgr',
      version=__version__,
      description='Simple PKI manager',
      author='Wampixel',
      maintainer='Wampixel',
      url='https://gitlab.com/pkimgr/python-pkimgr',
      python_requires=">= 3.8",
      install_requires=requirements,
      packages=['pkimgrlib', 'pkimgrlib.pki', 'pkimgrlib.cli'],
      package_dir={
        'pkimgrlib': 'src/pkimgrlib',
      },
      data_files=[
        ('pkimgr/default_conf', [
            'default_conf/default_certificate.yaml', 'default_conf/logger.yaml'
        ]),
        ('pkimgr/log', [])
      ],
      scripts=['bin/pkimgr'],
     )
