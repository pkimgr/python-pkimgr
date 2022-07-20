"""setup.py for pkimgr project"""
#!/usr/bin/env python

from setuptools import setup

from pkimgrlib import __version__


setup(name='Pkimgr',
      version=__version__,
      description='Simple PKI manager',
      author='Wampixel',
      maintainer='Wampixel',
      url='https://gitlab.com/pkimgr/python-pkimgr',
      python_requires=">= 3.8",
      install_requires=[
            'crytography >= 3.4.6',
            'pyaml >= 20.4.0'
      ],
      packages=['pkimgrlib'],
      package_dir={
        'pkimgrlib': 'src/pkimgrlib',
      },
      package_data={
        'default_conf': ['default_conf/default_certificate.yaml', 'default_conf/logger.yaml'],
      },
      scripts=['bin/pkimgr'],
     )
