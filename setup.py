#!/usr/bin/env python


from distutils.core import setup


setup(name='pcapitate',
      version='0.1.0',
      description='Parses raw pcap files for a friendlier snooping experience',
      author='Keith Fancher',
      author_email='keith.fancher@gmail.com',
      license='GPLv3',
      url='https://github.com/keithfancher/Pcapitate',
      scripts=['pcapitate.py'],
      install_requires=[
#          'dpkt', # this is true, but "pip install dpkt" is broken... sigh.
          'argparse'
      ]
)
