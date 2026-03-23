#!/usr/bin/env python
# Authors: Douglas Creager <dcreager@dcreager.net>
#          Calum Lind <calumlind@gmail.com>
#
# This file is placed into the public domain.
#
# Calculates the current version number by first checking output of “git describe”,
# modified to conform to PEP 386 versioning scheme.  If “git describe” fails
# (likely due to using release tarball rather than git working copy), then fall
# back on reading the contents of the RELEASE-VERSION file.
#
# Usage: Import in setup.py, and use result of get_version() as package version:
#
# from version import *
#
# setup(
#     ...
#     version=get_version(),
#     ...
# )
#
# Script will automatically update the RELEASE-VERSION file, if needed.
# Note that  RELEASE-VERSION file should *not* be checked into git; please add
# it to your top-level .gitignore file.
#
# You'll probably want to distribute the RELEASE-VERSION file in your
# sdist tarballs; to do this, just create a MANIFEST.in file that
# contains the following line:
#
#   include RELEASE-VERSION
#

import os
import time

__all__ = ('get_version',)

BASE_VERSION = '0.1.0'
VERSION_FILE = os.path.join(os.path.dirname(__file__), 'RELEASE-VERSION')


def get_version():
    # If RELEASE-VERSION exists (written by debian/rules), use it.
    try:
        with open(VERSION_FILE) as f:
            version = f.readline().strip()
            if version:
                return version
    except OSError:
        pass

    # Otherwise generate a timestamp-based dev version.
    version = '%s.dev%d' % (BASE_VERSION, int(time.time()))

    try:
        with open(VERSION_FILE, 'w') as f:
            f.write('%s\n' % version)
    except OSError:
        pass

    return version


if __name__ == '__main__':
    print(get_version())
