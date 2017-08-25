#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import absolute_import
from __future__ import unicode_literals

from DaemonCerts.DaemonCerts import DaemonCerts

if __name__ == '__main__':
    import sys
    dc = DaemonCerts(sys.argv[1:])
    dc.main()
