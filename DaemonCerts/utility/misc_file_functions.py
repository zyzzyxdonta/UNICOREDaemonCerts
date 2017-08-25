# -*- coding: utf-8 -*-
from __future__ import print_function
from __future__ import absolute_import

import os

def mkdir_p(path):
    import errno
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise
