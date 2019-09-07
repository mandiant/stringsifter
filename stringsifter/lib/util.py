# Copyright (C) 2019 FireEye, Inc. All Rights Reserved.

import io
import os
import sys
import contextlib


def package_base():
    """
    return package base folder (one level up from here)
    """
    pth = os.path.join(os.path.dirname(__file__), '..')
    return os.path.abspath(pth)


@contextlib.contextmanager
def redirect_stderr():
    _stderr = sys.stderr
    sys.stderr = io.StringIO()
    yield
    sys.stderr = _stderr
