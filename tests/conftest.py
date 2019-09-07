# Copyright (C) 2019 FireEye, Inc. All Rights Reserved.

import pytest
import stringsifter.preprocess as preprocess

@pytest.fixture(scope='module')
def featurizer():
    f = preprocess.Featurizer()
    yield f
