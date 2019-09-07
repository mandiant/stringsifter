# Copyright (C) 2019 FireEye, Inc. All Rights Reserved.

import os
import numpy
from io import StringIO
import stringsifter.rank_strings as rank_strings

test_strings = 'testing text\n' \
                'nagain\n' \
                'wheredoesitgo\n' \
                'testing text\n' \
                'nagain\n' \
                'wheredoesitgo\n' \
                'testing text\n' \
                'nagain\n' \
                'wheredoesitgo\n' \
                'testing text\n'


def _get_rank_strings_stdoutput(capsys, kwargs):
    rank_strings.main(**kwargs)
    stdout = capsys.readouterr().out
    return stdout.split('\n')[:-1]


def _get_kwargs(input_strings=test_strings, cutoff=None,
                cutoff_score=numpy.nan, scores=False, batch=False):
    return {'input_strings': StringIO(input_strings),
            'cutoff': cutoff,
            'cutoff_score': cutoff_score,
            'scores': scores,
            'batch': batch}


def test_string_length(featurizer):
    test_set = [['', 0],
                ['foo', 3],
                ['everybody', 9]]
    for s, true_len in test_set:
        feat_len = featurizer.string_length(s)
        assert feat_len == true_len


def test_default(capsys):
    """
    test default processing flow: # strings in == # strings out
    """
    output_lines = _get_rank_strings_stdoutput(capsys, _get_kwargs())
    assert len(output_lines) == 10


def test_scores(capsys):
    scores_value = True
    output_lines = _get_rank_strings_stdoutput(
        capsys, _get_kwargs(scores=scores_value))
    split_output_lines = [output_line.split(",") for output_line
                          in output_lines]
    previous_score = numpy.inf
    for output_score, output_string in split_output_lines:
        assert(type(output_string) is str)
        float_output_score = float(output_score)
        assert(type(float_output_score) is float)
        assert(previous_score >= float_output_score)
        previous_score = float_output_score


def test_cutoff(capsys):
    cutoff_value = 5
    output_lines = _get_rank_strings_stdoutput(
        capsys, _get_kwargs(cutoff=cutoff_value))
    assert len(output_lines) == cutoff_value


def test_cutoff_score(capsys):
    scores_value = True
    cutoff_score_value = 0.0
    output_lines = _get_rank_strings_stdoutput(
        capsys, _get_kwargs(scores=scores_value,
                            cutoff_score=cutoff_score_value))
    split_output_lines = [output_line.split(",") for output_line
                          in output_lines]
    for output_score, output_string in split_output_lines:
        assert float(output_score) >= cutoff_score_value


def test_batch():
    batch_value = 'tests/fixtures/'
    batch_files = [batch_value + batch_file for batch_file in
                   os.listdir(batch_value)]
    output_lines = rank_strings.main(
        **_get_kwargs(batch=batch_value))
    for batch_file in batch_files:
        ranking_file = batch_file + '.ranked_strings'
        assert os.path.isfile(ranking_file) is True
        os.remove(ranking_file)
