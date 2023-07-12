# Copyright (C) 2019 FireEye, Inc. All Rights Reserved.

import os
import sys
import numpy
import joblib
import argparse


if __package__ is None or __package__ == "":
    from lib import util
    from version import __version__
else:
    from .lib import util
    from .version import __version__


def is_valid_dir(parser, arg):
    arg = os.path.abspath(arg)
    if not os.path.exists(arg):
        parser.error("The directory %s does not exist!" % arg)
    else:
        return arg


def main(input_strings, cutoff, cutoff_score, scores, batch):
    modeldir = os.path.join(util.package_base(), "model")
    featurizer = joblib.load(os.path.join(modeldir, "featurizer.pkl"))
    ranker = joblib.load(os.path.join(modeldir, "ranker.pkl"))

    if not batch:
        strings = numpy.array([line.strip() for line in
                               input_strings.readlines()], dtype=object)

        if len(strings) < 1:
            raise ValueError("No strings found within input.")

        X_test = featurizer.transform(strings)
        y_scores = ranker.predict(X_test)

        if not numpy.isnan(cutoff_score):
            above_cutoff_indices = numpy.where(y_scores >= cutoff_score)
            y_scores = y_scores[above_cutoff_indices]
            strings = strings[above_cutoff_indices]

        argsorted_y_scores = numpy.argsort(y_scores)[::-1]
        sorted_strings = strings[argsorted_y_scores]
        cutoff_sorted_strings = sorted_strings.tolist()[:cutoff]

        if scores:
            sorted_y_scores = y_scores[argsorted_y_scores]
            print("\n".join(["%.2f,%s" % pair for pair in
                             zip(sorted_y_scores, cutoff_sorted_strings)]))
        else:
            print("\n".join(cutoff_sorted_strings))
    else:
        strings = []
        qids = []
        batch_files = os.listdir(batch)

        for batch_input_file in batch_files:
            with open(os.path.join(batch, batch_input_file)) as batch_input_fp:
                string_i = [line.strip() for line in
                            batch_input_fp.readlines()]
            strings.extend(string_i)
            qids.append(len(string_i))

        if len(strings) < 1:
            raise ValueError("No strings found in batch directory.")

        X_test = featurizer.transform(strings)
        y_scores = ranker.predict(X_test)

        strings_grouped = numpy.split(strings,
                                      numpy.cumsum(qids))[:-1]
        y_scores_grouped = numpy.split(y_scores, numpy.cumsum(qids))[:-1]

        batch_file_suffix = ".ranked_strings"
        for batch_file, strings_i, y_scores_i in zip(batch_files,
                                                     strings_grouped,
                                                     y_scores_grouped):
            with open(os.path.join(batch, batch_file + batch_file_suffix),
                      "w") as batch_output_fp:

                if not numpy.isnan(cutoff_score):
                    above_cutoff_indices_i = numpy.where(
                        y_scores_i >= cutoff_score)
                    y_scores_i = y_scores_i[above_cutoff_indices_i]
                    strings_i = strings_i[above_cutoff_indices_i]

                argsorted_y_scores_i = numpy.argsort(y_scores_i)[::-1]
                sorted_strings_i = strings_i[argsorted_y_scores_i]
                cutoff_sorted_strings_i = sorted_strings_i.tolist()[:cutoff]
                cutoff_sorted_strings_newlines_i = map(lambda s: s + "\n",
                                                       cutoff_sorted_strings_i)
                if scores:
                    sorted_y_scores_i = y_scores_i[argsorted_y_scores_i]
                    scores_strings_i = zip(sorted_y_scores_i,
                                           cutoff_sorted_strings_newlines_i)
                    scores_strings_combined_i = ["%.2f,%s" % (score_i, string_i)
                                                 for score_i, string_i in
                                                 scores_strings_i]
                    batch_output_fp.writelines(scores_strings_combined_i)
                else:
                    batch_output_fp.writelines(
                        cutoff_sorted_strings_newlines_i)


# entry point for script
def argmain():
    parser = argparse.ArgumentParser(
        description="StringSifter ranks strings based on their \
                     relevance for malware analysis.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument(
        "input_strings", nargs="?", type=argparse.FileType("r"),
        default=sys.stdin, help="Read input strings from stdin")
    parser.add_argument('--version', action='version', version=__version__)
    parser.add_argument(
        '--scores', '-s', action='store_true',
        help="display rank scores within output  \
              (default: scores not displayed)")
    parser.add_argument(
        '--batch', '-b', type=lambda adir: is_valid_dir(parser, adir),
        help="enable batch mode, where dir contains files  \
              containing Strings outputs to be ranked by  \
              StringSifter. This creates new files in dir \
              with StringSifter results denoted with the \
              .ranked_strings extention")

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        '--limit', '-l', type=int, default=None,
        help="limit output to the top `limit` ranked strings (default: no limit)")
    group.add_argument(
        '--min-score', '-m', type=float, default=numpy.nan,
        help="limit output to strings with score >= `min-score` (default: no min score)")
    args = parser.parse_args()

    main(args.input_strings, args.limit, args.min_score,
         args.scores, args.batch)


if __name__ == '__main__':
    argmain()
