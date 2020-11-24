# Copyright (C) 2019 FireEye, Inc. All Rights Reserved.

import re
import sys
import argparse

if __package__ is None or __package__ == "":
    from version import __version__
else:
    from .version import __version__

ASCII_BYTE = b" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"


def main():
    parser = argparse.ArgumentParser()
    # to read binary data from stdin use sys.stdin.buffer.
    #   sys.stdin is in 'r' mode, not 'rb'
    parser.add_argument('files', nargs='*', type=argparse.FileType('rb'),
                        default=[sys.stdin.buffer], help='files to process, or pipe to stdin')
    parser.add_argument('--version', action='version', version=__version__)
    parser.add_argument('-n', '--min-len', type=int, default=4,
                        help='Print sequences of characters that are at least ' +
                             'min-len characters long, instead of the default 4.')
    args = parser.parse_args()

    # regular expressions from flare-floss:
    #  https://github.com/fireeye/flare-floss/blob/master/floss/strings.py#L7-L9
    re_narrow = re.compile(b'([%s]{%d,})' % (ASCII_BYTE, args.min_len))
    re_wide = re.compile(b'((?:[%s]\x00){%d,})' % (ASCII_BYTE, args.min_len))

    for f in args.files:
        b = f.read()
        for match in re_narrow.finditer(b):
            print(match.group().decode('ascii'))
        for match in re_wide.finditer(b):
            try:
                print(match.group().decode('utf-16'))
            except UnicodeDecodeError:
                pass


if __name__ == '__main__':
    main()
