# Copyright (C) 2019 FireEye, Inc. All Rights Reserved.

"""
english letter probabilities

table from http://en.algoritmy.net/article/40379/Letter-frequency-English
"""

english_letter_probs_percent = [
    ['a', 8.167],
    ['b', 1.492],
    ['c', 2.782],
    ['d', 4.253],
    ['e', 12.702],
    ['f', 2.228],
    ['g', 2.015],
    ['h', 6.094],
    ['i', 6.966],
    ['j', 0.153],
    ['k', 0.772],
    ['l', 4.025],
    ['m', 2.406],
    ['n', 6.749],
    ['o', 7.507],
    ['p', 1.929],
    ['q', 0.095],
    ['r', 5.987],
    ['s', 6.327],
    ['t', 9.056],
    ['u', 2.758],
    ['v', 0.978],
    ['w', 2.360],
    ['x', 0.150],
    ['y', 1.974],
    ['z', 0.074]]

english_letter_probs = {lt: (per * 0.01) for lt, per in english_letter_probs_percent}


"""
Scrabble Scores
table from https://en.wikipedia.org/wiki/Scrabble_letter_distributions
"""
scrabble_dict = {"a": 1, "b": 3, "c": 3,  "d": 2, "e": 1,  "f": 4,
                 "g": 2, "h": 4, "i": 1,  "j": 8, "k": 5,  "l": 1,
                 "m": 3, "n": 1, "o": 1,  "p": 3, "q": 10, "r": 1,
                 "s": 1, "t": 1, "u": 1,  "v": 4, "w": 4,  "x": 8,
                 "y": 4, "z": 10}
