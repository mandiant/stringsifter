<div align="center">
  <img src="misc/stringsifter-flat-dark.png" width="400">
</div>

--------------------------------------------------------------------------------

StringSifter is a machine learning tool that automatically ranks strings based on their relevance for malware analysis.

# Quick Links
* [Technical Blogpost - *Learning to Rank Strings Output for Speedier Malware Analysis*](https://www.fireeye.com/blog/threat-research/2019/05/learning-to-rank-strings-output-for-speedier-malware-analysis.html)
* [Announcement Blogpost - *Open Sourcing StringSifter*](https://www.fireeye.com/blog/threat-research/2019/09/open-sourcing-stringsifter.html)
* [DerbyCon Talk - *StringSifter: Learning to Rank Strings Output for Speedier Malware Analysis*](https://youtu.be/pLiaVzOMJSk)

# Usage

StringSifter requires Python version 3.6 or newer. Run the following commands to get the code, run unit tests, and use the tool:

## Installation

Use `pip` to get running immediately:
```sh
pip install stringsifter
```

For development, check out the correct branch for your Python version or stay on master for the latest supported version. Then use `pipenv`:
```sh
git clone https://github.com/fireeye/stringsifter.git
cd stringsifter
git checkout python3.7 #Optional
pipenv install --dev
```

## Running Unit Tests

To run unit tests from the StringSifter installation directory:

```sh
pipenv run tests
```

## Running from the Command Line

The `pip install` command installs two runnable scripts `flarestrings` and `rank_strings` into your python environment. When developing from source, use `pipenv run flarestrings` and `pipenv run rank_strings`.

`flarestrings` mimics features of GNU binutils' `strings`, and `rank_strings` accepts piped input, for example:

```sh
flarestrings <my_sample> | rank_strings
```

`rank_strings` supports a number of command line arguments.  The positional argument `input_strings` specifies a file of strings to rank.  The optional arguments are:

Option | Meaning
--- | ---
--scores (-s) | Include the rank scores in the output
--limit (-l) | Limit output to the top `limit` ranked strings
--min-score (-m) | Limit output to strings with score >= `min-score`
--batch (-b) | Specify a folder of `strings` outputs for batch processing

Ranked strings are written to standard output unless the `--batch` option is specified, causing ranked outputs to be written to files named `<input_file>.ranked_strings`.

`flarestrings` supports an option `-n` (or `--min-len`) to print sequences of characters that are at least `min-len` characters long, instead of the default 4.  For example:

```sh
flarestrings -n 8 <my_sample> | rank_strings
```

will print and rank only strings of length 8 or greater.

## Running from a Docker container

- After cloning the repo, build the container.  From the the package's top level directory:
```sh
docker build -t stringsifter -f docker/Dockerfile .
```
- Run the container with `flarestrings` or `rank_strings` argument to use the respective command. The containerized commands can be used in pipelines:
```sh
cat <my_sample> | docker run -i stringsifter flarestrings | docker run -i stringsifter rank_strings
```
- Or, run the container without arguments to get a shell prompt, using the `-v` flag to expose a host directory to the container:
```sh
docker run -v <my_malware>:/samples -it stringsifter
```
where `<my_malware>` contains samples for analysis, for example:
```sh
docker run -v $HOME/malware/binaries:/samples -it stringsifter
```
- At the container prompt:
```sh
flarestrings /samples/<my_sample> | rank_strings <options>
```

All [command line arguments](#running-from-the-command-line) are supported in the containerized scripts.

## Running on FLOSS Output

StringSifter can be applied to arbitrary lists of strings, making it useful for practitioners looking to glean insights from alternative intelligence-gathering sources such as live memory dumps, sandbox runs, or binaries that contain obfuscated strings. For example, [FireEye Labs Obfuscated Strings Solver (FLOSS)](https://github.com/fireeye/flare-floss) extracts printable strings just as *Strings* does, but additionally reveals obfuscated strings that have been encoded, packed, or manually constructed on the stack. It can be used as an in-line replacement for Strings, meaning that StringSifter can be similarly invoked on FLOSS output using the following command:

```sh
$PY2_VENV/bin/floss –q <options> <my_sample> | rank_strings <options>
```

Notes:
1. The `–q` argument suppresses headers and formatting to show only extracted strings. To learn more about additional FLOSS options, please see its [Usage Docs](https://github.com/fireeye/flare-floss/blob/master/doc/usage.md).
2. FLOSS requires Python 2, while StringSifter requires Python 3.  In the example command at least one of `floss` or `rank_strings` must include a relative path referencing a python virtual enviroment.
3. FLOSS can be downloaded as a [standalone executable](https://github.com/fireeye/flare-floss/releases). In this case it is not required to specify a Python environment because the executable does not rely on a Python interpreter.

## Notes on running `strings`

This distribution includes the `flarestrings` program to ensure predictable output across platforms.  If you choose to run your system's installed `strings` note that its options are not consistent across versions and platforms:

### Linux

Most Linux distributions include the `strings` program from GNU Binutils.  To extract both "wide" and "narrow" strings the program must be run twice, piping to an output file:

```sh
strings <my_sample>       > strs.txt   # narrow strings
strings -el <my_sample>  >> strs.txt   # wide strings.  note the ">>"
```

### MacOS

Some versions of BSD `strings` packaged with MacOS do not support wide strings.  Also note that the `-a` option to strings to scan the whole file may be disabled in the default configuration.  Without `-a` informative strings may be lost.  We recommend installing GNU Binutils via Homebrew or MacPorts to get a version of `strings` that supports wide characters.  Use care to invoke the correct version of `strings`.

### Windows

`strings` is not installed by default on Windows. We recommend installing [Windows Sysinternals](https://docs.microsoft.com/en-us/sysinternals/), [Cygwin](https://www.cygwin.com/), or [Malcode Analyst Pack](http://sandsprite.com/iDef/MAP/) to get a working `strings`.

# Discussion
This version of StringSifter was trained using *Strings* outputs from sampled malware binaries associated with the first [EMBER dataset](https://github.com/endgameinc/ember). Ordinal labels were generated using weak supervision procedures, and supervised learning is performed by [Gradient Boosted Decision Trees](https://github.com/microsoft/LightGBM) with a learning-to-rank objective function. See [Quick Links](#quick-links) for further technical details. Please note that neither labeled data nor training code is currently available, though we may reconsider this approach in future releases.

## Issues
We use [GitHub Issues](https://github.com/fireeye/stringsifter/issues) for posting bugs and feature requests.

## Acknowledgements
- Thanks to the FireEye Data Science (FDS) and FireEye Labs Reverse Engineering (FLARE) teams for review and feedback.
- StringSifter was designed and developed by Philip Tully (FDS), Matthew Haigh (FLARE), Jay Gibble (FLARE), and Michael Sikorski (FLARE).
- The StringSifter logo was designed by Josh Langner (FLARE).
- `flarestrings` is derived from the excellent tool [FLOSS](https://github.com/fireeye/flare-floss/blob/master/floss/strings.py#L7-L9).
