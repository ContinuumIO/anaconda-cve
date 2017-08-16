# anaconda-cve
Compare vulnerabilities list available from NIST NVD against a conda environment and flag possible problems.
This will run on Linux/Unix systems and on Windows, but needs to be run under Cygwin in the latter case. 
Usage:

`vulnfinder.sh path-to-conda-environment path-to-nvd-json-file`

For example:

`./vulnfinder.sh /Applications/anaconda/anaconda/envs/py27 ./vuln.json`

 The CSV file ignore.csv contains CVE codes which have been previously determined to be false positives
 and should not be investigated again.
 
 The file ignore-words.txt contains a list of common words 
 (one per line, not case sensitive) of words which occur so frequently 
 in vulnerability descriptions that they should be ignored, even if they match 
 the name of a module or package or library. (Likely false positives, in other 
 words.)

 vulnfinder.sh creates the lists of modules, packages, and libraries, then calls the little Python script
 vulndigester.py. For this script there is a command-line option to produce HTML rather than text output.

vulnfinder.py can be run by itself as well if you already have lists of modules, packages, and libraries.

`vulnfinder.py -h` 

will explicate the various parameters and options:

```
usage: vulndigester.py [-h] [--html] [--description]
                       [--ignore-words /path/to/word/list]
                       [--env /path/to/environment/root]
                       vfile pkgfile libfile modfile

Check for vulnerabilities in lists of modules, packages, libraries

positional arguments:
  vfile                 JSON file from NVD
  pkgfile               a list of packages in a Conda environment, one per
                        line
  libfile               a list of libraries in a Conda environment, one per
                        line
  modfile               a list of modules in a Conda environment, one per line

optional arguments:
  -h, --help            show this help message and exit
  --html                HTML output rather than text
  --description, -d     Search language of descriptions as well as CPE codes
  --ignore-words /path/to/word/list, -i /path/to/word/list
                        File containing a list of words to ignore in
                        descriptions, one per line.
  --env /path/to/environment/root
                        Conda environment root
```
