# anaconda-cve
Compare vulnerabilities list available from NIST NVD against a conda environment and flag possible problems.

Usage:

vulnfinder.sh path-to-conda-environment path-to-nvd-json-file

For example:

./vulnfinder.sh /Applications/anaconda/anaconda/envs/py27 ./vuln.json

 The CSV file ignore.csv contains CVE codes which have been previously determined to be false positives
 and should not be investigated again.

 vulnfinder.sh creates the lists of modules, packages, and libraries, then calls the little Python script
 vulndigester.py. For this script there is a command-line option to produce HTML rather than text output.
 An example is provided in the vulnfinder.sh script.
