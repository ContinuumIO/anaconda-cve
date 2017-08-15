#!/usr/bin/env bash
# Two parameters:
# $1 : full path to local Anaconda environment being examined,
# e.g. /Applications/anaconda/anaconda/envs/py27
# or for Windows, say C:/Users/johnsmith/Anaconda2/py27
# Note the Unix-y path separators -- since this needs to be run (in Windows) under Cygwin
# $2 : location of vulnerabilities JSON file (from NVD)

export SP=`find $1 -name site-packages`
if uname -a | egrep -s CYGWIN
then
    export LIBSUFFIX=dll
else
    export LIBSUFFIX=so
fi

export TDIR=`python ./mktempfile.py`

echo $LIBSUFFIX
echo $TDIR


# Find top-level modules
# Query: include sub-module names too?
find $SP -name "__init__.py" \
    | sed -e "s|$SP||" \
    | cut -f 2 -d '/' \
    | cut -f 1 -d '-' \
    | sort \
    | uniq \
    > $TDIR/modules.txt

# Find libraries
find $1 -name "*\.$LIBSUFFIX" \
    | grep -o "/[^/]*\.$LIBSUFFIX" \
    | sed -e "s'/''g" \
    | sed -e "s/\.$LIBSUFFIX$//g" \
    >$TDIR/libraries.txt

# Find packages
conda list -p  $1 \
    | tr -s ' ' \
    | cut -f 1 -d ' ' \
    | grep -v '#' \
    > $TDIR/packages.txt

echo $TDIR

python vulndigester.py -d -i ignore-words.txt --env $1 $2 $TDIR/packages.txt $TDIR/libraries.txt $TDIR/modules.txt

# vulndigester.py has a number of options
# python vulndigester.py -h will explain them, a bit tersely

#rm -rf $TDIR

