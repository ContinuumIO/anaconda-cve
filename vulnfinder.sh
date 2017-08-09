#!/usr/bin/env bash
# Two parameters:
# $1 : full path to local Anaconda environment being examined,
# e.g. /Applications/anaconda/anaconda/envs/py27
# $2 : location of vulnerabilities JSON file (from NVD)

export TDIR=`mktemp -d`
export SP=`find $1 -name site-packages`

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
find $1 -name "*\.so*" \
    | grep -o "/[^/]*\.so" \
    | sed -e "s'/''g" \
    | sed -e "s/\.so$//g" \
    >$TDIR/libraries.txt

# Find packages
conda list -p  $1 \
    | tr -s ' ' \
    | cut -f 1 -d ' ' \
    | grep -v '#' \
    > $TDIR/packages.txt

python vulndigester.py --env $1 $2 $TDIR/packages.txt $TDIR/libraries.txt $TDIR/modules.txt

# For HTML output:
#python vulndigester.py --html --env $1 $2 $TDIR/packages.txt $TDIR/libraries.txt $TDIR/modules.txt

rm -rf $TDIR

