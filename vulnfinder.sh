#!/usr/bin/env bash
# One parameter: full path to local Anaconda environment being examined:
# e.g. /Applications/anaconda/anaconda/envs/py27

export TDIR=`mktemp -d`
export SP=`find $1 -name site-packages`

echo SP = $SP  # Debugging

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

echo temp directory is $TDIR  # For debugging

python vulndigester.py  vuln.json $TDIR/packages.txt $TDIR/libraries.txt $TDIR/modules.txt

# rm -rf $TDIR # When it's finally working

