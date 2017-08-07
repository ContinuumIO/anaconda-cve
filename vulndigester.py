import json
from collections import defaultdict
import sys
import re

nws = re.compile("[^\w]+")

reportItem="""

*********
Item type: {}
Name: {}
CVE: {}
Description: {}
URLS: 
 {}

"""
def printVuln(itype, iname, vuln):
    print reportItem.format(
        itype,
        iname,
        vuln.cve,
        vuln.description,
        '\n '.join(vuln.urls)
    )

def printItem(itype, iname, digest):
    for vname in digest.prodmap[iname]:
        printVuln(
            itype,
            iname,
            digest.cvemap[vname]
        )

def extractFromCPE(nodes):
    elements = set()
    for node in nodes:
        if 'cpe' in node:
            elements = set([cpe['cpe23Uri'].split(':')[4].lower() for cpe in node['cpe']])
        elif 'children' in node:
            elements |= extractFromCPE(node['children'])
    return elements

class Vulnerability(object):

    def __init__(self, v):
        self.cpeElements = extractFromCPE(v['configurations']['nodes'])
        self.cve = v['cve']['CVE_data_meta']['ID']
        self.urls = [
            rd['url'] for rd in v['cve']['references']['reference_data']
        ]
        self.description = ''
        for desc in v['cve']['description']['description_data']:
            if desc['lang'] == 'en':
                self.description = desc['value']
                break


class Digest(object):

    def __init__(self, fname):

        self.prodmap = defaultdict(set)
        self.cvemap = {}

        self.j = json.load(open(fname, 'rb'))

        for vuln in self.j['CVE_Items']:
            v = Vulnerability(vuln)
            for prodname in v.cpeElements:
                self.prodmap[prodname].add(v.cve)
            self.cvemap[v.cve] = v

def main(vfile, pkgfile, libfile, modfile):

    d = Digest(vfile)

    pset = set([line.strip().lower() for line in open(pkgfile)])
    lset = set([line.strip().lower() for line in open(libfile)])
    mset = set([line.strip().lower() for line in open(modfile)])
    itemset = set(d.prodmap.keys())

    for item in (pset & itemset):
        printItem(
            'Package (in CPE)',
            item,
            d
        )
    for item in (lset & itemset):
        printItem(
            'Library (in CPE)',
            item,
            d
        )
    for item in (mset & itemset):
        printItem(
            'Module (in CPE)',
            item,
            d
        )
    # Search descriptions too. This ought to be a run-time option.
    for vuln in d.cvemap.values():
        wset = set(nws.sub(' ', vuln.description).lower().split())
        for item in (wset & pset):
            printVuln(
                'Package name occurs in description',
                item,
                vuln
            )
        for item in (wset & lset):
            printVuln(
                'Library name occurs in description',
                item,
                vuln
            )
        for item in (wset & mset):
            printVuln(
                'Module name occurs in description',
                item,
                vuln
            )

if __name__ == '__main__':
    main(*sys.argv[1:])