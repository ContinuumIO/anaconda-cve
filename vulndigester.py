import json
from collections import defaultdict
import re
import pandas
from jinja2 import Template
import argparse


nws = re.compile("[^\w]+")

templateText="""
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Vulnerabilities report</title>
</head>
<body> 
<h2>NVD file: {{ filename }} <p>
Environment root: {{ environment }}
</h2>
{% for item in reportitems %}
    <p><p>*********<br>
    Item type: {{ item.itype }}<br>
    Name: {{ item.iname }}<br>
    CVE: {{ item.vuln.cve }}<br>
    Description: {{ item.vuln.description }}<br>
    URLS: <br>
    <blockquote>
    {% for url in item.vuln.urls %}
        <a href={{ url }}>{{ url }}</a><br>
    {% endfor %}
    </blockquote>
{% endfor %}
</body>
</html>
"""

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

class ItemReport(object):

    def __init__(self, vuln, iname, itype):
        self.vuln = vuln
        self.iname = iname
        self.itype= itype

class Digest(object):

    def __init__(self, fname, ignores={}):

        self.prodmap = defaultdict(set)
        self.cvemap = {}
        self.ignores = ignores

        self.j = json.load(open(fname, 'rb'))

        for vuln in self.j['CVE_Items']:
            v = Vulnerability(vuln)
            for prodname in v.cpeElements:
                self.prodmap[prodname].add(v.cve)
            self.cvemap[v.cve] = v

    def itemReports(self, item, itype):
        return [
            ItemReport(
                self.cvemap[vcode],
                item,
                itype
            )
            for vcode in filter(
                lambda x: x not in self.ignores,
                self.prodmap[item]
            )
        ]

def main():

    parser = argparse.ArgumentParser(
        description='Check for vulnerabilities in lists of modules, packages, libraries'
    )
    parser.add_argument(
        'vfile',
        type=str,
        help='JSON file from NVD'
    )
    parser.add_argument(
        'pkgfile',
        type=str,
        help='a list of packages in a Conda environment, one per line'
    )
    parser.add_argument(
        'libfile',
        type=str,
        help='a list of libraries in a Conda environment, one per line'
    )
    parser.add_argument(
        'modfile',
        type=str,
        help='a list of modules in a Conda environment, one per line'
    )
    parser.add_argument(
        '--html',
        action='store_true',
        default=False,
        help='HTML output rather than text'
    )
    parser.add_argument(
        '--env',
        action='store',
        type=str,
        default='Not provided',
        help='Conda environment root'
    )
    args = parser.parse_args()

    pset = set([line.strip().lower() for line in open(args.pkgfile)])
    lset = set([line.strip().lower() for line in open(args.libfile)])
    mset = set([line.strip().lower() for line in open(args.modfile)])
    ignores = pandas.read_csv('ignore.csv')
    ignores = set(ignores['cvecode'])
    d = Digest(args.vfile, ignores=ignores)
    itemset = set(d.prodmap.keys())

    reportlist = []

    for item in (pset & itemset):
        reportlist += d.itemReports(
            item,
            'Package (in CPE)'
            )
    for item in (lset & itemset):
        reportlist += d.itemReports(
            item,
            'Library (in CPE)'
            )
    for item in (mset & itemset):
        reportlist += d.itemReports(
            item,
            'Module (in CPE)'
            )

    # Search descriptions too. Maybe this ought to be a run-time option?
    for vuln in d.cvemap.values():
        if vuln.cve in ignores:
            continue
        wset = set(nws.sub(' ', vuln.description).lower().split())
        for item in (wset & pset):
            reportlist.append(
                ItemReport(
                    vuln,
                    item,
                    'Package name occurs in description'
                )
            )
        for item in (wset & lset):
            reportlist.append(
                ItemReport(
                    vuln,
                    item,
                    'Library name occurs in description'
                )
            )
        for item in (wset & mset):
            reportlist.append(
                ItemReport(
                    vuln,
                    item,
                    'Module name occurs in description'
                )
            )

    if args.html:
            t = Template(templateText)
            print t.render(
                filename = args.vfile,
                environment = args.env,
                reportitems = reportlist
            )
    else:
        print 'Environment: {}\nVulnerabilities file: {}\n\n'.format(
            args.env,
            args.vfile
        )
        for item in reportlist:
            printVuln(
                item.itype,
                item.iname,
                item.vuln
            )

if __name__ == '__main__':
    main()