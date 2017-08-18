import json
from collections import defaultdict
import re
import pandas
from jinja2 import Template
import argparse


nws = re.compile("[^\w]+")  # 'No white space'

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
    Item type: <br>
    <blockquote>
    {% for t in  item.itype %}
        {{ t }}<br>
    {% endfor %}
    </blockquote><br>
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
Item type: 
 {}
Name: {}
CVE: {}
Description: {}
URLS: 
 {}

"""

def updateReports(
        dest,
        src
    ):
    """
    Merge 'item type' descriptions into a single report
    :param dest: a dict {cve code : ItemReport obj}
    :param src: same as dest, or a single ItemReport obj
    :return: Updated dest parameter
    """
    if isinstance(src, dict):
        for cve, report in src.items():
            if cve in dest:
                dest[cve].itype += report.itype
            else:
                dest[cve] = report
    else:  # a single ItemReport object -- this for convenience
        scve = src.vuln.cve
        if scve in dest:
            dest[scve].itype += src.itype
        else:
            dest[scve] = src
    return dest

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
        self.itype= [itype]

    def updateReport(self, newtype):
        self.itype.append(newtype)

    def printReport(self):
        print reportItem.format(
            '\n '.join(self.itype),
            self.iname,
            self.vuln.cve,
            self.vuln.description,
            '\n '.join(self.vuln.urls)
        )

class Digest(object):
    """
    Representation of NVD vulnerabilities JSON file
    """

    def __init__(
            self,
            vfile,
            ignores={}
    ):
        """
        :param vfile: An NVD json file
        :param ignores: A set of CVE codes to ignore
        """
        self.prodmap = defaultdict(set)
        self.cvemap = {}
        self.ignores = ignores

        self.j = json.load(vfile)

        for vuln in self.j['CVE_Items']:
            v = Vulnerability(vuln)
            for prodname in v.cpeElements:
                self.prodmap[prodname].add(v.cve)
            self.cvemap[v.cve] = v

    def itemReports(self, item, itype):
        reports = {}
        for vcode in filter(
            lambda x: x not in self.ignores,
            self.prodmap[item]
        ):
            reports[vcode] = ItemReport(
                self.cvemap[vcode],
                item,
                itype
            )
        return reports


def main():

    parser = argparse.ArgumentParser(
        description='Check for vulnerabilities in lists of modules, packages, libraries'
    )
    parser.add_argument(
        'vfile',
        type=argparse.FileType('r'),
        help='JSON file from NVD'
    )
    parser.add_argument(
        'pkgfile',
        type=argparse.FileType('r'),
        help='a list of packages in a Conda environment, one per line'
    )
    parser.add_argument(
        'libfile',
        type=argparse.FileType('r'),
        help='a list of libraries in a Conda environment, one per line'
    )
    parser.add_argument(
        'modfile',
        type=argparse.FileType('r'),
        help='a list of modules in a Conda environment, one per line'
    )
    parser.add_argument(
        '--html',
        action='store_true',
        default=False,
        help='HTML output rather than text'
    )
    parser.add_argument(
        '--description',
        '-d',
        action='store_true',
        default=False,
        help='Search language of descriptions as well as CPE codes'
    )
    parser.add_argument(
        '--ignore-words',
        '-i',
        type=argparse.FileType('r'),
        default=None,
        metavar='/path/to/word/list',
        help='File containing a list of words to ignore in descriptions, one per line.'
    )
    parser.add_argument(
        '--env',
        action='store',
        metavar='/path/to/environment/root',
        type=str,
        default='Not provided',
        help='Conda environment root'
    )
    args = parser.parse_args()

    pset = set([line.strip().lower() for line in args.pkgfile])
    lset = set([line.strip().lower() for line in args.libfile])
    mset = set([line.strip().lower() for line in args.modfile])
    ignores = pandas.read_csv('ignore.csv')
    ignores = set(ignores['cvecode'])
    d = Digest(args.vfile, ignores=ignores)
    itemset = set(d.prodmap.keys())

    reports = {}

    for item in (pset & itemset):
        updateReports(
            reports,
            d.itemReports(
                item,
                'Package in CPE'
            )
        )
    for item in (lset & itemset):
        updateReports(
            reports,
            d.itemReports(
                item,
                'Library in CPE'
            )
        )
    for item in (mset & itemset):
        updateReports(
            reports,
            d.itemReports(
                item,
                'Module in CPE'
            )
        )

    # Search descriptions too?
    if args.description:
        if args.ignore_words:
            iwset = set([line.strip().lower() for line in args.ignore_words])
        else:
            iwset = set()
        for vuln in d.cvemap.values():
            if vuln.cve in ignores:
                continue
            wset = set(nws.sub(' ', vuln.description).lower().split())
            for item in ((wset & pset) - iwset):
                updateReports(
                    reports,
                    ItemReport(
                        vuln,
                        item,
                        'Package name occurs in description'
                    )
                )
            for item in ((wset & lset) - iwset):
                updateReports(
                    reports,
                    ItemReport(
                        vuln,
                        item,
                        'Library name occurs in description'
                    )
                )
            for item in ((wset & mset) - iwset):
                updateReports(
                    reports,
                    ItemReport(
                        vuln,
                        item,
                        'Module name occurs in description'
                    )
                )

    reportlist= sorted(reports.values(), key=lambda x : x.iname)

    if args.html:
            t = Template(templateText)
            print t.render(
                filename = args.vfile.name,
                environment = args.env,
                reportitems = reportlist
            )
    else:
        print 'Environment: {}\nVulnerabilities file: {}\n\n'.format(
            args.env,
            args.vfile.name
        )
        for item in reportlist:
            item.printReport()

if __name__ == '__main__':
    main()