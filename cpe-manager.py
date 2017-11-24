#!/usr/bin/env python3
"""
Copyright 2016, 2017
 Vincent Danen <vdanen@redhat.com>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
   General Public License <gnu.org/licenses/gpl.html> for more details.
"""

import argparse
import requests
import sys
from collections import namedtuple
from cpe import CPE
from cpe.cpe2_2 import CPE2_2

try:
    import xml.etree.cElementTree as ET
except:
    import xml.etree.ElementTree as ET


def parse_cpedictionary(cpedict_file=None):
    """
    Function to parse cpe-dictionary.xml
    """
    ns = 'http://cpe.mitre.org/dictionary/2.0'
    cpedict = {}
    def query(tree, nodename):
        return tree.find('{{{ex}}}{nodename}'.format(ex=ns, nodename=nodename))

    if not cpedict_file:
        try:
            # try a local file first
            with open('./cpe-dictionary.xml', 'r') as f:
                root = ET.fromstring(f.read())
        except:
            try:
                # try the default Red Hat cpe-dictionary.xml
                r = requests.get('https://www.redhat.com/security/data/metrics/cpe-dictionary.xml')
                root = ET.fromstring(r.text)
            except requests.exceptions.RequestException as e:
                print('Unexpected error occurred and no local file to read from: %s' % e)
                sys.exit(1)
    else:
        if 'http' in cpedict_file:
            try:
                r = requests.get(cpedict_file)
                root = ET.fromstring(r.text)
            except requests.exceptions.RequestException as e:
                print('Unexpected error occurred while obtaining %s: %s' % (cpedict_file, e))
                sys.exit(1)
            except ET.ParseError:
                print('Invalid XML found while loading %s; cannot parse' % cpedict_file)
                sys.exit(1)
        else:
            try:
                with open(cpedict_file, 'r') as f:
                    root = ET.fromstring(f.read())
            except FileNotFoundError:
                print('No such file or directory: %s' % cpedict_file)
                sys.exit(1)

    for cpe in root:
        name  = cpe.attrib['name']
        title = query(cpe, 'title').text
        cpedict[name] = title

    return cpedict


def validate(the_cpe, mode):
    """Try to validate the CPE"""
    if mode == '2.2':
        try:
            c22 = CPE2_2(the_cpe)
        except NotImplementedError:
            return('Invalid CPE: %s!' % the_cpe)
        except ValueError as e:
            return('Invalid CPE: %s (%s)' % (the_cpe, e))

        return c22
    elif mode == '2.3':
        try:
            c23 = CPE(the_cpe)
        except NotImplementedError:
            return('Invalid CPE: %s!' % the_cpe)
        except ValueError as e:
            return('Invalid CPE: %s (%s)' % (the_cpe, e))

        return c23


def get_cpe(the_cpe, mode, rhmode=True):
    """Turn a CPE string into a named object as a convenience"""
    myCPE = namedtuple('myCPE', 'part vendor product version update edition language sw_edition target_sw target_hw other cpe23 cpe')

    tcpe = validate(the_cpe, mode)
    if type(tcpe) == type('str'):
        # send the error string back to where it's useful
        return tcpe

    if rhmode:
        if tcpe.get_vendor()[0].strip('"') != 'redhat':
            return('Validation failed (not a Red Hat CPE!): %s' % the_cpe)

    if mode == '2.2':
        # we want the formatted type to be a 2.3-formatted CPE
        cpe23 = validate(the_cpe, '2.3')
    else:
        cpe23 = tcpe

    parts = myCPE(part       = tcpe.get_part()[0].strip('"'),
                  vendor     = tcpe.get_vendor()[0].strip('"'),
                  product    = tcpe.get_product()[0].strip('"'),
                  version    = tcpe.get_version()[0].strip('"'),
                  update     = tcpe.get_update()[0].strip('"'),
                  edition    = tcpe.get_edition()[0].strip('"'),
                  language   = tcpe.get_language()[0].strip('"'),
                  sw_edition = tcpe.get_software_edition()[0].strip('"'),
                  target_sw  = tcpe.get_target_software()[0].strip('"'),
                  target_hw  = tcpe.get_target_hardware()[0].strip('"'),
                  other      = tcpe.get_other()[0].strip('"'),
                  cpe23      = cpe23,
                  cpe        = tcpe)

    return parts


def describe_cpe(cpe_string, mode, rhmode=True):
    """Describe the parts of the provided CPE"""
    the_cpe = get_cpe(cpe_string, mode, rhmode)
    if type(the_cpe) == type('str'):
        print('Validation failed: %s' % the_cpe)
        sys.exit(1)

    part_map = {'a': 'Application', 'h': 'Hardware', 'o': 'Operating System'}

    print("""
    Refer to http://csrc.nist.gov/publications/nistir/ir7695/NISTIR-7695-CPE-Naming.pdf for the full specification,
    but in a nutshell:

    Part can be one of: a (Application), h (Hardware), or o (Operating System)
    Vendor is the supplier name and should be an abridged version of the primary DNS hostname (e.g. 'redhat.com' becomes
      'redhat' or 'oxford.ac.uk' becomes 'oxford')
    Product is a short and recognizable name of the product, where no such short recognition exists it should be the full
      name of the product with spaces underscored (e.g. 'red_hat_enterprise_linux' would be used if 'rhel' were not
      recognized as the same)
    Version is the version of the project and should be represented in the same way as the product (e.g. 'Foo 1-1' would
      use '1-1' or 'Bar 1.1-p3' would be '1.1-p3'.  There is no way in CPE to note major and minor versions so you can
      opt to use this field for the major (e.g. '1') and the Update field for the minor
    Update is used for update or service pack information, and may be referred to as a point or minor version.  In the
      case of a version "0" you can use the vendor term for initial release (e.g. you could use '0' to refer to RHEL 7.0
      or 'ga' in the case of RHEL 7 GA).  If there is no commonly used term for the initial release, then '-' should be
      used for that CPE (e.g. "Foo 1" would be "foo:1:-:" unless it was referred to as "Foo 1.0" in which case "foo:1:0:"
      may be more appropriate)
    Edition is used for the edition of this platform, e.g. "workstation" or "server" or "professional", etc.""")
    if mode == '2.3':
        print("""      NOTE: This is available for legacy CPE 2.2 compatability but is considered deprecated in 2.3
    Language is used for the language used for this product (e.g. "zh-tw" for traditional Chinese)
    Software Edition is used to characterise how the product is tailored for a particular maket or class of end users
    Target Software is used to indicate the software environment within which the product operates
    Target Hardware is used to indicate the architecture on whioch the product operates (e.g. "x86" or "x86_64")
    Other is used to capture any other general descriptive or identifying infomration which is vendor- or
      product-specific
            """)

    print('Given the CPE string "%s":\n' % cpe_string)
    print('              Part: %s [%s]' % (the_cpe.part, part_map[the_cpe.part]))
    print('            Vendor: %s' % the_cpe.vendor)
    print('           Product: %s' % the_cpe.product)
    print('           Version: %s' % the_cpe.version)
    print('            Update: %s' % the_cpe.update)
    print('           Edition: %s' % the_cpe.edition)
    if mode == '2.3':
        print('          Language: %s' % the_cpe.language)
        print('  Software Edition: %s' % the_cpe.sw_edition)
        print('   Target Software: %s' % the_cpe.target_sw)
        print('   Target Hardware: %s' % the_cpe.target_hw)
        print('             Other: %s' % the_cpe.other)


if __name__ == '__main__':
    """The main program"""

    parser = argparse.ArgumentParser()
    parser.add_argument('-x', '--xml', dest='xml', help='Use this cpe-dictionary.xml file; defaults to https://www.redhat.com/security/data/metrics/cpe-dictionary.xml if not found in the current working directory')
    parser.add_argument('-v', '--validate', dest='validate', action='store_true', help='Validate CPEs found in cpe-dictionary.xml')
    parser.add_argument('-c', '--cpe', dest='mycpe', metavar='CPE', help='Operate on this provided CPE string')
    parser.add_argument('-d', '--describe', dest='describe', action='store_true', help='Describe the provided CPE string')
    parser.add_argument('-w', '--wfn', dest='wfn', action='store_true', help="Returns the CPE name as a WFN string")
    parser.add_argument('-u', '--uri', dest='uri', action='store_true', help="Returns the CPE name as a URI string")
    parser.add_argument('-f', '--fs', dest='fs', action='store_true', help="Returns the CPE name as an FS string")
    parser.add_argument('-m', '--mode', dest='mode', metavar='MODE', default='2.2',  help="Either 2.2 or 2.3; which CPE version to validate; defaults to 2.2")
    parser.add_argument('--disable-redhat', dest='disable_redhat', action='store_true', help="Disable Red Hat-specific checks")
    args = parser.parse_args()

    rhmode = True
    if args.disable_redhat:
        rhmode = False

    if args.describe and not args.mycpe:
        print('Must provide a CPE to describe!')
        sys.exit(1)

    if args.wfn and not args.mycpe:
        print('Must a provide a CPE to display WFN of!')
        sys.exit(1)

    if args.uri and not args.mycpe:
        print('Must a provide a CPE to display URI of!')
        sys.exit(1)

    if args.mode not in ['2.2', '2.3']:
        print('Invalid mode: %s; must be 2.2 or 2.3' % args.mode)
        sys.exit(1)

    if args.describe and args.mycpe:
        describe_cpe(args.mycpe, args.mode, rhmode)

    if (args.wfn or args.uri or args.fs) and args.mycpe:
        x = get_cpe(args.mycpe, args.mode, rhmode)
        if type(x) == type('str'):
            print('Validation failed for %s: %s' % (args.mycpe, x))
        if args.wfn:
            print('               WFN: %s' % x.cpe.as_wfn())
        if args.uri:
            print('         URI (2.2): %s' % x.cpe23.as_uri_2_3())
        if args.fs:
            print('   Formatted (2.3): %s' % x.cpe23.as_fs())

    if args.mycpe:
        sys.exit(0)

    if args.xml:
        cpes = parse_cpedictionary(args.xml)
    else:
        cpes = parse_cpedictionary()

    print('Loaded %d CPEs from cpe-dictionary.xml' % len(cpes))

    if args.validate:
        fail=0
        for cpe_string in cpes:
            cpe_name = cpes[cpe_string]

            x = get_cpe(cpe_string, args.mode, rhmode)
            if type(x) == type('str'):
                print('Validation failed for %s: %s' % (cpe_name, x))
                fail = fail + 1
                continue

        if fail > 0:
            print('%d out of %d CPEs failed to validate' % (fail, len(cpes)))
