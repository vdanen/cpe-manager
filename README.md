CPE Usage
=========

Author: Vincent Danen <vdanen@redhat.com>

This tool was initially written internally for the Red Hat Product Security
team for the purposes of managing and validating CPEs within our products.
As such it is a little Red Hat-centric, but should be usable for any other
non-Red Hat project.

It requires the wonderful CPE python module from https://pypi.python.org/pypi/cpe/.

To describe the usage of CPE within Red Hat and for Red Hat products.

Red Hat currently uses CPE 2.2, so this tool is more focused on that
although it will work with 2.3 as well.


CPE Specification
-----------------

**Part** can be one of: a (Application), h (Hardware), or o (Operating System)

**Vendor** is the supplier name and should be an abridged version of the primary
DNS hostname (e.g. 'redhat.com' becomes 'redhat' or 'oxford.ac.uk' becomes
'oxford')

**Product** is a short and recognizable name of the product, where no such short
recognition exists it should be the full name of the product with spaces
underscored (e.g. 'red_hat_enterprise_linux' would be used if 'rhel' were not
recognized as the same)

**Version** is the version of the project and should be represented in the same
way as the product (e.g. 'Foo 1-1' would use '1-1' or 'Bar 1.1-p3' would be
'1.1-p3'.  There is no way in CPE to note major and minor versions so you can
opt to use this field for the major (e.g. '1') and the Update field for the
minor

**Update** is used for update or service pack information, and may be referred to
as a point or minor version.  In the case of a version "0" you can use the
vendor term for initial release (e.g. you could use '0' to refer to RHEL 7.0 or
'ga' in the case of RHEL 7 GA).  If there is no commonly used term for the
initial release, then '-' should be used for that CPE (e.g. "Foo 1" would be
"foo:1:-:" unless it was referred to as "Foo 1.0" in which case "foo:1:0:" may
be more appropriate)

**Edition** is used for the the edition of this platform, e.g. "workstation" or
"server" or "professional", etc.  NOTE: This is available for legacy CPE 2.2
compatability but is considered deprecated in 2.3

**Language** is used for the language used for this product (e.g. "zh-tw" for
traditional Chinese)

**Software Edition** is used to characterise how the product is tailored for a
particular maket or class of end users

**Target Software** is used to indicate the software environment within which the
product operates

**Target Hardware** is used to indicate the architecture on whioch the product
operates (e.g. "x86" or "x86_64")

**Other** is used to capture any other general descriptive or identifying
infomration which is vendor- or product-specific



Verifying CPE Names
-------------------

CPEs should be validated before they are used in public and perhaps
included in the global CPE dictionary.  It can be difficult to change CPE
names once they are out in the wild.

The cpe-manager.py script can be used to validate the CPE:

```
$ ./cpe-manager.py -d -c cpe:/a:redhat:openstack-installer:6::el7
```

