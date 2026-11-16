# Source provenance

This repository is a fork of
[unidiag/tvcas3-server](https://github.com/unidiag/tvcas3-server), based on upstream
commit `876f597aeaa67847e1f0971cccbb13e0b2573ed9`. The original commits remain
ancestors of the Python publication; this is not a new, unrelated Git history.

The Python implementation was developed against TVCAS3.2 PHP. The installed
release and the readable upstream source identify the same version. Static
comparison of `cas/bin/functions.php`, `ecmg.php`, `emmg.php` and `cron1min.php`
found equivalent executable tokens after normalizing release obfuscation
(identifier renaming, inlined constants, comments and whitespace). This is not a
claim that every PHP deployment/configuration file is byte-identical.

The exported Python source came from `third_party/tvcas-python` in the headend
source tree at commit `525d6cca6a23db65213ad6929ca664059de74a11`. Standalone
adjustments are listed in [CHANGELOG.md](../CHANGELOG.md). The PHP installation,
private SQLite databases, legacy SQL/JSON exports and operational credentials
are not source inputs to the published package.

Synthetic reference tests executed the original ECM, EMM and CONFIG algorithms
under PHP 7.2. The resulting bytes matched Python. The original card firmware was
not available for review; firmware internals are not inferred from those checks.

## License and attribution

The original source identifies:

> Copyright (C) 2018–2020, Homer Simpson / TVCAS.COM

The Python derivative is distributed under **GPL-3.0-or-later**, preserving the
original [COPYING](../COPYING). Python port and standalone packaging: smdbg and
contributors, 2026. No exclusive authorship of the original TVCAS algorithms is
claimed. Flask, Waitress, cryptography and test/build dependencies are separate
packages with their own licenses.

## Legacy files

The current branch does not ship or execute PHP, `o.php`, `SQLyogTunnel.php` or the
upstream SQL dump. They remain visible in the inherited PHP history.

In particular, the upstream `o.php` packaging helper has a code path which
transmits a generated ECM key to an external HTTP endpoint. It was not included
in the installed release used for compatibility checks and is not used by the
Python port. Do not use that historical helper to package a private installation.
