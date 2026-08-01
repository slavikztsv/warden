"""The demo distribution: everything that is not part of the product itself.

Kept as a package (not a bare directory) so demo/scenario/catalog.py can be
imported by production code (broker/__main__.py) and by demo code
(cli/explain.py) alike, with tests/support/catalog.py re-exporting the same
symbols rather than defining its own copy.
"""
