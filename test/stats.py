#!/usr/bin/env python
from __future__ import print_function

import sys, imp

_stats = [0, 0, 0, 0] # blocks: calls, bytes; find: calls, matches

def _wrap_blocks(blocks):
    def wrapped(self):
        _stats[0] += 1
        for block in blocks(self):
            _stats[1] += len(block)
            yield block
    return wrapped

def _wrap_find(find):
    def wrapped(self, node):
        first = True
        _stats[2] += 1
        for match in find(self, node):
            _stats[3] += 1
            yield match
            # may not return after first yield
    return wrapped

sys.argv.pop(0)

if sys.argv[0] == "-a":
    sys.argv.pop(0)
    _stats_stdout = open(sys.argv.pop(0), "a")
else:
    _stats_stdout = None # don't use sys.stdout, which is changed by dedup

dedup = imp.load_source("dedup", sys.argv[0])
dedup.File._blocks = _wrap_blocks(dedup.File._blocks)
dedup.Index.find = _wrap_find(dedup.Index.find)
try:
    dedup.main() # could throw or exit by OptionParser.error
finally:
    print(*_stats, file=_stats_stdout)
