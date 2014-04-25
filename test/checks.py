#!/usr/bin/env python
from __future__ import print_function

import sys, imp, collections, itertools

# verify that same node isn't added to index multiple times
def _wrap_extend(extend):
    def wrapped(self, files):
        seen = self._checks_seen = getattr(self, "_checks_seen", {})
        files, check = itertools.tee(files)
        for node in check:
            assert id(node) not in seen
            seen[id(node)] = node
        extend(self, files)
    return wrapped

sys.argv.pop(0)

dedup = imp.load_source("dedup", sys.argv[0])
dedup.Index.extend = _wrap_extend(dedup.Index.extend)
dedup.main()
