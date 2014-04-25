#!/usr/bin/env python
from __future__ import print_function

import os, stat, hashlib, itertools, optparse, sys, codecs, subprocess
from collections import deque
try:
    from itertools import zip_longest, filterfalse
except ImportError:
    from itertools import izip_longest as zip_longest, \
                          ifilterfalse as filterfalse
try:
    from os import fsencode
except ImportError:
    def fsencode(name):
        assert isinstance(name, bytes)
        return name


class Node:
    def __init__(self, filename, treename="", parent=None):
        self._filename = filename
        self._treename = treename
        self._parent = parent
        self._scan()

    def filename(self):
        return self._filename

    def filepath(self):
        if self._parent:
            return os.path.join(self._parent.filepath(), self._filename)
        else:
            return self._filename

    def treepath(self):
        if self._parent:
            path = self._parent.treepath()
            if path:
                path += os.sep
            return path + self._treename
        else:
            return self._treename

    def _scan(self):
        stat_result = os.lstat(self.filepath())
        mode = stat_result.st_mode
        if stat.S_ISREG(mode):
            cls = File
        elif stat.S_ISDIR(mode):
            cls = Dir
        elif stat.S_ISLNK(mode):
            cls = Link
        else:
            cls = Unknown
        self.__class__ = cls
        self.scanned(stat_result)

    def scanned(self, stat_result):
        pass

    def digests(self):
        yield b"" # last in sequence must be a string for Dir._full_digest

    def items(self):
        return iter(())

    def flattened(self):
        yield self
        for item in self.items():
            for file in item.flattened():
                yield file

    def unlink(self):
        os.unlink(self.filepath())

    def empty(self):
        return False

    def tip(self):
        return self


class File(Node):
    def scanned(self, stat_result):
        self._size = stat_result.st_size

    _convert_command = None

    def _blocks(self):
        path = self.filepath()
        with open(path, 'rb') as f:
            if self._convert_command is not None:
                p = subprocess.Popen((self._convert_command, "", path),
                                     shell=True, close_fds=True,
                                     stdin=f, stdout=subprocess.PIPE,
                                     bufsize=-1) # much faster
                f = p.stdout

            # Ensure fixed-size blocks so they match up when comparing
            block_size = 1 << 20

            b = b""
            while True:
                assert len(b) < block_size
                r = f.read(block_size - len(b))
                assert isinstance(r, bytes)
                b += r
                if not r: # EOF
                    if b:
                        yield b
                    break
                if len(b) == block_size:
                    yield b
                    b = b""

            if self._convert_command is not None:
                f.close()
                if p.wait():
                    raise RuntimeError(
                        "Command failed on file: '{0}'".format(path))

    def digests(self):
        yield self.__class__

        if self._convert_command is None:
            yield self._size

        while True:
            try:
                yield self._full_digest
                break
            except AttributeError:
                h = hashlib.md5()
                for b in self._blocks():
                    h.update(b)
                self._full_digest = h.digest()

    def __eq__(self, other):
        if not isinstance(other, File):
            return False
        return all(b1 == b2 for b1, b2 in
                   zip_longest(self._blocks(), other._blocks()))

    def empty(self):
        return self._size == 0


class Dir(Node):
    def scanned(self, stat_result):
        # Do not defer scanning as dedups might change contents
        # Sorting is required at least by __eq__ and by -a
        self._items = [Node(name, name, self) for name in
                       sorted(os.listdir(self.filepath()))]

    def digests(self):
        yield self.__class__

        while True:
            try:
                yield self._name_digest
                break
            except AttributeError:
                self._name_digest = hashlib.md5(
                    b"\0".join(map(fsencode, self._item_filenames()))).digest()

        while True:
            try:
                yield self._full_digest
                break
            except AttributeError:
                h = hashlib.md5()
                for item in self._items:
                    for digest in item.digests():
                        pass
                    assert isinstance(digest, bytes)
                    h.update(fsencode(item.filename()) + b"\0" + digest)
                self._full_digest = h.digest()

    def __eq__(self, other):
        if not isinstance(other, Dir):
            return False
        return self._items == other._items and \
               self._item_filenames() == other._item_filenames()

    def _item_filenames(self):
        return [item.filename() for item in self._items]

    def items(self):
        return iter(self._items)

    def unlink(self):
        for item in self._items:
            item.unlink()
        os.rmdir(self.filepath())

    def empty(self):
        return not self._items

    def tip(self):
        if len(self._items) == 1:
            return self._items[0].tip()
        else:
            return self


class Link(Node):
    def scanned(self, stat_result):
        self._link = os.readlink(self.filepath())

    def digests(self):
        yield self.__class__

        while True:
            try:
                yield self._full_digest
                break
            except AttributeError:
                self._full_digest = hashlib.md5(fsencode(self._link)).digest()

    def __eq__(self, other):
        if not isinstance(other, Link):
            return False
        return self._link == other._link


class Unknown(Node):
    pass



class Index:
    """An index accelerates lookup of files by their digests.

    It is a tree, where each node contains a list of unchecked files with their
    digest generators. When the next digest is retrieved, the file is pushed
    into a child node corresponding to that digest.

    Matching files are returned in the order they were inserted."""

    class _LazyDeque:
        def __init__(self):
            self._iters = deque()
        def extend(self, files):
            self._iters.append(iter(files))
        def popleft(self):
            while True:
                for file in self._iters[0]:
                    return file, file.digests()
                self._iters.popleft()
        # NOTE: no __bool__ method

    def __init__(self, files=()):
        self._index = self._LazyDeque(), {}
        self.extend(files)

    def extend(self, files):
        self._index[0].extend(files)

    def find(self, node):
        deferred = []

        # first optimistically check only previously generated digests
        index = self._index
        digests = node.digests()
        for digest in digests:
            deferred.append((index, digest))
            index = index[1].get(digest)
            if not index:
                break
        else:
            assert not index[1]
            for file, _ in index[0]:
                if node == file:
                    yield file
            # if we're looking for a single match, we may have already found it,
            # and will not resume this routine, saving some work

        # now check all unchecked files at every index level for more matches
        for index, digest in reversed(deferred):
            digests = itertools.chain((digest,), digests)
            while True:
                try: # don't use bool(index[0]) due to _LazyDeque implementation
                    item = index[0].popleft() # insert somewhere before yield
                except IndexError:
                    break
                child = index
                digests, digests_copy = itertools.tee(digests)
                for check in digests_copy:
                    digest = next(item[1])
                    child = child[1].setdefault(digest, (deque(), {}))
                    if digest != check:
                        child[0].append(item)
                        break
                else:
                    assert not child[1]
                    assert not list(item[1]) # also frees memory
                    child[0].append(item)
                    if node == item[0]:
                        yield item[0]



def main():
    parser = optparse.OptionParser(
        usage="%prog [-x command | -i | -n | -d] [-rfvla] source ... target",
        description="Delete every source that matches target or any item it "
                    "contains. Files are compared by content, directories by "
                    "item names and content.",
        add_help_option=False)
    parser.version = "dedup 0.3.1"
    parser.add_option("-h", "--help", action="help",
                      help=optparse.SUPPRESS_HELP)
    parser.add_option("--version", action="version",
                      help=optparse.SUPPRESS_HELP)
    parser.add_option("-a", action="store_true", dest="all_targets",
                      help="compare sources to each other, not to target")
    parser.add_option("-r", action="store_true", dest="recurse",
                      help="recursively delete individual items in source")
    parser.add_option("-f", action="store_true", dest="only_files",
                      help="do not delete directories, only files")
    parser.add_option("-v", action="store_true", dest="verbose",
                      help="be verbose, showing what is deleted")
    parser.add_option("-x", dest="execute", metavar="command",
                      help="execute command instead of deleting, "
                           "$1 is source, $2 is target")
    parser.add_option("-i", action="store_true", dest="mode_i",
                      help="instead of deleting, list matches")
    parser.add_option("-n", action="store_true", dest="mode_n",
                      help="instead of deleting, list non-matches")
    parser.add_option("-d", action="store_true", dest="mode_d",
                      help="instead of deleting, "
                           "compare two trees in a diff-like output")
    parser.add_option("-l", action="store_true", dest="list_all",
                      help="list all matching targets")
    parser.add_option("-c", dest="convert", metavar="command",
                      help="pipe file contents through command before "
                           "comparing, $1 is file")

    opts, args = parser.parse_args()

    modes = bool(opts.mode_i) + bool(opts.mode_n) + bool(opts.mode_d)
    if modes + (opts.execute is not None) > 1:
        parser.error("options -x, -i, -n and -d are mutually exclusive")
    opts.mode_delete = modes == 0

    if (opts.mode_i or opts.mode_d) and opts.verbose:
        parser.error("-v can't be specified with -i and -d (try -l instead)")
    if opts.mode_n and opts.verbose:
        parser.error("-v can't be specified with -n")
    if (opts.mode_n or opts.mode_delete) and opts.list_all:
        parser.error("-l can only be specified with -i and -d")
    if opts.mode_d and (opts.recurse or opts.only_files or opts.all_targets):
        parser.error("-r, -f and -a can't be specified with -d")
    if len(args) == 0:
        parser.error("target not specified")
    if not opts.mode_d and len(args) + bool(opts.all_targets) < 2:
        parser.error("source not specified")
    if opts.mode_d and len(args) != 2:
        parser.error("-d only works with a single source")


    def mark_all_new(node, find, recurse):
        node._all_new = True
        for match in find(node):
            node._all_new = False
            break
        if recurse:
            for item in node.items():
                mark_all_new(item, find, recurse)
                if not item._all_new:
                    node._all_new = False

    File._convert_command = opts.convert


    # Output should be readable by users (no UnicodeEncodeError) but also useful
    # in pipelines, therefore, similarly to ls, output depends on isatty
    if str is bytes:
        pass # don't do anything for Python 2
    elif sys.stdout.isatty():
        sys.stdout = codecs.getwriter(sys.stdout.encoding)(
            sys.stdout.detach(), "replace")
    else:
        sys.stdout = codecs.getwriter(sys.getfilesystemencoding())(
            sys.stdout.detach(), "surrogateescape")


    def make_matches(index, diff_exception=False):
        def matches(node):
            for item in index.find(node):
                if diff_exception and \
                        node.empty() and item.treepath() != node.treepath():
                    continue
                yield item
                if not opts.list_all:
                    break
        return matches

    if opts.mode_d:
        def process(a, b):
            if a == b:
                return

            a_new = None
            if a and not a.empty():
                matches = list(b_matches(a))
                for match in matches:
                    print(" ", a.treepath(), "->", match.treepath())
                if not matches and a._all_new:
                    a_new = a.treepath()
                if matches or a._all_new:
                    a = None

            b_new = None
            if b and not b.empty():
                matches = list(a_matches(b))
                for match in matches:
                    print(" ", b.treepath(), "<-", match.treepath())
                if not matches and b._all_new:
                    b_new = b.treepath()
                if matches or b._all_new:
                    b = None

            if a_new == b_new is not None:
                print("*", a_new)
            else:
                if a_new is not None:
                    print("-", a_new)
                if b_new is not None:
                    print("+", b_new)

            a = dict((item.filename(), item) for item in a.items()) if a else {}
            b = dict((item.filename(), item) for item in b.items()) if b else {}

            for name in sorted(set(a.keys()) | set(b.keys())):
                process(a.get(name, None), b.get(name, None))

        a, b = map(Node, args)
        a_matches = make_matches(Index(a.flattened()), diff_exception=True)
        b_matches = make_matches(Index(b.flattened()), diff_exception=True)

        mark_all_new(a, b_matches, True)
        mark_all_new(b, a_matches, True)

        process(a, b)

    else:
        def process(node):
            if opts.mode_n:
                for match in matches(node):
                    return
                else:
                    if node._all_new:
                        print((node.tip() if opts.recurse else
                               node).treepath())
                        return

            elif opts.mode_i:
                matches_ = list(matches(node))
                for match in matches_:
                    print(node.treepath(), "->", match.treepath())
                if matches_:
                    return

            elif opts.mode_delete:
                for match in matches(node):
                    if opts.verbose:
                        print(node.treepath())
                    if opts.execute is None:
                        node.unlink()
                    else:
                        if subprocess.call(
                                (opts.execute, "",
                                    node.filepath(), match.filepath()),
                                shell=True, close_fds=True):
                            raise RuntimeError(
                                "Command failed on file: '{0}' "
                                "matching '{1}'".format(node.filepath(),
                                                        match.filepath()))
                    return

            if opts.recurse:
                for item in node.items():
                    process(item)

        if opts.all_targets:
            sources = [Node(arg, arg) for arg in args]
            if opts.recurse:
                files = itertools.chain(*(tree.flattened() for tree in sources))
            else:
                files = sources
            index = Index(files)

            def matches(node):
                for match in index.find(node):
                    if match is node:
                        return
                    yield match
                    if not opts.list_all:
                        break

        else:
            tree = Node(args.pop())
            matches = make_matches(Index(tree.flattened()))
            sources = (Node(arg, arg) for arg in args)

        if opts.only_files:
            if opts.recurse:
                sources = itertools.chain.from_iterable(
                    i.flattened() for i in sources)
            sources = filterfalse(lambda x: isinstance(x, Dir), sources)
            opts.recurse = False

        for node in sources:
            if opts.mode_n:
                mark_all_new(node, matches, opts.recurse)
            process(node)


if __name__ == "__main__":
    try:
        main()
    except (EnvironmentError, RuntimeError) as e:
        print("{0}: error: {1}".format(os.path.basename(sys.argv[0]), e),
              file=sys.stderr)
        sys.exit(1)
