#!/usr/bin/env python
from __future__ import print_function

import os, stat, hashlib, itertools, optparse, sys, io, subprocess
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
    _pairwise_command = None

    def _blocks(self):
        def read_blocks(f):
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

        path = self.filepath()
        with open(path, 'rb') as f:
            if self._convert_command is None:
                for b in read_blocks(f):
                    yield b
            else:
                p = subprocess.Popen((self._convert_command, "", path),
                                     shell=True, close_fds=True,
                                     stdin=f, stdout=subprocess.PIPE,
                                     bufsize=-1) # much faster
                for b in read_blocks(p.stdout):
                    try:
                        yield b
                    except GeneratorExit:
                        # If __eq__ discards generator early, complete the
                        # process anyway so it doesn't print or return errors.
                        while p.stdout.read(1 << 20): # can be any size
                            pass

                p.stdout.close()
                if p.wait():
                    raise RuntimeError(
                        "Command failed on file: '{0}'".format(path))

    def digests(self):
        yield b"F"

        if self._pairwise_command is not None:
            return

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

        if self._pairwise_command is not None:
            return not subprocess.call(
                (self._pairwise_command, "", self.filepath(), other.filepath()),
                shell=True, close_fds=True)

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
        yield b"D"

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
        yield b"L"

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



def dedup_diff(a, b, a_matches, b_matches, verbose=False):
    # This code is complex because it both tries to reduce index lookups by
    # aggregating information about negative ("new") matches as it recurses,
    # and to reduce buffering to output results as soon as possible.

    # However, all results must still be buffered as long as either subtree
    # appears to be potentially new.

    def process(a, b, parent):
        def write(tag, args):
            if parent:
                parent[0].append(tag)
                parent[1].append(args)
            else:
                print(" -+*"[tag], *(
                    i.treepath() if isinstance(i, Node) else i for i in args))

        if a == b:
            assert a is not None
            if verbose:
                write(0, (a,))
            a = b = None
            yield None, None

        else:
            # Empty nodes are not printed as either matching or new,
            # but don't prevent the entire containing directory being new
            if a:
                if a.empty():
                    if not verbose:
                        a = None
                else:
                    for match in b_matches(a):
                        write(0, (a, "->", match))
                        a = None
                        yield None, True
            if b:
                if b.empty():
                    if not verbose:
                        b = None
                else:
                    for match in a_matches(b):
                        write(0, (b, "<-", match))
                        b = None
                        yield True, None

        buffer = [[], []] # empty buffer; flushed buffer is []
        a_named = {i.filename(): i for i in a.items()} if a else {}
        b_named = {i.filename(): i for i in b.items()} if b else {}
        # From now on non-falsy a and b mean "new"
        for name in sorted(set(a_named) | set(b_named)):
            for p in process(a_named.get(name), b_named.get(name), buffer):
                # Reset new if p is falsy, keep otherwise
                if a and not p[0] or b and not p[1]:
                    a = p[0] and a
                    b = p[1] and b
                    yield a, b
                    if not parent and buffer and not a and not b:
                        for tag, args in zip(*buffer):
                            write(tag, args)
                        del buffer[:]

        if a or b:
            write(bool(a)+bool(b)*2, (a or b,))
        if buffer:
            mask = ~(bool(a)+bool(b)*2)
            for tag, args in zip(*buffer):
                if not tag or tag & mask:
                    write(tag & mask, args)

    list(process(a, b, None))


def dedup_new(sources, matches, extend, recurse=False):
    def process(node, parent_new):
        all_new = new = not list(matches(node))
        if not new and parent_new:
            parent_new = yield # set to false

        if recurse and new:
            for item in node.items():
                for all_new in process(item, all_new):
                    if parent_new:
                        parent_new = yield # propagate
                    for new_item in node.items():
                        if new_item is item:
                            break
                        print(new_item.tip().treepath()) # flush buffered items

        if all_new and not parent_new:
            print((node.tip() if recurse else node).treepath())

        extend(node, prune=new) # prune if recursed

    for source in sources:
        list(process(source, False))


def dedup(sources, matches, extend,
          delete=False, execute=None, recurse=False, verbose=False):

    def process(node):
        matched = False
        for match in matches(node):
            matched = True
            if not delete:
                print(node.treepath(), "->", match.treepath())

        if recurse and not matched:
            for item in node.items():
                process(item)

        if matched and delete:
            if verbose:
                print(node.treepath())
            if execute is None:
                node.unlink()
            else:
                if subprocess.call(
                        (execute, "", node.filepath(), match.filepath()),
                        shell=True, close_fds=True):
                    raise RuntimeError(
                        "Command failed on file: '{0}' matching '{1}'".format(
                            node.filepath(), match.filepath()))
        else:
            extend(node, prune=not matched) # prune if recursed

    for source in sources:
        process(source)


def main():
    parser = optparse.OptionParser(
        usage="%prog [-x command | -i | -n | -d] [-rfvla] source ... target",
        description="Delete every source that matches target or any item it "
                    "contains. Files are compared by content, directories by "
                    "item names and content.",
        add_help_option=False)
    parser.version = "dedup 0.4"
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
    parser.add_option("-p", dest="pairwise", metavar="command",
                      help="compare pairs of files with command, "
                           "$1 and $2 are files")

    opts, args = parser.parse_args()

    modes = bool(opts.mode_i) + bool(opts.mode_n) + bool(opts.mode_d)
    if modes + (opts.execute is not None) > 1:
        parser.error("options -x, -i, -n and -d are mutually exclusive")
    opts.mode_delete = modes == 0

    if opts.mode_i and opts.verbose:
        parser.error("-v can't be specified with -i (try -l instead)")
    if opts.mode_n and opts.verbose:
        parser.error("-v can't be specified with -n")
    if opts.mode_n and opts.list_all:
        parser.error("-l can only be specified with -i and -d")
    if opts.mode_delete and opts.list_all:
        parser.error("-l can only be specified with -i and -d (try -v instead)")
    if opts.mode_d and (opts.recurse or opts.only_files or opts.all_targets):
        parser.error("-r, -f and -a can't be specified with -d")
    if opts.convert is not None and opts.pairwise is not None:
        parser.error("-c and -p can't be specified together")
    if len(args) == 0:
        parser.error("target not specified")
    if not opts.mode_d and len(args) + bool(opts.all_targets) < 2:
        parser.error("source not specified")
    if opts.mode_d and len(args) != 2:
        parser.error("-d only works with a single source")

    File._convert_command = opts.convert
    File._pairwise_command = opts.pairwise


    # Output should be readable by users (no UnicodeEncodeError) but also useful
    # in pipelines, therefore, similarly to ls, output depends on isatty
    if str is bytes:
        pass # don't do anything for Python 2
    elif sys.stdout.isatty():
        sys.stdout = io.TextIOWrapper(sys.stdout.detach(),
                                      encoding=sys.stdout.encoding,
                                      errors="replace",
                                      line_buffering=sys.stdout.line_buffering)
    else:
        sys.stdout = io.TextIOWrapper(sys.stdout.detach(),
                                      sys.getfilesystemencoding(),
                                      errors="surrogateescape")


    def flattened(node):
        yield node
        for item in node.items():
            for file in flattened(item):
                yield file

    def make_matches(index):
        def matches(node):
            for item in index.find(node):
                yield item
                if not opts.list_all:
                    break
        return matches

    if opts.mode_d:
        a, b = map(Node, args)
        a_matches = make_matches(Index(flattened(a)))
        b_matches = make_matches(Index(flattened(b)))
        dedup_diff(a, b, a_matches, b_matches, verbose=opts.verbose)

    else:
        index = Index()
        if opts.all_targets:
            def extend(node, prune=False):
                if opts.recurse and not prune:
                    index.extend(flattened(node))
                else:
                    index.extend((node,))
        else:
            def extend(node, prune=False):
                pass
            target = Node(args.pop())
            index.extend(flattened(target)) # target always recursive

        matches = make_matches(index)

        sources = (Node(arg, arg) for arg in args)
        recurse = opts.recurse
        if opts.only_files:
            if recurse:
                sources = itertools.chain.from_iterable(
                    flattened(i) for i in sources)
            sources = filterfalse(lambda x: isinstance(x, Dir), sources)
            recurse = False

        if opts.mode_n:
            dedup_new(sources, matches, extend, recurse=recurse)
        else:
            assert opts.mode_delete or opts.mode_i
            dedup(sources, matches, extend,
                  delete=opts.mode_delete, execute=opts.execute,
                  recurse=recurse, verbose=opts.verbose)


if __name__ == "__main__":
    try:
        main()
    except (EnvironmentError, RuntimeError) as e:
        print("{0}: error: {1}".format(os.path.basename(sys.argv[0]), e),
              file=sys.stderr)
        sys.exit(1)
