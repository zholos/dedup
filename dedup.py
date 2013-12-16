#!/usr/bin/env python
from __future__ import print_function

import os, stat, hashlib, itertools, optparse, sys, codecs, subprocess
try:
    from itertools import zip_longest
except ImportError:
    from itertools import izip_longest as zip_longest
try:
    from os import fsencode
except ImportError:
    def fsencode(name):
        assert isinstance(name, bytes)
        return name


class Node:
    def __init__(self, filename, treename = "", parent = None):
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

    def unlink(self):
        os.unlink(self.filepath())

    def empty(self):
        return False


class File(Node):
    def scanned(self, stat_result):
        self._size = stat_result.st_size

    _convert_command = None

    def _blocks(self):
        path = self.filepath()
        with open(path, 'rb') as f:
            if self._convert_command is not None:
                p = subprocess.Popen((self._convert_command, "", path),
                                     shell = True, close_fds = True,
                                     stdin = f, stdout = subprocess.PIPE,
                                     bufsize = -1) # much faster
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
        # Sorting is required at least by __eq__
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

    def flattened(self):
        yield self
        for item in self._items:
            for file in item.flattened():
                yield file

    def unlink(self):
        for item in self._items:
            item.unlink()
        os.rmdir(self.filepath())

    def empty(self):
        return not self._items


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
    def __init__(self, files):
        # Items are kept in order and matches are returned in order
        self._index = list((file, file.digests()) for file in files), {}

    def find(self, node):
        index = self._index
        for digest in node.digests():
            if index[0]:
                for item in index[0]:
                    index[1].setdefault(next(item[1]), ([], {}))[0].append(item)
                del index[0][:]
            try:
                index = index[1][digest]
            except KeyError:
                return
 
        assert not index[1]
        for file, _ in index[0]:
            if file == node:
                yield file


def main():
    parser = optparse.OptionParser(
        usage="%prog [-x command | -i | -n | -d] [-rfvl] source ... target",
        description="Deletes source files or directories that have a copy "
                    "somewhere in the tree rooted at target. Files are "
                    "compared by content (not metadata), directories are "
                    "compared by item names and content.",
        add_help_option=False)
    parser.version = "dedup 0.2"
    parser.add_option("-h", "--help", action="help",
                      help=optparse.SUPPRESS_HELP)
    parser.add_option("--version", action="version",
                      help=optparse.SUPPRESS_HELP)
    parser.add_option("-r", action="store_true", dest="recurse",
                      help="If source is a directory, recursively deletes "
                           "individual files and subdirectories that have "
                           "copies. Without this option a source directory can "
                           "only be deleted as a whole.")
    parser.add_option("-f", action="store_true", dest="only_files",
                      help="Do not delete directories, only individual files.")
    parser.add_option("-v", action="store_true", dest="verbose",
                      help="Be verbose, showing files and directories as they "
                           "are deleted.")
    parser.add_option("-x", dest="execute", metavar="command",
                      help="Execute a command for each match instead of "
                           "deleting the source file or directory. Source name "
                           "is $1, matching target name is $2. E.g. "
                           "'touch -r \"$2\" \"$1\"'.")
    parser.add_option("-i", action="store_true", dest="mode_i",
                      help="Instead of deleting anything, list source files "
                           "and the target files they match.")
    parser.add_option("-n", action="store_true", dest="mode_n",
                      help="Instead of deleting anything, list source files "
                           "that do not match any target files.")
    parser.add_option("-d", action="store_true", dest="mode_d",
                      help="Instead of deleting anything, compare a single "
                           "source tree to the target tree and give a "
                           "diff-like output.")
    parser.add_option("-l", action="store_true", dest="list_all",
                      help="List all matches, not just the first one.")
    parser.add_option("-c", dest="convert", metavar="command",
                      help="Pipe file contents through a command before "
                           "comparing. File can also be accessed by name with "
                           "$1. E.g. 'zcat -f'.")

    opts, args = parser.parse_args()

    modes = bool(opts.mode_i) + bool(opts.mode_n) + bool(opts.mode_d)
    if modes + (opts.execute is not None) > 1:
        parser.error("options -x, -i, -n and -d are mutually exclusive")
    opts.mode_none = modes == 0

    if not opts.mode_none and opts.verbose:
        parser.error("-v can't be specified with -i, -n and -d "
                     "(try -l instead)")
    if opts.mode_none and opts.list_all:
        parser.error("-l can only be specified with -i, -n or -d "
                     "(try -v instead)")
    if opts.mode_d and (opts.recurse or opts.only_files):
        parser.error("-r and -f can't be specified with -d")
    if len(args) == 0:
        parser.error("target not specified")
    if opts.mode_d and len(args) != 2:
        parser.error("-d only works with a single source argument")


    if opts.list_all:
        def matches_slice(matches):
            return matches
    else:
        def matches_slice(matches):
            return itertools.islice(matches, 1)

    if opts.recurse:
        def single_item_dir(node):
            return isinstance(node, Dir) and len(list(node.items())) == 1
    else:
        def single_item_dir(node):
            return False

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


    if opts.mode_d:
        def process(a, b):
            if a == b:
                return

            a_new = None
            if a and not a.empty():
                matches = list(matches_slice(b_find(a)))
                for match in matches:
                    print(" ", a.treepath(), "->", match.treepath())
                if not matches and a._all_new:
                    a_new = a.treepath()
                if matches or a._all_new:
                    a = None

            b_new = None
            if b and not b.empty():
                matches = list(matches_slice(a_find(b)))
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
        a_find = Index(a.flattened()).find
        b_find = Index(b.flattened()).find

        mark_all_new(a, b_find, True)
        mark_all_new(b, a_find, True)

        process(a, b)

    else:
        def process(node):
            if not (opts.only_files and isinstance(node, Dir)):
                if opts.mode_n:
                    for match in find(node):
                        return
                    else:
                        if opts.list_all or \
                                node._all_new and not single_item_dir(node):
                            print(node.treepath())
                            if not opts.list_all:
                                return

                elif opts.mode_i:
                    matches = list(matches_slice(find(node)))
                    for match in matches:
                        print(node.treepath(), "->", match.treepath())
                    if matches:
                        return

                elif opts.mode_none:
                    for match in find(node):
                        if opts.verbose:
                            print(node.treepath())
                        if opts.execute is None:
                            node.unlink()
                        else:
                            if subprocess.call(
                                    (opts.execute, "",
                                        node.filepath(), match.filepath()),
                                    shell = True, close_fds = True):
                                raise RuntimeError(
                                    "Command failed on file: '{0}' "
                                    "matching '{1}'".format(node.filepath(),
                                                            match.filepath()))
                        return

            if opts.recurse:
                for item in node.items():
                    process(item)

        tree = Node(args.pop())
        find = Index(tree.flattened()).find
        sources = (Node(arg, arg) for arg in args)

        for node in sources:
            if opts.mode_n:
                mark_all_new(node, find, opts.recurse)
            process(node)


if __name__ == "__main__":
    main()
