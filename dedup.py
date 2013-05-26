#!/usr/bin/env python
_version = "dedup 0.1"

import os, stat, hashlib, itertools, optparse, sys


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
        yield "" # last in sequence must be a string

    def items(self):
        return iter(())

    def recurse(self):
        yield self

    def unlink(self):
        os.unlink(self.filepath())

    def empty(self):
        return False


def _file_blocks(path):
    with open(path, 'rb') as f:
        block_size = 1 << 20
        while True:
            b = f.read(block_size)
            if len(b) != block_size:
                # Shouldn't have short reads until EOF,
                # otherwise blocks won't match up in file stream comparison.
                if len(f.read(1)):
                    raise IOError("Not a regular file: '{0}'".format(path))
                yield b
                break
            yield b

class File(Node):
    def scanned(self, stat_result):
        self._size = stat_result.st_size

    def digests(self):
        yield self.__class__
        yield self._size

        while True:
            try:
                yield self._full_digest
                break
            except AttributeError:
                h = hashlib.md5()
                for b in _file_blocks(self.filepath()):
                    h.update(b)
                self._full_digest = h.digest()

    def __eq__(self, other):
        if not isinstance(other, File):
            return False
        return all(b1 == b2 for b1, b2 in
                   itertools.izip_longest(_file_blocks(self.filepath()),
                                          _file_blocks(other.filepath())))

    def empty(self):
        return self._size == 0


class Dir(Node):
    def scanned(self, stat_result):
        # Do not defer scanning as dedups might change contents
        self._items = [Node(name, name, self) for name in
                       sorted(os.listdir(self.filepath()))]

    def digests(self):
        yield self.__class__

        while True:
            try:
                yield self._name_digest
                break
            except AttributeError:
                self._name_digest = \
                    hashlib.md5("\0".join(self._item_filenames())).digest()

        while True:
            try:
                yield self._full_digest
                break
            except AttributeError:
                h = hashlib.md5()
                for item in self._items:
                    for digest in item.digests():
                        pass
                    h.update(item.filename() + "\0" + digest)
                self._full_digest = h.digest()

    def __eq__(self, other):
        if not isinstance(other, Dir):
            return False
        return self._items == other._items and \
               self._item_filenames() == other._item_filenames()

    def items(self):
        return iter(self._items)

    def _item_filenames(self):
        return [item.filename() for item in self._items]

    def recurse(self):
        yield self
        for item in self._items:
            for file in item.recurse():
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
                self._full_digest = hashlib.md5(self._link).digest()

    def __eq__(self, other):
        if not isinstance(other, Link):
            return False
        return self._link == other._link


class Unknown(Node):
    pass



class Index:
    def __init__(self, tree):
        self._index = \
            list((file, file.digests()) for file in tree.recurse()), {}

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
        usage="%prog [-i | -n | -d] [-rvl] source ... target",
        description="Deletes source files or directories that have a copy "
                    "somewhere in the tree rooted at target. Files are "
                    "compared by content (not metadata), directories are "
                    "compared by item names and content.",
        add_help_option=False)
    parser.version = _version
    parser.add_option("-h", "--help", action="help",
                      help=optparse.SUPPRESS_HELP)
    parser.add_option("--version", action="version",
                      help=optparse.SUPPRESS_HELP)
    parser.add_option("-r", action="store_true", dest="recurse",
                      help="If source is a directory, recursively deletes "
                           "individual items that have copies. Without this "
                           "option source files and directories can only be "
                           "deleted entirely.")
    parser.add_option("-v", action="store_true", dest="verbose",
                      help="Be verbose, showing items as they are deleted.")
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

    opts, args = parser.parse_args()

    modes = bool(opts.mode_i) + bool(opts.mode_n) + bool(opts.mode_d)
    if modes > 1:
        parser.error("options -i, -n and -d are mutually exclusive")
    opts.mode_none = modes == 0

    if not opts.mode_none and opts.verbose:
        parser.error("-v can't be specified with -i, -n and -d "
                     "(try -l instead)")
    if opts.mode_none and opts.list_all:
        parser.error("-l can only be specified with -i, -n or -d "
                     "(try -v instead)")
    if opts.mode_d and opts.recurse:
        parser.error("-r can't be specified with -d")
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

    def mark_all_new(node, tree_index, recurse):
        node._all_new = True
        for match in tree_index.find(node):
            node._all_new = False
            break
        if recurse:
            for item in node.items():
                mark_all_new(item, tree_index, recurse)
                if not item._all_new:
                    node._all_new = False


    if opts.mode_d:
        def process(a, b):
            if a == b:
                return

            a_new = None
            if a and not a.empty():
                matches = list(matches_slice(b_index.find(a)))
                for match in matches:
                    print " ", a.treepath(), "->", match.treepath()
                if not matches and a._all_new:
                    a_new = a.treepath()
                if matches or a._all_new:
                    a = None

            b_new = None
            if b and not b.empty():
                matches = list(matches_slice(a_index.find(b)))
                for match in matches:
                    print " ", b.treepath(), "<-", match.treepath()
                if not matches and b._all_new:
                    b_new = b.treepath()
                if matches or b._all_new:
                    b = None

            if a_new is not None and a_new == b_new:
                print "*", a_new
            else:
                if a_new is not None:
                    print "-", a_new
                if b_new is not None:
                    print "+", b_new

            a = dict((item.filename(), item) for item in a.items()) if a else {}
            b = dict((item.filename(), item) for item in b.items()) if b else {}

            for name in sorted(set(a.keys()) | set(b.keys())):
                process(a.get(name, None), b.get(name, None))

        a, b = Node(args[0]), Node(args[1])
        a_index, b_index = Index(a), Index(b)

        mark_all_new(a, b_index, True)
        mark_all_new(b, a_index, True)

        process(a, b)

    else:
        def process(node):
            if opts.mode_n:
                for match in tree_index.find(node):
                    return
                else:
                    if opts.list_all or \
                            node._all_new and not single_item_dir(node):
                        print node.treepath()
                        if not opts.list_all:
                            return

            elif opts.mode_i:
                matches = list(matches_slice(tree_index.find(node)))
                for match in matches:
                    print node.treepath(), "->", match.treepath()
                if matches:
                    return

            elif opts.mode_none:
                for match in tree_index.find(node):
                    if opts.verbose:
                        print node.treepath()
                    node.unlink()
                    return

            if opts.recurse:
                for item in node.items():
                    process(item)

        tree = Node(args.pop())
        tree_index = Index(tree)

        for arg in args:
            node = Node(arg, arg)
            if opts.mode_n:
                mark_all_new(node, tree_index, opts.recurse)
            process(node)


if __name__ == "__main__":
    main()
