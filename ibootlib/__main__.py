
from argparse import ArgumentParser

from binpatch.io import readBytesFromPath, writeBytesToPath
from binpatch.types import FilesystemPath

from .patch import iBootPatcher


def main() -> None:
    parser = ArgumentParser()

    parser.add_argument('-i', nargs=1, type=FilesystemPath)
    parser.add_argument('-o', nargs=1, type=FilesystemPath)

    args = parser.parse_args()

    if not args.i and not args.o:
        parser.print_help()

    inData = readBytesFromPath(args.i[0])

    i = iBootPatcher(inData)
    i.patch_prod()
    i.patch_sepo()
    i.patch_bord()
    i.patch_ecid()
    i.patch_rsa()

    writeBytesToPath(args.o[0], i.data)


if __name__ == '__main__':
    main()
