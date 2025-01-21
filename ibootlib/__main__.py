
from argparse import ArgumentParser

from binpatch.io import readBytesFromPath, writeBytesToPath
from binpatch.types import FilesystemPath

from .patch import iBootPatcher, patch_sigcheck_3_4


def main() -> None:
    parser = ArgumentParser()

    parser.add_argument('-i', nargs=1, type=FilesystemPath)
    parser.add_argument('-o', nargs=1, type=FilesystemPath)

    args = parser.parse_args()

    if not args.i and not args.o:
        return parser.print_help()

    inData = readBytesFromPath(args.i[0])

    patcher = iBootPatcher(inData)
    patch_sigcheck_3_4(patcher)

    writeBytesToPath(args.o[0], patcher.patchedData)


if __name__ == '__main__':
    main()
