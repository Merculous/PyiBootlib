
from argparse import ArgumentParser

from binpatch.io import readBytesFromPath, writeBytesToPath
from binpatch.types import FilesystemPath

from .patch import iBootPatcher, patch_boot_args_3, patch_sigcheck_3_4


def main() -> None:
    parser = ArgumentParser()

    parser.add_argument('-i', nargs=1, type=FilesystemPath)
    parser.add_argument('-o', nargs=1, type=FilesystemPath)

    parser.add_argument('-b', nargs=1, type=str)

    args = parser.parse_args()

    if not args.i and not args.o:
        return parser.print_help()

    inData = readBytesFromPath(args.i[0])

    patcher = iBootPatcher(inData)
    
    if patcher.iOSVersion in (3, 4):
        patch_sigcheck_3_4(patcher)
    elif patcher.iOSVersion in (5, 6, 7):
        patcher.patch_sigcheck_567()
    else:
        print('signature WIP!')

    if args.b:
        if patcher.iOSVersion == 3:
            patch_boot_args_3(patcher, args.b[0].encode())
        else:
            print('boot-args WIP!')

    writeBytesToPath(args.o[0], patcher.patchedData)


if __name__ == '__main__':
    main()
