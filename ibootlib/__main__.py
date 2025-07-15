
from argparse import ArgumentParser
from pathlib import Path

from binpatch.io import readBytesFromPath, writeBytesToPath

from .patch import iBootPatcher


def main() -> None:
    parser = ArgumentParser()

    parser.add_argument('-i', type=Path)
    parser.add_argument('-o', type=Path)

    parser.add_argument('-b', type=str)
    parser.add_argument('-d', type=str)
    parser.add_argument('-u', action='store_true')

    args = parser.parse_args()

    if not args.i and not args.o:
        return parser.print_help()

    inData = readBytesFromPath(args.i[0])

    patcher = iBootPatcher(inData)

    if patcher.iOSVersion in (3, 4):
        patcher.patch_sigcheck_3_4()
    elif patcher.iOSVersion in (5, 6, 7):
        patcher.patch_sigcheck_567()
    else:
        print('signature WIP!')

    if args.b:
        patcher.patch_boot_args(args.b.encode())

    if args.d:
        patcher.patch_debug_enabled()

    if args.u:
        patcher.patch_uarts()

    writeBytesToPath(args.o[0], patcher.patchedData)


if __name__ == '__main__':
    main()
