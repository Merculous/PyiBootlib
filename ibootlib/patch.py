
import struct

from armfind.find import find_next_CMP_with_value
from armfind.sizes import CMPBitSizes, LDR_WBitSizes
from armfind.types import LDR_W
from armfind.utils import instructionToObject, objectToInstruction
from binpatch.patch import replaceBufferAtIndex
from binpatch.types import Buffer
from binpatch.utils import getBufferAtIndex

from .find import iBoot


class iBootPatcher(iBoot):
    def __init__(self, data: Buffer, log: bool = True) -> None:
        super().__init__(data, log)

        self.patchedData = self._data[:]

    def patch_prod(self) -> None:
        prodOffset = self.find_prod()
        self.patchedData = replaceBufferAtIndex(self.patchedData, b'\x00\x20\x00\x20', prodOffset, 4)

    def patch_sepo(self) -> None:
        sepoOffset = self.find_sepo()
        self.patchedData = replaceBufferAtIndex(self.patchedData, b'\x00\x20\x00\x20', sepoOffset, 4)

    def patch_bord(self) -> None:
        bordOffset = self.find_bord()
        self.patchedData = replaceBufferAtIndex(self.patchedData, b'\x00\x20\x00\x20', bordOffset, 4)

    def patch_ecid(self) -> None:
        ecidOffset = self.find_ecid()
        self.patchedData = replaceBufferAtIndex(self.patchedData, b'\x00\x20\x00\x20', ecidOffset, 4)

    def patch_rsa(self) -> None:
        rsaOffset = self.find_rsa()
        self.patchedData = replaceBufferAtIndex(self.patchedData, b'\x00\x20\x00\x20', rsaOffset, 4)

    def patch_debug_enabled(self) -> None:
        debugOffset = self.find_debug_enabled()
        self.patchedData = replaceBufferAtIndex(self.patchedData, b'\x01\x20\x01\x20', debugOffset, 4)

    def patch_boot_args(self, newArgs: Buffer) -> None:
        bootArgsOffset = self.find_boot_args()
        bootArgsLdr = instructionToObject(getBufferAtIndex(self._data, bootArgsOffset, 4), LDR_W, LDR_WBitSizes)
        bootArgsRefOffset = (bootArgsOffset + bootArgsLdr.imm12 + 4) & ~3

        cmp = find_next_CMP_with_value(self._data, bootArgsOffset, 0, 0)

        if cmp is None:
            raise Exception('Failed to find CMP Rx, #0!')

        cmp, cmpOffset = cmp

        if self.log:
            print(f'Found CMP Rx, #0 at {cmpOffset:x}')

        newCmp = cmp
        newCmp.imm8 = 1
        newCmpBytes = objectToInstruction(newCmp, CMPBitSizes)

        self.patchedData = replaceBufferAtIndex(self.patchedData, newCmpBytes, cmpOffset, 2)

        relianceStrOffset = self.find_reliance_str()
        relianceStrAddr = struct.pack('<I', self.loadAddr + relianceStrOffset)

        newBootArgs = newArgs + b'\x00'

        if self.log:
            print(f'Replacing boot-args with new string: {newBootArgs.decode()}')

        self.patchedData = replaceBufferAtIndex(self.patchedData, newBootArgs, relianceStrOffset, len(newBootArgs))
        self.patchedData = replaceBufferAtIndex(self.patchedData, relianceStrAddr, bootArgsRefOffset, 4)


def patch_sigcheck_3_4(iBootPatchObj: iBootPatcher) -> None:
    iBootPatchObj.patch_prod()
    iBootPatchObj.patch_sepo()
    iBootPatchObj.patch_bord()
    iBootPatchObj.patch_ecid()
    iBootPatchObj.patch_rsa()


def patch_boot_args_3(iBootPatchObj: iBootPatcher, newArgs: Buffer) -> None:
    iBootPatchObj.patch_boot_args(newArgs)
