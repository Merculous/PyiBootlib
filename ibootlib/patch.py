
import struct
from io import BytesIO

from armfind.find import (find_next_CMP_with_value, find_next_IT,
                          find_next_LDR_Literal)
from armfind.sizes import CMPBitSizes, LDR_WBitSizes, LDRLiteralBitSizes
from armfind.types import LDR_W, LDRLiteral
from armfind.utils import instructionToObject, objectToInstruction
from armfind.validators import isLDR_W, isLDRLiteral
from binpatch.patch import replaceBufferAtIndex
from binpatch.utils import getBufferAtIndex

from .find import iBoot


class iBootPatcher(iBoot):
    def __init__(self, data: BytesIO, log: bool = True) -> None:
        super().__init__(data, log)

        self.patchedData = self._data

    def patch_prod(self) -> None:
        prodOffset = self.find_prod()
        self.patchedData = replaceBufferAtIndex(self.patchedData, BytesIO(b'\x00\x20\x00\x20'), prodOffset, 4)

    def patch_sepo(self) -> None:
        sepoOffset = self.find_sepo()
        self.patchedData = replaceBufferAtIndex(self.patchedData, BytesIO(b'\x00\x20\x00\x20'), sepoOffset, 4)

    def patch_bord(self) -> None:
        bordOffset = self.find_bord()
        self.patchedData = replaceBufferAtIndex(self.patchedData, BytesIO(b'\x00\x20\x00\x20'), bordOffset, 4)

    def patch_ecid(self) -> None:
        ecidOffset = self.find_ecid()
        self.patchedData = replaceBufferAtIndex(self.patchedData, BytesIO(b'\x00\x20\x00\x20'), ecidOffset, 4)

    def patch_rsa(self) -> None:
        rsaOffset = self.find_rsa()
        self.patchedData = replaceBufferAtIndex(self.patchedData, BytesIO(b'\x00\x20\x00\x20'), rsaOffset, 4)

    def patch_debug_enabled(self) -> None:
        if not self.hasKernelLoad:
            return

        debugOffset = self.find_debug_enabled()
        self.patchedData = replaceBufferAtIndex(self.patchedData, BytesIO(b'\x01\x20\x01\x20'), debugOffset, 4)

    def patch_boot_args(self, newArgs: BytesIO) -> None:
        if not self.hasKernelLoad:
            return

        relianceStrOffset = self.find_reliance_str()
        relianceStrAddr = BytesIO(struct.pack('<I', self.loadAddr + relianceStrOffset))

        newBootArgs = BytesIO(newArgs.getvalue() + b'\x00')

        if self.log:
            print(f'Replacing boot-args with new string: {newBootArgs.getvalue().decode()}')

        self.patchedData = replaceBufferAtIndex(self.patchedData, newBootArgs, relianceStrOffset, len(newBootArgs.getbuffer()))

        bootArgsOffset = self.find_boot_args()

        it = find_next_IT(self._data, bootArgsOffset, 0)
        cmp = None

        if it:
            it, itOffset = it

            # Make sure IT isn't super far away
            itRange = range(bootArgsOffset, bootArgsOffset + 8, 2)

            if itOffset in itRange:
                if self.log:
                    print(f'Found IT at {itOffset:x}')
            else:
                it, itOffset = None, None

        if self.iOSVersion <= 4:
            if it:
                cmp = find_next_CMP_with_value(self._data, itOffset - 2, 0, 0)
            else:
                cmp = find_next_CMP_with_value(self._data, bootArgsOffset - 0x10, 0, 0)
        else:
            cmp = find_next_CMP_with_value(self._data, bootArgsOffset, 0, 0)

        if cmp is None:
            raise Exception('Failed to find CMP Rx, #0!')

        cmp, cmpOffset = cmp

        if self.log:
            print(f'Found CMP Rx, #0 at {cmpOffset:x}')

        bootArgsLDR = instructionToObject(getBufferAtIndex(self._data, bootArgsOffset, 2), LDRLiteral, LDRLiteralBitSizes, isLDRLiteral)

        if bootArgsLDR is None:
            bootArgsLDR = instructionToObject(getBufferAtIndex(self._data, bootArgsOffset, 4), LDR_W, LDR_WBitSizes, isLDR_W)

            if bootArgsLDR is None:
                raise Exception('Failed to convert boot-args offset to object!')
            
            bootArgsRefOffset = (bootArgsOffset + bootArgsLDR.imm12 + 4) & ~3

        else:
            bootArgsRefOffset = (bootArgsOffset + (bootArgsLDR.imm8 << 2) + 4) & ~3

        self.patchedData = replaceBufferAtIndex(self.patchedData, relianceStrAddr, bootArgsRefOffset, 4)

        if self.iOSVersion <= 4:
            newCMP = cmp
            newCMP.imm8 = 1
            newCMPData = objectToInstruction(newCMP, CMPBitSizes)
            self.patchedData = replaceBufferAtIndex(self.patchedData, newCMPData, cmpOffset, 2)
            return

        nullLDROffset = itOffset - 2
        nullLDR = instructionToObject(getBufferAtIndex(self._data, nullLDROffset, 2), LDRLiteral, LDRLiteralBitSizes, isLDRLiteral)

        if nullLDR is None:
            raise Exception('Failed to get null LDR!')

        newNullLDR = nullLDR
        newNullLDR.imm8 -= 1
        newNullLDRData = objectToInstruction(newNullLDR, LDRLiteralBitSizes)
        self.patchedData = replaceBufferAtIndex(self.patchedData, newNullLDRData, nullLDROffset, 2)

    def patch_uarts_stage1(self) -> None:
        uartOffset = self.find_uarts_stage1()
        self.patchedData = replaceBufferAtIndex(self.patchedData, BytesIO(b'\x00\x20'), uartOffset, 2)

    def patch_uarts_stage2(self) -> None:
        uartOffset = self.find_uarts_stage2()
        self.patchedData = replaceBufferAtIndex(self.patchedData, BytesIO(b'\x03\x21'), uartOffset, 2)

    def patch_uarts(self) -> None:
        if not self.hasKernelLoad:
            self.patch_uarts_stage1()
        else:
            self.patch_uarts_stage2()

    def patch_sigcheck_567(self) -> None:
        sigOffset = self.find_verify_shsh_567()
        self.patchedData = replaceBufferAtIndex(self.patchedData, BytesIO(b'\x00\x20\x18\x60'), sigOffset, 4)


def patch_sigcheck_3_4(iBootPatchObj: iBootPatcher) -> None:
    iBootPatchObj.patch_prod()
    iBootPatchObj.patch_sepo()
    iBootPatchObj.patch_bord()
    iBootPatchObj.patch_ecid()
    iBootPatchObj.patch_rsa()


def patch_boot_args(iBootPatchObj: iBootPatcher, newArgs: BytesIO) -> None:
    iBootPatchObj.patch_boot_args(newArgs)
