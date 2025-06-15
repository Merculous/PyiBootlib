
import struct
from io import BytesIO

from armfind.find import find_next_CMP_with_value, find_next_IT
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

        bootArgsOffset = self.find_boot_args()

        it = find_next_IT(self._data, bootArgsOffset, 0)

        if it is None:
            cmp = find_next_CMP_with_value(self._data, bootArgsOffset - 0x20, 0, 0)

            if cmp is None:
                raise Exception('Failed to find CMP Rx, #0!')

            cmp, cmpOffset = cmp
        else:
            it, itOffset = it

            if self.log:
                print(f'Found IT at {itOffset:x}')

            cmp = find_next_CMP_with_value(self._data, itOffset - 2, 0, 0)

            if cmp is None:
                raise Exception('Failed to find CMP Rx, #0!')
            
            cmp, cmpOffset = cmp

        if self.log:
            print(f'Found CMP Rx, #0 at {cmpOffset:x}')

        bootArgsLdr = instructionToObject(getBufferAtIndex(self._data, bootArgsOffset, 4), LDR_W, LDR_WBitSizes, isLDR_W)

        if not bootArgsLdr:
            bootArgsLdr = instructionToObject(getBufferAtIndex(self._data, bootArgsOffset, 2), LDRLiteral, LDRLiteralBitSizes, isLDRLiteral)

            if not bootArgsLdr:
                raise Exception('Failed to get LDR type!')

            bootArgsRefOffset = (bootArgsOffset + (bootArgsLdr.imm8 << 2) + 4) & ~3

        else:
            bootArgsRefOffset = (bootArgsOffset + bootArgsLdr.imm12 + 4) & ~3

        newCmp = cmp
        newCmp.imm8 = 1
        newCmpBytes = objectToInstruction(newCmp, CMPBitSizes)

        self.patchedData = replaceBufferAtIndex(self.patchedData, newCmpBytes, cmpOffset, 2)

        relianceStrOffset = self.find_reliance_str()
        relianceStrAddr = BytesIO(struct.pack('<I', self.loadAddr + relianceStrOffset))

        newBootArgs = BytesIO(newArgs.getvalue() + b'\x00')

        if self.log:
            print(f'Replacing boot-args with new string: {newBootArgs.getvalue().decode()}')

        self.patchedData = replaceBufferAtIndex(self.patchedData, newBootArgs, relianceStrOffset, len(newBootArgs.getbuffer()))
        self.patchedData = replaceBufferAtIndex(self.patchedData, relianceStrAddr, bootArgsRefOffset, 4)

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


def patch_boot_args_3(iBootPatchObj: iBootPatcher, newArgs: BytesIO) -> None:
    iBootPatchObj.patch_boot_args(newArgs)
