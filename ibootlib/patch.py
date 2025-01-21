
from binpatch.patch import replaceBufferAtIndex
from binpatch.types import Buffer

from .find import iBoot


class iBootPatcher(iBoot):
    def __init__(self, data: Buffer, log: bool = True) -> None:
        super().__init__(data, log)

        self.patchedData = self.data[:]

    def patch_prod(self) -> None:
        prodOffset = self.find_prod()
        self.patchedData = replaceBufferAtIndex(self.data, b'\x00\x20\x00\x20', prodOffset, 4)

    def patch_sepo(self) -> None:
        sepoOffset = self.find_sepo()
        self.patchedData = replaceBufferAtIndex(self.data, b'\x00\x20\x00\x20', sepoOffset, 4)

    def patch_bord(self) -> None:
        bordOffset = self.find_bord()
        self.patchedData = replaceBufferAtIndex(self.data, b'\x00\x20\x00\x20', bordOffset, 4)

    def patch_ecid(self) -> None:
        ecidOffset = self.find_ecid()
        self.patchedData = replaceBufferAtIndex(self.data, b'\x00\x20\x00\x20', ecidOffset, 4)

    def patch_rsa(self) -> None:
        rsaOffset = self.find_rsa()
        self.patchedData = replaceBufferAtIndex(self.data, b'\x00\x20\x00\x20', rsaOffset, 4)

    def patch_debug_enabled(self) -> None:
        debugOffset = self.find_debug_enabled()
        self.patchedData = replaceBufferAtIndex(self.data, b'\x01\x20\x01\x20', debugOffset, 4)


def patch_sigcheck_3_4(iBootPatchObj: iBootPatcher) -> None:
    iBootPatchObj.patch_prod()
    iBootPatchObj.patch_sepo()
    iBootPatchObj.patch_bord()
    iBootPatchObj.patch_ecid()
    iBootPatchObj.patch_rsa()
