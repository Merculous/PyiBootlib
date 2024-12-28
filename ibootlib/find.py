
import struct

from armfind.find import (
    find_next_MOVW_with_value,
    find_next_MOV_W_with_value,
    find_next_LDR_Literal,
    find_next_BL,
    find_next_LDR_W_with_value
)
from binpatch.utils import getBufferAtIndex
from binpatch.types import Buffer

class iBoot:
    def __init__(self, data: Buffer, log: bool = True) -> None:
        self.data = data
        self.log = log
        self.loadAddr = self.getLoadAddr()
        self.hasKernelLoad = self.canLoadKernel()

    def getLoadAddr(self) -> int:
        return struct.unpack('<I', getBufferAtIndex(self.data, 0x20, 4))[0] - 0x40
    
    def canLoadKernel(self) -> bool:
        loadStr = b'error loading kernelcache\n'
        offset = self.data.find(loadStr)
        found = True if offset != -1 else False
        return found

    def find_prod(self) -> int:
        if self.log:
            print('find_prod()')

        ldr = find_next_LDR_Literal(self.data, 0, 0, b'PROD'[::-1])

        if ldr is None:
            raise Exception('Failed to find LDR Rx, PROD!')

        ldr, ldrOffset = ldr

        if self.log:
            print(f'Found LDR Rx, PROD at {ldrOffset:x}')

        bl = find_next_BL(self.data, ldrOffset, 0)

        if bl is None:
            raise Exception('Failed to find BL!')

        bl, blOffset = bl

        if self.log:
            print(f'Found BL at {blOffset:x}')

        return blOffset

    def find_sepo(self) -> int:
        if self.log:
            print('find_sepo()')

        ldr = find_next_LDR_Literal(self.data, 0, 0, b'SEPO'[::-1])

        if ldr is None:
            raise Exception('Failed to find LDR Rx, SEPO!')

        ldr, ldrOffset = ldr

        if self.log:
            print(f'Found LDR Rx, SEPO at {ldrOffset:x}')

        bl = find_next_BL(self.data, ldrOffset, 0)

        if bl is None:
            raise Exception('Failed to find BL!')

        bl, blOffset = bl

        if self.log:
            print(f'Found BL at {blOffset:x}')

        return blOffset

    def find_bord(self) -> int:
        if self.log:
            print('find_bord()')

        ldr = find_next_LDR_Literal(self.data, 0, 0, b'BORD'[::-1])

        if ldr is None:
            raise Exception('Failed to find LDR Rx, BORD!')

        ldr, ldrOffset = ldr

        if self.log:
            print(f'Found LDR Rx, BORD at {ldrOffset:x}')

        bl = find_next_BL(self.data, ldrOffset, 0)

        if bl is None:
            raise Exception('Failed to find BL!')

        bl, blOffset = bl

        if self.log:
            print(f'Found BL at {blOffset:x}')

        return blOffset

    def find_ecid(self) -> int:
        if self.log:
            print('find_ecid()')

        ldr = find_next_LDR_Literal(self.data, 0, 0, b'ECID'[::-1])

        if ldr is None:
            raise Exception('Failed to find LDR Rx, ECID!')

        ldr, ldrOffset = ldr

        if self.log:
            print(f'Found LDR Rx, ECID at {ldrOffset:x}')

        bl = find_next_BL(self.data, ldrOffset, 0)

        if bl is None:
            raise Exception('Failed to find BL!')

        bl, blOffset = bl

        if self.log:
            print(f'Found BL at {blOffset:x}')

        return blOffset

    def find_RSA(self) -> int:
        if self.log:
            print('find_RSA()')

        movw = find_next_MOVW_with_value(self.data, 0, 0, 0x414)

        if movw is None:
            raise Exception('Failed to find MOVW Rx, #0x414!')

        movw, movwOffset = movw

        if self.log:
            print(f'Found MOVW Rx, #0x414 at {movwOffset:x}')

        mov_w = find_next_MOV_W_with_value(self.data, movwOffset, 0, 0x3FF)

        if mov_w is None:
            raise Exception('Failed to find MOV.W Rx, #0xFFFFFFFF!')

        mov_w, mov_wOffset = mov_w

        if self.log:
            print(f'Found MOV.W Rx, #0xFFFFFFFF at {mov_wOffset:x}')

        return mov_wOffset

    def find_debug_enabled(self) -> int:
        if self.log:
            print('find_debug_enabled()')

        debugStrOffset = self.data.find(b'debug-enabled')

        if debugStrOffset == -1:
            raise Exception('Failed to find debug-enabled!')

        debugStrAddr = struct.pack('<I', self.loadAddr + debugStrOffset)
        ldr = find_next_LDR_W_with_value(self.data, 0, 0, debugStrAddr)

        if ldr is None:
            raise Exception('Failed to find LDR.W Rx, debug-enabled!')

        ldr, ldrOffset = ldr

        if self.log:
            print(f'Found LDR.W Rx, debug-enabled at {ldrOffset:x}')

        bl = find_next_BL(self.data, ldrOffset, 1)

        if bl is None:
            raise Exception('Failed to find BL!')

        bl, blOffset = bl

        if self.log:
            print(f'Found BL at {blOffset:x}')

        return blOffset
