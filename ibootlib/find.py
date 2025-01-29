
import struct

from armfind.find import (find_next_BL, find_next_LDR_Literal,
                          find_next_LDR_W_with_value,
                          find_next_MOV_W_with_value,
                          find_next_MOVW_with_value)
from binpatch.types import Buffer
from binpatch.utils import getBufferAtIndex


class iBoot:
    def __init__(self, data: Buffer, log: bool = True) -> None:
        self._data = data
        self.log = log
        self.loadAddr = self.getLoadAddr()
        self.hasKernelLoad = self.canLoadKernel()

    def getLoadAddr(self) -> int:
        return struct.unpack('<I', getBufferAtIndex(self._data, 0x20, 4))[0] - 0x40
    
    def canLoadKernel(self) -> bool:
        loadStr = b'error loading kernelcache\n'
        offset = self._data.find(loadStr)
        found = True if offset != -1 else False
        return found

    def find_prod(self) -> int:
        if self.log:
            print('find_prod()')

        ldr = find_next_LDR_Literal(self._data, 0, 0, b'PROD'[::-1])

        if ldr is None:
            raise Exception('Failed to find LDR Rx, PROD!')

        ldr, ldrOffset = ldr

        if self.log:
            print(f'Found LDR Rx, PROD at {ldrOffset:x}')

        bl = find_next_BL(self._data, ldrOffset, 0)

        if bl is None:
            raise Exception('Failed to find BL!')

        bl, blOffset = bl

        if self.log:
            print(f'Found BL at {blOffset:x}')

        return blOffset

    def find_sepo(self) -> int:
        if self.log:
            print('find_sepo()')

        ldr = find_next_LDR_Literal(self._data, 0, 0, b'SEPO'[::-1])

        if ldr is None:
            raise Exception('Failed to find LDR Rx, SEPO!')

        ldr, ldrOffset = ldr

        if self.log:
            print(f'Found LDR Rx, SEPO at {ldrOffset:x}')

        bl = find_next_BL(self._data, ldrOffset, 0)

        if bl is None:
            raise Exception('Failed to find BL!')

        bl, blOffset = bl

        if self.log:
            print(f'Found BL at {blOffset:x}')

        return blOffset

    def find_bord(self) -> int:
        if self.log:
            print('find_bord()')

        ldr = find_next_LDR_Literal(self._data, 0, 0, b'BORD'[::-1])

        if ldr is None:
            raise Exception('Failed to find LDR Rx, BORD!')

        ldr, ldrOffset = ldr

        if self.log:
            print(f'Found LDR Rx, BORD at {ldrOffset:x}')

        bl = find_next_BL(self._data, ldrOffset, 0)

        if bl is None:
            raise Exception('Failed to find BL!')

        bl, blOffset = bl

        if self.log:
            print(f'Found BL at {blOffset:x}')

        return blOffset

    def find_ecid(self) -> int:
        if self.log:
            print('find_ecid()')

        ldr = find_next_LDR_Literal(self._data, 0, 0, b'ECID'[::-1])

        if ldr is None:
            raise Exception('Failed to find LDR Rx, ECID!')

        ldr, ldrOffset = ldr

        if self.log:
            print(f'Found LDR Rx, ECID at {ldrOffset:x}')

        bl = find_next_BL(self._data, ldrOffset, 0)

        if bl is None:
            raise Exception('Failed to find BL!')

        bl, blOffset = bl

        if self.log:
            print(f'Found BL at {blOffset:x}')

        return blOffset

    def find_rsa(self) -> int:
        if self.log:
            print('find_rsa()')

        movw = find_next_MOVW_with_value(self._data, 0, 0, 0x414)

        if movw is None:
            raise Exception('Failed to find MOVW Rx, #0x414!')

        movw, movwOffset = movw

        if self.log:
            print(f'Found MOVW Rx, #0x414 at {movwOffset:x}')

        mov_w = find_next_MOV_W_with_value(self._data, movwOffset, 0, 0x3FF)

        if mov_w is None:
            raise Exception('Failed to find MOV.W Rx, #0xFFFFFFFF!')

        mov_w, mov_wOffset = mov_w

        if self.log:
            print(f'Found MOV.W Rx, #0xFFFFFFFF at {mov_wOffset:x}')

        return mov_wOffset

    def find_debug_enabled(self) -> int:
        if self.log:
            print('find_debug_enabled()')

        debugStrOffset = self._data.find(b'debug-enabled')

        if debugStrOffset == -1:
            raise Exception('Failed to find debug-enabled!')

        debugStrAddr = struct.pack('<I', self.loadAddr + debugStrOffset)
        ldr = find_next_LDR_W_with_value(self._data, 0, 0, debugStrAddr)

        if ldr is None:
            raise Exception('Failed to find LDR.W Rx, debug-enabled!')

        ldr, ldrOffset = ldr

        if self.log:
            print(f'Found LDR.W Rx, debug-enabled at {ldrOffset:x}')

        bl = find_next_BL(self._data, ldrOffset, 1)

        if bl is None:
            raise Exception('Failed to find BL!')

        bl, blOffset = bl

        if self.log:
            print(f'Found BL at {blOffset:x}')

        return blOffset

    def find_boot_args(self) -> int:
        if self.log:
            print(f'find_boot_args()')

        bootArgsStr = b'rd=md0 nand-enable-reformat=1 -progress'
        bootArgsStrOffset = self._data.find(bootArgsStr)

        if bootArgsStrOffset == -1:
            raise Exception('Failed to find boot args string!')
        
        bootArgsStrAddr = struct.pack('<I', self.loadAddr + bootArgsStrOffset)
        ldr = find_next_LDR_W_with_value(self._data, 0, 0, bootArgsStrAddr)

        if ldr is None:
            raise Exception(f'Failed to find LDR.W Rx, {bootArgsStr.decode()}')
        
        ldr, ldrOffset = ldr

        if self.log:
            print(f'Found LDR.W Rx, {bootArgsStr.decode()} at {ldrOffset:x}')

        return ldrOffset

    def find_reliance_str(self) -> int:
        if self.log:
            print('find_reliance_str()')

        relianceStr = b'Reliance on this certificate'
        relianceStrOffset = self._data.find(relianceStr)

        if relianceStrOffset == -1:
            raise Exception(f'Failed to find {relianceStr.decode()}')
        
        if self.log:
            print(f'Found {relianceStr.decode()} at {relianceStrOffset:x}')

        return relianceStrOffset
