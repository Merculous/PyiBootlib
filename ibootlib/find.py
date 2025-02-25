
import struct

from armfind.find import (find_next_BL, find_next_LDR_Literal,
                          find_next_LDR_W_with_value, find_next_LDRB,
                          find_next_MOV_W_with_value,
                          find_next_MOVS_with_value, find_next_MOVW_with_value)
from binpatch.types import Buffer
from binpatch.utils import getBufferAtIndex

iBootVersions = {
    2: range(294, 386),
    3: range(573, 818),
    4: range(872, 1073),
    5: range(1219, 1220),
    6: range(1537, 1538),
    7: range(1940, 1941),
    8: range(2261, 2262),
    9: range(2817, 2818),
    10: range(3393, 3407)
}

class iBoot:
    def __init__(self, data: Buffer, log: bool = True) -> None:
        self._data = data
        self.log = log
        self.loadAddr = self.getLoadAddr()
        self.hasKernelLoad = self.canLoadKernel()
        self.iOSVersion = self.getiOSVersion()

    def getLoadAddr(self) -> int:
        return struct.unpack('<I', getBufferAtIndex(self._data, 0x20, 4))[0] - 0x40
    
    def canLoadKernel(self) -> bool:
        loadStr = b'error loading kernelcache\n'
        offset = self._data.find(loadStr)
        found = True if offset != -1 else False
        return found
    
    def getiOSVersion(self) -> int:
        iBootVersion = int(getBufferAtIndex(self._data, 0x286, 10).translate(None, b'\x00').split(b'.')[0])
        match = 0

        for version in iBootVersions:
            if iBootVersion not in iBootVersions[version]:
                continue

            match += version
            break

        if match == 0:
            raise Exception('Failed to determine iOS version!')

        if self.log:
            print(f'Determined this image is iOS {match}')

        return match

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

    def find_uarts_stage1(self) -> int:
        if self.log:
            print('find_uarts_stage1()')

        movw = find_next_MOVW_with_value(self._data, 0, 0, 0x107)

        if movw is None:
            raise Exception('Failed to find MOVW Rx, #0x107!')

        movw, movwOffset = movw

        if self.log:
            print(f'Found MOVW Rx, #0x107 at {movwOffset:x}')

        ldr = find_next_LDRB(self._data, movwOffset, 0)

        if ldr is None:
            raise Exception('Failed to find LDRB Rx, [Rx]!')

        ldr, ldrOffset = ldr

        if self.log:
            print(f'Found LDRB Rx, [Rx] at {ldrOffset:x}')

        return ldrOffset


    def find_uarts_stage2(self) -> int:
        if self.log:
            print('find_uarts_stage2()')

        uartStr = b'debug-uarts'
        uartStrOffset = self._data.find(uartStr)

        if uartStrOffset == -1:
            raise Exception(f'Failed to find {uartStr.decode()}!')
        
        if self.log:
            print(f'Found {uartStr.decode()} at {uartStrOffset:x}')

        uartStrAddr = struct.pack('<I', self.loadAddr + uartStrOffset)

        # We need the second instruction
        ldr = find_next_LDR_Literal(self._data, 0, 1, uartStrAddr)

        if ldr is None:
            raise Exception(f'Failed to find LDR Rx, {uartStr.decode()}')

        ldr, ldrOffset = ldr

        if self.log:
            print(f'Found LDR Rx, {uartStr.decode()} at {ldrOffset:x}')

        # MOVS value is ldrOffset - 2
        movs = find_next_MOVS_with_value(self._data, ldrOffset - 2, 0, 0)

        if movs is None:
            raise Exception('Failed to find MOVS Rx, #0!')

        movs, movsOffset = movs

        if self.log:
            print(f'Found MOVS Rx, #0 at {movsOffset:x}')

        return movsOffset

    def find_verify_shsh_567(self) -> int:
        if self.log:
            print('find_verify_shsh_567()')

        movw = find_next_MOVW_with_value(self._data, 0, 0, 0x4F4D)

        if movw is None:
            raise Exception('Failed to find MOVW Rx, OM!')
        
        movw, movwOffset = movw

        if self.log:
            print(f'Found MOVW Rx, OM at {movwOffset:x}')

        bl = find_next_BL(self._data, movwOffset - 0x90, 0)

        if bl is None:
            raise Exception('Failed to find BL!')
        
        bl, blOffset = bl

        if self.log:
            print(f'Found BL at {blOffset:x}')

        return blOffset
