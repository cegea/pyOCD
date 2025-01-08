# pyOCD debugger
# Copyright (c) 2006-2013 Arm Limited
# Copyright (c) 2021 Chris Reed
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ...coresight.coresight_target import CoreSightTarget
from ...core.memory_map import (FlashRegion, RamRegion, MemoryMap)
from ...debug.svd.loader import SVDFile

#DBGMCU clock 
RCC_APB2ENR_CR = 0x40021018
RCC_APB2ENR_DBGMCU = 0x00400000

DBGMCU_CR = 0x40015804
DBGMCU_APB1_CR = 0x40015808
DBGMCU_APB2_CR = 0x4001580C

#0000 0000 0000 0000 0000 0000 0000 0100
#BGMCU_CR_VAL = 0x00000000

#0000 0010 0010 0000 0001 1101 0011 0011
DBGMCU_APB1_VAL = 0x02201D33

#0000 0000 0000 0111 0000 1000 0000 0000
DBGMCU_APB2_VAL = 0x00070800


FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xe7fdbe00,
    0x4a6ab672, 0x608a496a, 0x608a4a6a, 0xbf00e000, 0x0392690a, 0xd1fa0f92, 0x444a4a67, 0x48676050,
    0x04008c00, 0x60900980, 0x60d00840, 0x68004864, 0x48640503, 0x18180d1b, 0x280ad01f, 0x2810d01d,
    0x2001d01b, 0x6a086010, 0x0fc00280, 0x6a086110, 0xd40803c0, 0x4a5c485d, 0x10526002, 0x22066002,
    0x4a5b6042, 0x6a086082, 0xd4040300, 0x4959485a, 0x217f6041, 0x20006001, 0x20004770, 0x484ee7e2,
    0x68404448, 0x484a6801, 0xd0041c49, 0x22016801, 0x43910412, 0x69416001, 0x07d22201, 0x61414311,
    0x8f4ff3bf, 0x47702000, 0x47702001, 0x4a4b4840, 0x13c16102, 0x69416141, 0x041b2301, 0x61414319,
    0x8f4ff3bf, 0xbf00e000, 0x03896901, 0xd1fa0f89, 0x42116901, 0x6102d002, 0x47702001, 0x47702000,
    0x4b35b530, 0x444b2401, 0x04e4681a, 0xd10c2a01, 0x29016919, 0x6899d002, 0xd10642a1, 0x685968dd,
    0x4285194d, 0x2101d801, 0x2100e000, 0xd0012a01, 0xe006689a, 0x2a01691a, 0x689ad002, 0xd10042a2,
    0x4b2e68da, 0x40101e52, 0x0ac04a21, 0x00c06113, 0x1c800349, 0x61504308, 0x21016950, 0x43080409,
    0xf3bf6150, 0xe0008f4f, 0x6910bf00, 0x0f800380, 0x6910d1fa, 0xd0014018, 0x20016113, 0xb530bd30,
    0x4b131dc9, 0x4d1d08c9, 0x611d00c9, 0x615c2401, 0x6814e014, 0x68546004, 0xf3bf6044, 0xe0008f4f,
    0x691cbf00, 0x0fa403a4, 0x691cd1fa, 0xd002422c, 0x2001611d, 0x3008bd30, 0x32083908, 0xd1e82900,
    0x08406958, 0x61580040, 0xbd302000, 0x45670123, 0x40022000, 0xcdef89ab, 0x00000004, 0x1fff75c0,
    0x40015800, 0xfffffbaa, 0x0000aaaa, 0x40003000, 0x00000fff, 0x000001ff, 0x40002c00, 0x0000c3fa,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000005,
    'pc_unInit': 0x20000083,
    'pc_program_page': 0x20000163,
    'pc_erase_sector': 0x200000e5,
    'pc_eraseAll': 0x200000b1,

    'static_base' : 0x20000000 + 0x00000004 + 0x000001e0,
    'begin_stack' : 0x20001a00,
    'end_stack' : 0x20000a00,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x400,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        0x20000200,
        0x20000600
    ],
    'min_program_length' : 0x400,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x1e0,
    'rw_start': 0x1e4,
    'rw_size': 0x18,
    'zi_start': 0x1fc,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x8000000,
    'flash_size': 0x20000,
    'sector_sizes': (
        (0x0, 0x800),
    )
}


class STM32G0C1(CoreSightTarget):

    VENDOR = "STMicroelectronics"

    PART_NUMBER = "STM32G0C1RCTX"

    MEMORY_MAP = MemoryMap(
        FlashRegion(    start=0x08000000,  length=0x80000,      blocksize=0x800, is_boot_memory=True,
            algo=FLASH_ALGO),
        RamRegion(      start=0x20000000,  length=0x24000)
        )

    def __init__(self, session):
        super(STM32G0C1, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("STM32F0xx.svd")

    def post_connect_hook(self):
        enclock = self.read_memory(RCC_APB2ENR_CR)
        enclock |= RCC_APB2ENR_DBGMCU
        self.write_memory(RCC_APB2ENR_CR, enclock)
        self.write_memory(DBGMCU_APB1_CR, DBGMCU_APB1_VAL)
        self.write_memory(DBGMCU_APB2_CR, DBGMCU_APB2_VAL)
