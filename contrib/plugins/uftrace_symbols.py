#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Create symbol and mapping files for uftrace
#
# Copyright 2025 Linaro Ltd
# Author: Pierrick Bouvier <pierrick.bouvier@linaro.org>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import argparse
import elftools
import os

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

def elf_func_symbols(elf):
    symbol_tables = [(idx, s) for idx, s in enumerate(elf.iter_sections())
                  if isinstance(s, SymbolTableSection)]
    symbols = []
    for _, section in symbol_tables:
        for _, symbol in enumerate(section.iter_symbols()):
            if symbol_size(symbol) == 0:
                continue
            type = symbol['st_info']['type']
            if type == 'STT_FUNC' or type == 'STT_NOTYPE':
                symbols += [symbol]
    symbols.sort(key = lambda x: symbol_addr(x))
    return symbols

def symbol_size(symbol):
    return symbol['st_size']

def symbol_addr(symbol):
    addr = symbol['st_value']
    # clamp addr to 48 bits, like uftrace entries
    return addr & 0xffffffffffff

def symbol_name(symbol):
    return symbol.name

def generate_symbol_file(path, map_offset):
    file = open(path, 'rb')
    elf = ELFFile(file)

    sym_file_path = f'./uftrace.data/{os.path.basename(path)}.sym'
    sym_file = open(sym_file_path, 'w')

    symbols = elf_func_symbols(elf)

    # print hexadecimal addresses on 48 bits
    addrx = "0>12x"
    for s in symbols:
        addr = symbol_addr(s)
        addr = f'{addr:{addrx}}'
        size = f'{symbol_size(s):{addrx}}'
        print(addr, size, 'T', symbol_name(s), file=sym_file)

    last_sym = symbols[-1]
    map_start = map_offset
    map_end = symbol_addr(last_sym) + symbol_size(last_sym) + map_offset
    map_start = map_start
    map_end = map_end
    full_path = os.path.realpath(path)
    mapping = f'{map_start:{addrx}}-{map_end:{addrx}} r--p 00000000 00:00 0 {full_path}'

    print(f'{sym_file_path} ({len(symbols)} symbols)')
    file.close()
    sym_file.close()
    return mapping

def parse_parameter(p):
    s = p.split(":")
    path = s[0]
    if len(s) == 1:
        return path, 0
    if len(s) > 2:
        raise ValueError('only one offset can be set')
    offset = s[1]
    if not offset.startswith('0x'):
        err = f'offset "{offset}" is not an hexadecimal constant. '
        err += 'It should starts with "0x".'
        raise ValueError(err)
    offset = int(offset, 16)
    return path, offset

def is_user_mode(map_file_path):
    if os.path.exists(map_file_path):
        with open(map_file_path, 'r') as map_file:
            if not map_file.readline().startswith('# map stack on'):
                return True
    return False

def main():
    parser = argparse.ArgumentParser(description=
                                     'generate symbol files for uftrace')
    parser.add_argument('elf_file', nargs='+',
                        help='path to an ELF file. '
                        'Use /path/to/file:0xdeadbeef to add a mapping offset.')
    args = parser.parse_args()

    if not os.path.exists('./uftrace.data'):
        os.mkdir('./uftrace.data')

    mappings  = []
    mappings += ['# map stack on highest address possible, to prevent uftrace']
    mappings += ['# from considering any kernel address']
    mappings += ['ffffffffffff-ffffffffffff rw-p 00000000 00:00 0 [stack]']
    for file in args.elf_file:
        path, offset = parse_parameter(file)
        mappings += [generate_symbol_file(path, offset)]

    map_file_path = './uftrace.data/sid-0.map'

    if is_user_mode(map_file_path):
        print(f'do not overwrite {map_file_path} generated from qemu-user')
        return

    with open(map_file_path, 'w') as map_file:
        print('\n'.join(mappings), file=map_file)
    print(f'{map_file_path}')
    print('\n'.join(mappings))

if __name__ == '__main__':
    main()
