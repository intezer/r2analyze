# This file is part of r2analyze.
#
# Copyright (c) 2021, Intezer Labs
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 
# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import r2pipe
import re

# List of bad chars that can't be used in a radare flag name.
# (· is used in GoASM)
bad_chars = r'[*\s]|\\|/|,|\.|-|&|·|\*|\{|\}|\[|\]|\(|\)|#|\+|<|>|!|\?|\$|;|%|@|`|\"|\''

class Radare:
    def __init__(self):
        self._r2 = r2pipe.open()

        if self._r2.pipe[0] == -1 or self._r2.pipe[1] == -1:
            raise Exception("Please run from within radare2.")

        # Get base address
        self._base = int(self._r2.cmdj('ij')['bin']['baddr'])

        # Get hashes of the file.
        hashes = self._r2.cmdj('itj')
        self._sha256 = hashes['sha256']

    def get_file_hash(self) -> str:
        return self._sha256

    def get_base_address(self) -> int:
        return self._base

    def get_function_data(self) -> list:
        # Get functions.
        funcs = self._r2.cmdj('aflj')

        # Create function map.
        req_data = []

        for f in funcs:
            start = int(f['offset']) - self._base
            end = int(f['offset']+f['size']) - self._base

            req_data.append({
                'start_address': start,
                'end_address': end
            })
        return req_data

    def apply_genes(self, report):
        func_report = report['functions']

        # Create a new flag space for the genes.
        self._r2.cmd('fs gene')

        for addr in func_report:
            typ = self.clean_flag_name("_".join(func_report[addr]['software_type']))
            fam = self.clean_flag_name("_".join(func_report[addr]['code_reuse']))
            fixed_address = int(addr)+self._base

            self._r2.cmd('f gene_{}_{}_{} 1 {}'.format(
                typ, fam, fixed_address, fixed_address))

        # Select all flag spaces
        self._r2.cmd('fs *')


    def clean_flag_name(self, n: str) -> str:
        '''
        Helper function that removes bad characters from the flag name.
        '''

        # Because radare2 can only use ASCII for flag names, we encode the
        # string as an ASCII string and replace non-ascii characters with "backslashreplace".
        # This will result in for example, "\\u50b3\\u9001\\u4f7f\\u7528\\u8005\\u8a18\\u9304".
        # The backslashes is replaced later for "_" since backslash is not allowed in the name
        # resulting in a final string of: "_u50b3_u9001_u4f7f_u7528_u8005_u8a18_u9304".
        name = n.encode('ascii', errors='backslashreplace').decode()

        # Do some specific replacements.
        # This replaces C++ with Cpp and crypto++ with cryptopp.
        name = re.sub(r'\+\+', 'pp', name)

        # Replace bad chars.
        return re.sub(bad_chars, '_', name)
