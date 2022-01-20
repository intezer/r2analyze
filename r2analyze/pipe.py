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

import requests
import os

from r2analyze.analyze import Client
from r2analyze.r2 import Radare

FUNCTIONS_LIMIT = 10000
INTEZER_API_KEY = os.environ.get('INTEZER_API_KEY')

def run():
    r2 = Radare()

    sha = r2.get_file_hash()
    print("Analyzing {}".format(sha))

    req_data = r2.get_function_data()
    print("Functions found {}.".format(len(req_data)))

    c = Client(INTEZER_API_KEY, 'r2analyze')

    is_partial_result = len(req_data) >= FUNCTIONS_LIMIT

    try:
        result_url = c.create_plugin_report(sha, req_data)
    except requests.ConnectionError:
        # We got connection error when sending a large payload of functions.
        # The fallback is to send a limited amount of functions
        result_url = c.create_plugin_report(sha, req_data[:FUNCTIONS_LIMIT])
        is_partial_result = True

    report = c.get_plugin_report(result_url)

    if is_partial_result:
        print("The result is partial due to the large amount of functions.")

    r2.apply_genes(report)


def main():
    try:
        run()
    except Exception as err:
        print(err)


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        print(err)
