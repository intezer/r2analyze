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

from r2analyze import __version__

# Standard Library
import os
import time

# 3rd party.
import requests

# Variables

VERSION = __version__
BASE_URL = os.environ.get('INTEZER_BASE_URL', 'https://analyze.intezer.com')
API_URL = '{}/api'

FUNCTIONS_LIMIT = 10000
FUNCTIONS_FALLBACK_LIMIT = 1000

GET_ACCESS_TOKEN_URL = '{}/v2-0/get-access-token'
REPORT_URL = '{}/v1-2/files/{}/community-ida-plugin-report'


class Client:
    def __init__(self, api_key, user_agent, base_url=BASE_URL, api_url=None, user_agent_version=VERSION):
        self._api_key = api_key
        self._user_agent = user_agent
        self._user_agent_version = user_agent_version
        self._session = None
        if api_url is None:
            self._api_url = API_URL.format(base_url)
        else:
            self._api_url = api_url

    @property
    def session(self):
        if not self._session:
            session = requests.session()
            adapter = requests.adapters.HTTPAdapter(max_retries=3)
            session.mount("https://", adapter)
            session.mount("http://", adapter)
            session.headers = {
                'User-Agent': '{}/{}'.format(self._user_agent, self._user_agent_version)}
            self._session = session
        return self._session

    def init_access_token(self, url):
        if 'Authorization' not in self.session.headers:
            response = requests.post(url, json={'api_key': self._api_key})
            response.raise_for_status()

            token = 'Bearer {}'.format(response.json()['result'])
            self.session.headers['Authorization'] = token

    def _post(self, url_path, **kwargs):
        self.init_access_token(GET_ACCESS_TOKEN_URL.format(self._api_url))
        retries = 5
        retries_counter = 0
        while retries_counter <= retries:
            response = self.session.post(url_path, **kwargs)
            if 299 >= response.status_code >= 200 or 499 >= response.status_code >= 400:
                return response
            else:
                time.sleep(2)
                retries_counter += 1

        return None

    def _get(self, url_path, **kwargs):
        self.init_access_token(GET_ACCESS_TOKEN_URL.format(self._api_url))
        return self.session.get(url_path, **kwargs)

    def create_plugin_report(self, sha256, functions_data):
        response = self._post(REPORT_URL.format(self._api_url, sha256),
                              json={'functions_data': functions_data[:FUNCTIONS_LIMIT]})

        if response is None:
            raise Exception('Failed creating plugin report')

        if response.status_code == 404:
            raise Exception(
                "Please analyze the file first on Intezer Analyze. The sha256 is: {}".format(sha256))

        if response.status_code == 409:
            raise Exception('not_supported_file')

        if response.status_code != 201:
            raise Exception(response.reason)

        result_url = response.json()['result_url']

        return result_url

    def get_plugin_report(self, result_url):
        retries = 5
        retries_counter = 0
        while retries_counter <= retries:
            response = self._get(self._api_url + result_url)
            if response.status_code == 202:
                time.sleep(2)
                retries_counter += 1
            else:
                response.raise_for_status()
                return response.json()['result']

