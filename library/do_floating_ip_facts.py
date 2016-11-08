#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2015, Patrick F. Marques <patrickfmarques@gmail.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
DOCUMENTATION = '''
---
module: do_floating_ip_facts
short_description: DigitalOcean Floating IPs facts
description:
     - Fetch DigitalOcean Floating IPs facts.
version_added: "2.3"
author: "Patrick Marques (@pmarques)"
options:
  oauth_token:
    description:
     - DigitalOcean OAuth token.
    required: true

notes:
  - Version 2 of DigitalOcean API is used.
requirements:
  - "python >= 2.6"
'''


EXAMPLES = '''
- name: "Create a Floating IP in regigin lon1"
  do_floating_ip_facts:
    register: result
'''


RETURN = '''
# Digital Ocean API info https://developers.digitalocean.com/documentation/v2/#floating-ips
data:
    description: a DigitalOcean Floating IP resource
    returned: success and no resource constraint
    type: dict
    sample: {
      "floating_ips": [
        {
          "ip": "45.55.96.47",
          "droplet": null,
          "region": {
            "name": "New York 3",
            "slug": "nyc3",
            "sizes": [
              "512mb",
              "1gb",
              "2gb",
              "4gb",
              "8gb",
              "16gb",
              "32gb",
              "48gb",
              "64gb"
            ],
            "features": [
              "private_networking",
              "backups",
              "ipv6",
              "metadata"
            ],
            "available": true
          },
          "locked": false
        }
      ],
      "links": {
      },
      "meta": {
        "total": 1
      }
    }
'''

import json
import os

from ansible.module_utils.basic import env_fallback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url
from ansible.module_utils.pycompat24 import get_exception


class RestException(Exception):
    pass


class Response(object):

    def __init__(self, resp, info):
        self.body = None
        if resp:
            self.body = resp.read()
        self.info = info

    @property
    def json(self):
        if self.body:
            return json.loads(self.body)
        elif "body" in self.info:
            return json.loads(self.info["body"])
        else:
            return None

    @property
    def status_code(self):
        return self.info["status"]


class Rest(object):

    def __init__(self, module, headers):
        self.module = module
        self.headers = headers
        self.baseurl = 'https://api.digitalocean.com/v2'

    def _url_builder(self, path):
        if path[0] == '/':
            path = path[1:]
        return '%s/%s' % (self.baseurl, path)

    def send(self, method, path, data=None, headers=None):
        url = self._url_builder(path)
        data = self.module.jsonify(data)

        resp, info = fetch_url(self.module, url, data=data, headers=self.headers, method=method)

        response = Response(resp, info)

        if response.status_code >= 500:
            raise RestException(response.info['msg'])
        else:
            return response

    def get(self, path, data=None, headers=None):
        return self.send('GET', path, data, headers)

    def put(self, path, data=None, headers=None):
        return self.send('PUT', path, data, headers)

    def post(self, path, data=None, headers=None):
        return self.send('POST', path, data, headers)

    def delete(self, path, data=None, headers=None):
        return self.send('DELETE', path, data, headers)


def core(module):
    api_token = module.params['oauth_token']

    rest = Rest(module, {'Authorization': 'Bearer {}'.format(api_token),
                         'Content-type': 'application/json'})

    # TODO: recursive fetch!
    response = rest.get('floating_ips?page=1&per_page=20')
    status_code = response.status_code
    json = response.json
    if status_code == 200:
        module.exit_json(changed=False, data=json)
    else:
        module.fail_json(msg='Error fecthing facts [{}: {}]'.format(
            status_code, response.json['message']))


def main():
    module = AnsibleModule(
        argument_spec = dict(
            oauth_token = dict(
                no_log=True,
                # Support environment variable for DigitalOcean OAuth Token
                fallback=(env_fallback, ['DO_API_TOKEN', 'DO_API_KEY']),
                required=True,
            ),
        ),
    )

    try:
        core(module)
    except Exception as e:
        e = get_exception()
        module.fail_json(msg=e.message)

if __name__ == '__main__':
    main()
