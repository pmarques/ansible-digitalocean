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
module: do_sshkeys
short_description: Manage DigitalOcean SSH keys
description:
     - Create/delete DigitalOcean SSH keys.
version_added: "2.3"
author: "Patrick Marques (@patrickfmarques)"
options:
  state:
    description:
     - Indicate desired state of the target.
    default: present
    choices: ['present', 'absent']
  fingerprint:
    description:
     - This is a unique identified for the SSH key used to delete a key
    required: false
    default: None
  name:
    description:
     - The name for the SSH key
    required: false
    default: None
  ssh_pub_key:
    description:
     - The Public SSH key to add.
    required: false
    default: None
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
- name: "Create ssh key"
  do_sshkeys:
    name: "johndoe"
    ssh_pub_key: "ssh-rsa AAAAB3Nza(.....)VTw=="
  register: result

- name: "Delete ssh key"
  do_sshkeys:
    state: "absent"
    fingerprint: "64:09:d6:26:c9:f2:ab:28:bb:81:b1:d9:61:6b:88:80"
'''


RETURN = '''
# Digital Ocean API info https://developers.digitalocean.com/documentation/v2/#list-all-keys
data:
    description: a DigitalOcean SSH Keys resource manager
    returned: success and no resource constraint
    type: dict
    sample:
'''

import json
import os

from ansible.module_utils.basic import env_fallback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url


class Response(object):

    def __init__(self, resp, info):
        self.body = None
        if resp:
            self.body = resp.read()
        self.info = info

    @property
    def json(self):
        if not self.body:
            if "body" in self.info:
                return json.loads(self.info["body"])
            return None
        try:
            return json.loads(self.body)
        except ValueError:
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

        return Response(resp, info)

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
    state = module.params['state']
    fingerprint = module.params['fingerprint']
    name = module.params['name']
    ssh_pub_key = module.params['ssh_pub_key']

    rest = Rest(module, {'Authorization': 'Bearer {}'.format(api_token),
                         'Content-type': 'application/json'})

    if state in ('present'):
        payload = {
            "name": name,
            "public_key": ssh_pub_key
        }
        # if name is not None:
        #     payload["name"] = name

        response = rest.post("account/keys", data=payload)
        status_code = response.status_code
        json = response.json
        if status_code == 201:
            module.exit_json(changed=True, data=json)
        else:
            module.fail_json(msg="Error creating ssh key [{}: {}]".format(
                status_code, response.json["message"]))

    elif state in ('absent'):
        response = rest.delete("account/keys/{}".format(fingerprint))
        status_code = response.status_code
        json = response.json
        if status_code == 204:
            module.exit_json(changed=True)
        elif status_code == 404:
            module.exit_json(changed=False)
        else:
            module.fail_json(msg="Error creating ssh key [{}: {}]".format(
                status_code, response.json["message"]))


def main():
    module = AnsibleModule(
        argument_spec = dict(
            state = dict(choices=['present', 'absent'], default='present'),
            fingerprint = dict(aliases=['id'], required=False),
            name = dict(required=False),
            ssh_pub_key = dict(required=False),
            oauth_token = dict(
                no_log=True,
                # Support environment variable for DigitalOcean OAuth Token
                fallback=(env_fallback, ['DO_OAUTH_TOKEN']),
                required=True,
            ),
        ),
        # required_one_of = (
        # ),
        required_if = ([
            ('state','delete',['ip'])
        ]),
        # required_together = (),
        # mutually_exclusive = (
        #     ['region', 'droplet_id']
        # ),
    )

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=str(e))

if __name__ == '__main__':
    main()
