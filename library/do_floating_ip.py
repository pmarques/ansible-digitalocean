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
module: do_floating_ip
short_description: Manage DigitalOcean Floating IPs
description:
     - Create/delete/assign a floating IP.
version_added: "2.3"
author: "Patrick Marques (@pmarques)"
options:
  state:
    description:
     - Indicate desired state of the target.
    default: present
    choices: ['present', 'absent']
  ip:
    description:
     - Public IP address of the Floating IP. Used to remove an IP
    required: false
    default: None
  region:
    description:
     - The region that the Floating IP is reserved to.
    required: false
    default: None
  droplet_id:
    description:
     - The Droplet that the Floating IP should be assigned to. If a list of Droplet
       IDs (separated by commas ',') is given, it will check if the Floating IP is
       assigned to any Droplet in the list and if not assigns the Floating IP to
       the first Droplet in the list.
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
- name: "Create a Floating IP in regigin lon1"
  do_floating_ip:
    state: present
    region: lon1

- name: "Create a Floating IP assigned to Droplet ID 123456"
  do_floating_ip:
    state: present
    droplet_id: 123456

- name: "Delete a Floating IP with ip 1.2.3.4"
  do_floating_ip:
    state: present
    ip: "1.2.3.4"

'''


RETURN = '''
# Digital Ocean API info https://developers.digitalocean.com/documentation/v2/#floating-ips
data:
    description: a DigitalOcean Floating IP resource
    returned: success and no resource constraint
    type: dict
    sample: {
      "action": {
        "id": 68212728,
        "status": "in-progress",
        "type": "assign_ip",
        "started_at": "2015-10-15T17:45:44Z",
        "completed_at": null,
        "resource_id": 758603823,
        "resource_type": "floating_ip",
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
        "region_slug": "nyc3"
      }
    }
'''

import json
import os
import time

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


def wait_action(module, rest, ip, action_id, timeout=10):
    end_time = time.time() + 10
    while time.time() < end_time:
        response = rest.get('floating_ips/{}/actions/{}'.format(ip, action_id))
        status_code = response.status_code
        status = response.json['action']['status']
        # TODO: check status_code == 200?
        if status == 'completed':
            return True
        elif status == 'errored':
            module.fail_json(msg='Floating ip action error [ip: {}: action: {}]'.format(
                ip, action_id), data=json)

    module.fail_json(msg='Floating ip action timeout [ip: {}: action: {}]'.format(
        ip, action_id), data=json)


def core(module):
    api_token = module.params['oauth_token']
    state = module.params['state']

    rest = Rest(module, {'Authorization': 'Bearer {}'.format(api_token),
                         'Content-type': 'application/json'})

    if state in ('present'):
        # if a Droplet ID and a Floating ID are passed to module, we only need to
        # associate them, is not possible to create and specify Floating ID / IP
        if module.params['droplet_id'] is not None and module.params['ip'] is not None:
            assign_floating_id_to_droplet(module, rest)
        else:
            create_floating_ips(module, rest)

    elif state in ('absent'):
        delete_floating_ips(module, rest)


def get_floating_ip_details(module, rest):
    ip = module.params['ip']

    response = rest.get('floating_ips/{}'.format(ip))
    status_code = response.status_code
    json = response.json
    if status_code == 200:
        return response.json
    else:
        module.fail_json(msg='Error geting floating ip [{}] details [{}: {}]'.format(
            ip, status_code, response.json['message']), region=module.params['region'])


def get_all_floating_ips(module, rest):
    # TODO: recursive fetch!
    response = rest.get('floating_ips?page=1&per_page=20')
    status_code = response.status_code
    json = response.json
    if status_code != 200:
        module.fail_json(msg='Error fecthing facts [{}: {}]'.format(
            status_code, response.json['message']))

    return json['floating_ips']

def assert_floating_ips_to_droplet_ids(module, rest):
    floating_ips = get_all_floating_ips(module, rest)


    for fip in floating_ips:
        if fip['droplet']['id'] in module.params['droplet_id']:
            return fip

    return None


def create_floating_ips(module, rest):
    """
    Create a Floating IP in a region or associated to one of the Droplet IDs.
    """

    payload = {
    }

    if module.params['region'] is not None:
        payload['region'] = module.params['region']
    if module.params['droplet_id'] is not None:
        # If there is already on Floating IP associated to one of the Droplet IDs
        # our job is done
        fip = assert_floating_ips_to_droplet_ids(module, rest)
        if fip is not None:
            module.exit_json(changed=False, data=fip)

        payload['droplet_id'] = module.params['droplet_id'][0]

    response = rest.post('floating_ips', data=payload)
    status_code = response.status_code
    json = response.json
    if status_code == 202:
        module.exit_json(changed=True, data=json)
    else:
        module.fail_json(msg='Error creating floating ip [{}: {}]'.format(
            status_code, response.json['message']), region=module.params['region'])


def delete_floating_ips(module, rest):
    ip = module.params['ip']

    response = rest.delete('floating_ips/{}'.format(ip))
    status_code = response.status_code
    json = response.json
    if status_code == 204:
        module.exit_json(changed=True)
    elif status_code == 404:
        module.exit_json(changed=False)
    else:
        module.exit_json(changed=False, data=json)


def assign_floating_id_to_droplet(module, rest):
    floating_ip = get_floating_ip_details(module, rest)
    droplet = floating_ip['floating_ip']['droplet']

    if droplet is not None and str(droplet['id']) in module.params['droplet_id']:
        module.exit_json(changed=False, data=floating_ip)

    ip = module.params['ip']

    payload = {
        'type': 'assign',
        'droplet_id': module.params['droplet_id'][0],
    }

    response = rest.post('floating_ips/{}/actions'.format(ip), data=payload)
    status_code = response.status_code
    json = response.json
    if status_code == 201:
        wait_action(module, rest, ip,  json['action']['id'])

        module.exit_json(changed=True, data=floating_ip, action_id=json['action']['id'])
    else:
        module.fail_json(msg='Error creating floating ip [{}: {}]'.format(
            status_code, response.json['message']), region=module.params['region'])


def main():
    module = AnsibleModule(
        argument_spec = dict(
            state = dict(choices=['present', 'absent'], default='present'),
            ip = dict(aliases=['id'], required=False),
            region = dict(required=False),
            droplet_id = dict(required=False),
            oauth_token = dict(
                no_log=True,
                # Support environment variable for DigitalOcean OAuth Token
                fallback=(env_fallback, ['DO_API_TOKEN', 'DO_API_KEY']),
                required=True,
            ),
        ),
        # required_one_of = (
        # ),
        required_if = ([
            ('state','delete',['ip'])
        ]),
        # required_together = (),
        mutually_exclusive = (
            ['region', 'droplet_id']
        ),
    )

    # Parse droplet_id(s) into a list
    if module.params['droplet_id'] is not None:
        module.params['droplet_id'] = [ int(did) for did in module.params['droplet_id'].split(',') ]

    try:
        core(module)
    except Exception as e:
        e = get_exception()
        module.fail_json(msg=e.message)

if __name__ == '__main__':
    main()
