#!/usr/bin/python

# Copyright: (c) 2021, NLA

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

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: sns_users
short_description: API client to manipulate users in Stormshield Network Security appliances
description:
  TODO: update
  Configuration API reference: https://documentation.stormshield.eu/SNS/v4/en/Content/Basic_Command_Line_Interface_configurations
options:
  name:
    name of the user
  comment:
    optionnal comment
  groups:
    groups to which user belongs
  state:
      description:
          - Whether the account should exist or not, taking action if the state is different from what is stated.
      choices: [ absent, present ]
      default: present
  force_modify:
    description:
      - Set to true to disconnect other administrator already connected with modify privilege.
  timeout:
    description:
      - Set the connection and read timeout.
  appliance:
    description:
      - appliance connection's parameters (host, port, user, password, sslverifypeer, sslverifyhost, cabundle, usercert, proxy)
author:
  - NLA
notes:
  - This module requires python-SNS-API library
'''

EXAMPLES = '''
- name: Create a user account
  sns_users:
    name: toto
    state: present
    appliance:
      host: myappliance.local
      password: mypassword
  delegate_to: localhost
'''

RETURN = '''
output:
  description: JSON output in string Format
  type: str
  sample: {'Status': 'OK', 'Code': '0', 'Num_line': '934', 'host': '402', 'network': '532'}"
Status:
  description: upload status. Can be ['OK','FAILED']
  returned: changed
  type: str
  sample: 'OK'
'''

import os.path
import time

from stormshield.sns.sslclient import SSLClient
from stormshield.sns.configparser import ConfigParser

from ansible.module_utils.basic import AnsibleModule

def runCommand(fwConnection,command):
    '''
    returns a dict with keys ['code','data','format','msg','output','parser','ret','xml']
    '''
    return fwConnection.send_command(command)


def user_exists(fwConnection, username):
    response = runCommand(fwConnection, "USER SHOW user=%s" % username)
    if response.ret == 100:
        return True
    else:
        return False


def user_getdn(fwConnection, username):
    response = runCommand(fwConnection, "USER SHOW user=%s" % username)
    data = response.parser.serialize_data()
    user_dn = data['User']['dn']
    return user_dn


def group_getmembers(fwConnection, groupname):
    response = runCommand(fwConnection, "USER GROUP SHOW group=%s" % groupname)
    if response.ret >= 200:
        # probably groupname error
        #TODO: implement group check
        return None
    data = response.parser.serialize_data()
    member_keys = [k for k in data['Group'].keys() if 'member' in k]
    members = [data['Group'][m] for m in member_keys]

    return members


def user_in_group(fwConnection, username, groupname):
    user_dn = user_getdn(fwConnection, username)
    members = group_getmembers(fwConnection, groupname)
    if not members:
        return False
    if user_dn in members:
        return True
    else:
        return False

def create_user():
    pass

def remove_user():
    pass

def modify_user():
    pass

def main():
    module = AnsibleModule(
        argument_spec={
            "name": {"required": True, "type": "str"},
            "state": {"type": "str", "default": "present", "choices": ['absent', 'present']},
            "group": {"required": False, "type": "str"},
            "force_modify": {"required": False, "type":"bool", "default":False},
            "timeout": {"required": False, "type": "int", "default": None},
            "appliance": {
                "required": True, "type": "dict",
                "options": {
                    "host": {"required": True, "type": "str"},
                    "ip": {"required": False, "type": "str"},
                    "port": {"required": False, "type": "int", "default": 443},
                    "user": {"required": False, "type": "str", "default": "admin"},
                    "password": {"required": False, "type": "str"},
                    "sslverifypeer": {"required": False, "type": "bool", "default": True},
                    "sslverifyhost": {"required": False, "type": "bool", "default": True},
                    "cabundle": {"required": False, "type": "str"},
                    "usercert": {"required": False, "type": "str"},
                    "proxy":  {"required": False, "type": "str"},
                }
            }
        }
    )

    name = module.params['name']
    state = module.params['state']
    group = module.params['group']
    force_modify = module.params['force_modify']

    if name is None:
        module.fail_json(msg="User name is required")

    options = {}
    if module.params['timeout'] is not None:
      options["timeout"] = module.params['timeout']

    try:
        client = SSLClient(
            host=module.params['appliance']['host'],
            ip=module.params['appliance']['ip'],
            port=module.params['appliance']['port'],
            user=module.params['appliance']['user'],
            password=module.params['appliance']['password'],
            sslverifypeer=module.params['appliance']['sslverifypeer'],
            sslverifyhost=module.params['appliance']['sslverifyhost'],
            cabundle=module.params['appliance']['cabundle'],
            usercert=module.params['appliance']['usercert'],
            proxy=module.params['appliance']['proxy'],
            autoconnect=False,
            **options)
    except Exception as exception:
        module.fail_json(msg=str(exception))

    try:
        client.connect()
    except Exception as exception:
        module.fail_json(msg=str(exception))

    if force_modify:
        try:
            response = client.send_command("MODIFY FORCE ON")
        except Exception as exception:
            client.disconnect()
            module.fail_json(msg="Can't take Modify privilege: {}".format(str(exception)))
        if response.ret >= 200:
            client.disconnect()
            module.fail_json(msg="Can't take Modify privilege", result=response.output,
                             data=response.parser.serialize_data(), ret=response.ret)
##
# custom

    resultJson=dict(changed=False, original_message='', message='')

    if state == 'present':
      if user_exists(client, name):
        user_dn = user_getdn(client, name)
        if group:
            if user_in_group(client, name, group):
                resultJson['changed']=False
                resultJson['message']="user %s already exists and is in the right group!" % name
            else:
                resultJson['changed']=True
                resultJson['message']="user %s already exists but not in group %s!" % (name, group)
        else:
          resultJson['changed']=False
          resultJson['message']="user %s already exists !" % name
      else:
        resultJson['changed']=True
        resultJson['message']="user %s does not exists !" % name

      client.disconnect()
      module.exit_json(**resultJson)

    module.exit_json(**resultJson)

if __name__ == '__main__':
    main()
