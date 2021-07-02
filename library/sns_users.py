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
  uid:
    name of the user
  given_name:
    optionnal full name (will default to uid if absent)
  group:
    group to which user belongs (TODO: only one for now)
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
    uid: toto
    given_name: toto tata
    group: TotoGroup
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


class User:
    def __init__(self, uid, given_name=None, group=None, module=None):
        self.uid = uid
        self.given_name = given_name
        self.group = group
        self.module = module  # used to debug ansible module
        self.dn = None


    def setdn(self, fwConnection):
        response = runCommand(fwConnection, "USER SHOW user=%s" % self.uid)
        data = response.parser.serialize_data()
        self.dn = data['User']['dn']


    def exists(self, fwConnection):
        response = runCommand(fwConnection, "USER SHOW user=%s" % self.uid)
        if response.ret == 100:
            return True
        else:
            return False


    def create(self):
        pass
    
    def remove_user(self):
        pass
    
    def modify_user(self):
        pass


    def group_getmembers(self, fwConnection, groupname):
        response = runCommand(fwConnection, "USER GROUP SHOW group=%s" % groupname)
        if response.ret >= 200:
            # probably groupname error
            #TODO: implement group check
            return None
        data = response.parser.serialize_data()
        member_keys = [k for k in data['Group'].keys() if 'member' in k]
        members = [data['Group'][m] for m in member_keys]
    
        return members
    
    
    def in_group(self, fwConnection, groupname):
        members = self.group_getmembers(fwConnection, groupname)
        if not members:
            return False
        if self.dn in members:
            return True
        else:
            return False

def main():
    module = AnsibleModule(
        argument_spec={
            "uid": {"required": True, "type": "str"},
            "given_name": {"required": False, "type": "str"},
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

    # prefly checks
    uid = module.params['uid']
    state = module.params['state']
    group = module.params['group']
    force_modify = module.params['force_modify']

    if uid is None:
        module.fail_json(msg="User uid is required")

    options = {}
    if module.params['timeout'] is not None:
      options["timeout"] = module.params['timeout']

    # sns connection
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

    # write privileges handling
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

    # user handling
    resultJson=dict(changed=False, original_message='', message='')
    current_user = User(uid, 'given_name', group, module)

    if state == 'present':
      if current_user.exists(client):
        current_user.setdn(client)
        if group:
            if current_user.in_group(client, group):
                resultJson['changed']=False
                resultJson['message']="user %s already exists and is in the right group!" % uid
            else:
                resultJson['changed']=True
                resultJson['message']="user %s already exists but not in group %s!" % (uid, group)
        else:
          resultJson['changed']=False
          resultJson['message']="user %s already exists !" % uid
      else:
        resultJson['changed']=True
        resultJson['message']="user %s does not exists !" % uid

      client.disconnect()
      module.exit_json(**resultJson)

    module.exit_json(**resultJson)

if __name__ == '__main__':
    main()
