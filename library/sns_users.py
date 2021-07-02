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

ANSIBLE_METADATA = {'metadata_version': '0.9',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: sns_users
short_description: API client to manipulate users in Stormshield Network Security appliances
description:
  Configuration API reference: https://documentation.stormshield.eu/SNS/v4/en/Content/Basic_Command_Line_Interface_configurations
options:
  uid:
    name of the user. Format is supposed to be firstname.lastname. Common Name will try to be "Firstname Lastname".
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
    uid: toto.tata
    group: TotoGroup
    mail: toto.tata@domain.fr
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

from stormshield.sns.sslclient import SSLClient
from stormshield.sns.configparser import ConfigParser

from ansible.module_utils.basic import AnsibleModule

def runCommand(fwConnection,command):
    '''
    returns a dict with keys ['code','data','format','msg','output','parser','ret','xml']
    '''
    return fwConnection.send_command(command)


class User:
    def __init__(self, uid, group=None, mail=None, module=None):
        self.uid = uid
        self.group = group
        self.module = module  # mostly used to debug ansible module
        self.dn = None
        self.mail = None
        self.new_mail = mail
        self.given_name = " ".join([w.capitalize() for w in self.uid.replace('.', ' ').split()])


    def exists(self, fwConnection):
        response = runCommand(fwConnection, "USER SHOW user=%s" % self.uid)
        if response.ret == 100:
            data = response.parser.serialize_data()
            self.dn = data['User']['dn']  # keep DN for group membership
            if 'mail' in data['User']:
                self.mail = data['User']['mail']  # keep mail for identify handling

            if 'Certificate' in data:
                # an identity exists, save it for later
                self.identity = data['Certificate']['Subject']
                self.identity_expiration = data['Certificate']['NotAfter']
            return True
        else:
            return False


    def create(self, fwConnection):
        firstname = self.given_name.split()[0]
        lastname = self.given_name.split()[1]
        # self.module.fail_json(msg="USER CREATE uid=%s name=%s gname=\"%s\"" % (self.uid, name, self.given_name))
        response = runCommand(fwConnection, "USER CREATE uid=%s name=%s gname=\"%s\"" % 
                              (self.uid, firstname, lastname))
        if response.ret >= 200:
            self.module.fail_json(msg="error creating user %s" % self.uid, data=response.parser.serialize_data(),
                                  result=response.output, ret=response.ret)
            return False
        return True


    def remove(self, fwConnection):
        # self.module.fail_json(msg="USER REMOVE %s % self.uid
        response = runCommand(fwConnection, "USER REMOVE %s" % self.uid)
        if response.ret >= 200:
            self.module.fail_json(msg="error removing user %s" % self.uid, data=response.parser.serialize_data(),
                                  result=response.output, ret=response.ret)
            return False
        return True
    

    def add_mail(self, fwConnection):
        """ TODO: implement other modifications. Description is safe but mail and uid are probably tricky """
        if self.mail and self.identity:
            # cannot modify email for now
            self.module.fail_json(msg="cannot modify email address for user %s (identity needs to be regenerated)" % self.uid)
            return False

        # USER UPDATE %s operation=add attribute=mail value=%s % (self.uid, self.mail)
        if self.mail:
            operation = 'mod'
        else:
            operation = 'add'

        # self.module.fail_json(msg="USER UPDATE user=%s operation=%s attribute=mail value=%s" % (self.uid, operation, self.new_mail))
        response = runCommand(fwConnection, "USER UPDATE user=%s operation=%s attribute=mail value=%s" %
                                            (self.uid, operation, self.new_mail))
        if response.ret >= 200:
            self.module.fail_json(msg="error update email of user %s" % self.uid, data=response.parser.serialize_data(),
                                  result=response.output, ret=response.ret)
            return False
        return True


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

    def add_to_group(self, fwConnection, groupname):
        response = runCommand(fwConnection, "USER GROUP ADDUSER %s %s" % (groupname, self.uid) )
        if response.ret >= 200:
            self.module.fail_json(msg="error adding user %s to group %s" % (self.uid, groupname),
                                   data=response.parser.serialize_data(),
                                   result=response.output, ret=response.ret)
            return False
        return True


def main():
    module = AnsibleModule(
        argument_spec={
            "uid": {"required": True, "type": "str"},
            "email": {"required": False, "type": "str"},
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
    email = module.params['email']
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

    # acquire write privileges
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
    current_user = User(uid, group, email, module)

    if state == 'present':
        if not current_user.exists(client):
            if current_user.create(client):
                resultJson['changed']=True
                resultJson['message']="user %s created" % uid
            else: 
                resultJson['changed']=False
                resultJson['message']="Error creating user %s" % uid
        else:
            # nothing to do
            resultJson['changed']=False
            resultJson['message']="user %s already exists!" % uid

        if group:
            if current_user.in_group(client, group):
                # nothing to do
                resultJson['changed']=False
                resultJson['message']="user %s already exists and is in the right group!" % uid
            else:
                # assign to the group
                # TODO: handle group creation and assignation after the user is created. Groups cannot be empty in stormshield!
                current_user.add_to_group(client, group)
                resultJson['changed']=True
                resultJson['message']="user %s added to group %s!" % (uid, group)

        if email:
            if not current_user.mail:
                current_user.add_mail(client)
                resultJson['changed']=True
                resultJson['message']="Add email %s to user %s" % (email, uid)


    if state == 'absent':
        if current_user.exists(client):
            if current_user.remove(client):
                resultJson['changed']=True
                resultJson['message']="user %s removed" % uid
            else:
                resultJson['changed']=False
                resultJson['message']="Error removing user %s" % uid
        else:
          # nothing to do
          resultJson['changed']=False

    client.disconnect()
    module.exit_json(**resultJson)

if __name__ == '__main__':
    main()
