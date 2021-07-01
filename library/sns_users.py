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
- name: Upload CSV OBJECT with a local file
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

from ansible.module_utils.basic import AnsibleModule

def runCommand(fwConnection,command):
    '''
    returns a dict with keys ['code','data','format','msg','output','parser','ret','xml']
    '''
    return fwConnection.send_command(command)

def getObjectUploadStatus(fwConnection):
    '''
    returns the object import status
    '''
    return runCommand(fwConnection,"CONFIG OBJECT IMPORT STATUS")

def uploadObjectCSV(fwConnection,objectFilePath):
    '''
    Uploads a CSV file to SNS appliance. Returns the final upload status.
        Parameters:
                fwConnection (SSLClient): SNS connection socket initialized outside with SSLClient()
                objectFilePath (str): CSV file to upload
        Returns:
                uploadStatus (dict): the final upload status
    '''
    if os.path.exists(objectFilePath) == False:
      raise Exception("Specified file %s does not exist" %(objectFilePath))

    runCommand(fwConnection, "CONFIG OBJECT IMPORT CANCEL") # reset previous erroneous state
    runCommand(fwConnection, "CONFIG OBJECT IMPORT UPLOAD < %s" % (objectFilePath))
    runCommand(fwConnection, "CONFIG OBJECT IMPORT ACTIVATE")
    currentUploadStatus=getObjectUploadStatus(fwConnection)
    while True:
        if currentUploadStatus.data['Result']['Status'] == "OK":
            uploadStatus=currentUploadStatus.data['Result']
            runCommand(fwConnection, "CONFIG OBJECT ACTIVATE")
            break
        if currentUploadStatus.data['Result']['Status'] in ['FAILED' ,'NO IMPORT PENDING']:
            raise Exception('A problem occured during upload activation : %s' % str(currentUploadStatus.data['Result']))
            break
        if currentUploadStatus.data['Result']['Status'] == "PENDING":
            time.sleep(2) # wait for completion
            currentUploadStatus=getObjectUploadStatus(fwConnection)
    return uploadStatus


def user_exists(fwConnection, username, m):
    """ returns a dict with keys ['code','data','format','msg','output','parser','ret','xml'] """
    ret = runCommand(fwConnection, "USER SHOW user=%s" % username)
    if ret.ret == 100:
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
      if user_exists(client, name, module):
        module.debug("user %s exists !" % name)
        resultJson['changed']=False
        resultJson['message']="user %s already exists !" % name
      else:
        module.debug("user %s does not exists !" % name)
        resultJson['changed']=True
        resultJson['message']="user %s does not exists !" % name

      client.disconnect()
      module.exit_json(**resultJson)

#      resultJson=dict()
#      resultJson['output']=str(response)
#      for (k,v) in dict(response).items():
#          resultJson[k]=v
#      if response['Status'] == "OK":
#          resultJson['changed']=True
#          module.exit_json(**resultJson)
#      else:
#          resultJson['changed']=False
#          resultJson['success']=False
#          resultJson['msg']="Errors occured during the import operation"
#          module.fail_json(**resultJson)
    module.exit_json(**resultJson)

if __name__ == '__main__':
    main()
