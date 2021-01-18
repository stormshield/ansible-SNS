#!/usr/bin/python

# Copyright: (c) 2020, MEK 

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
module: sns_object_import
short_description: API client to upload OBJECTS in CSV format to Stormshield Network Security appliances
description:
  This module uploads objects with the specified CSV file to SNS appliance
  Configuration API reference: https://documentation.stormshield.eu/SNS/v3/en/Content/CLI_Serverd_Commands_reference_Guide_v3/Introduction.htm
options:
  path:
    description:
      - Set the CSV file to upload
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
  - Mehdi KHELIFA (@MEK)
notes:
  - This module requires python-SNS-API library
'''

EXAMPLES = '''
- name: Upload CSV OBJECT with a local file
  sns_object_import:
    path: path/to/objectFile.csv
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
    payload={
        "UPLOADING-FILE": "CONFIG OBJECT IMPORT UPLOAD < %s" % (objectFilePath),
        "IMPORT-COMMIT": "CONFIG OBJECT IMPORT ACTIVATE",
        "COMMIT-OBJECT-DB": "CONFIG OBJECT ACTIVATE"
    }
    runCommand(fwConnection,"CONFIG OBJECT IMPORT CANCEL")
    runCommand(fwConnection,payload["UPLOADING-FILE"])
    runCommand(fwConnection,payload["IMPORT-COMMIT"])
    currentUploadStatus=getObjectUploadStatus(fwConnection)
    while True:
        if currentUploadStatus.data['Result']['Status'] == "OK":
            uploadStatus=currentUploadStatus.data['Result']
            break
        if currentUploadStatus.data['Result']['Status'] in ['FAILED' ,'NO IMPORT PENDING']:
            raise Exception('A problem occured during upload activation : %s' % str(currentUploadStatus.data['Result']))
            break
        if currentUploadStatus.data['Result']['Status'] == "PENDING":
            currentUploadStatus=getObjectUploadStatus(fwConnection)
    return uploadStatus


def main():
    module = AnsibleModule(
        argument_spec={
            "path": {"required": True, "type": "str"},
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

    path = module.params['path']
    force_modify = module.params['force_modify']

    if path is None:
        module.fail_json(msg="Path of the file is required")

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

    if path is not None:
        try:
            response = uploadObjectCSV(client,path)
        except Exception as exception:
            client.disconnect()
            module.fail_json(msg=str(exception))
        client.disconnect()
        resultJson=dict()
        resultJson['output']=str(response)
        for (k,v) in dict(response).items():
            resultJson[k]=v
        if response['Status'] == "OK":
            resultJson['changed']=True
            module.exit_json(**resultJson)
        else:
            resultJson['changed']=False
            resultJson['success']=False
            resultJson['msg']="Errors occured during the import operation"
            module.fail_json(**resultJson)

if __name__ == '__main__':
    main()
