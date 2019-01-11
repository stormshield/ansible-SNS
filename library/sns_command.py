#!/usr/bin/python

# Copyright: (c) 2018, Stormshield https://www.stormshield.com
#
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
module: sns_command
short_description: API client to configure Stormshield Network Security appliances
description:
  This module executes configuration commands or scripts on the remote appliance.
  Configuration API reference: https://documentation.stormshield.eu/SNS/v3/en/Content/CLI_Serverd_Commands_reference_Guide_v3/Introduction.htm
options:
  script:
    description:
      - Configuration script to execute
  expect_disconnect:
    description
      - Set to True if the script makes the remote server to disconnect (ie: install firmware update)
  appliance:
    description:
      - appliance connection's parameters (host, port, user, password, sslverifypeer, sslverifyhost, cabundle, usercert)
author:
  - Remi Pauchet (@stormshield)
notes:
  - This module requires pySNSAPI python library
'''

EXAMPLES = '''
- name: Get appliance properties
  sns_command:
    script: "SYSTEM PROPERTY"
    appliance:
      host: myappliance.local
      password: mypassword
  delegate_to: localhost

- name: Update firmware with a local update file
  sns_command:
    script: |
      SYSTEM UPDATE UPLOAD < /tmp/fwupd-SNS-3.7.1-amd64-M.maj
      SYSTEM UPDATE ACTIVATE
    expect_disconnect: True
    appliance:
      host: myappliance.local
      password: mypassword
  delegate_to: localhost
'''

RETURN = '''
ret:
  description: last command return code
  returned: changed
  type: int
  sample: 100
output:
  description: script execution output
  returned: changed
  type: string
  sample: |
    > CONFIG NTP SERVER LIST
    101 code=00a01000 msg="Begin" format="section_line"
    [Result]
    name=fr.pool.ntp.org keynum=none type=host
    100 code=00a00100 msg="Ok"
    > HELP
    101 code=00a01000 msg="Begin" format="raw"
    AUTH       : User authentication
    CHPWD      : Return if it's necessary to update password or not
    CONFIG     : Firewall configuration functions
    GLOBALADMIN : Global administration
    HA         : HA functions
    HELP       : Display available commands
    LIST       : Display the list of connected users, show user rights (Level) and rights for current session (SessionLevel).
    LOG        : Log related functions.Everywhere a timezone is needed, if not specified the command is treated with firewall timezone setting.
    MODIFY     : Get / lose the modify or the mon_write right
    MONITOR    : Monitor related functions
    NOP        : Do nothing but avoid disconnection from server.
    PKI        : show or update the pki
    QUIT       : Log off
    REPORT     : Handling of reports
    SYSTEM     : System commands
    USER       : User related functions
    VERSION    : Display server version
    100 code=00a00100 msg="Ok"
result:
  description: last command output
  returned: changed
  type: string
  sample: |
    101 code=00a01000 msg="Begin" format="section_line"
    [Result]
    name=ntp1.stormshieldcs.eu keynum=none type=host
    name=ntp2.stormshieldcs.eu keynum=none type=host
    100 code=00a00100 msg="Ok"
data:
  description: last parsed command result
  type: complex
  sample: |
    {'Result': [
        {'name': 'ntp1.stormshieldcs.eu', 'keynum': 'none', 'type': 'host'},
        {'name': 'ntp2.stormshieldcs.eu', 'keynum': 'none', 'type': 'host'}
    ]}
'''

import re

from stormshield.sns.sslclient import SSLClient

from ansible.module_utils.basic import AnsibleModule

def main():
    module = AnsibleModule(
        argument_spec={
            "command": {"required": False, "type": "str"},
            "script": {"required": False, "type": "str"},
            "expect_disconnect": {"required": False, "type":"bool", "default":False},
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
                    "usercert": {"required": False, "type": "str"}
                }
            }
        }
    )

    EMPTY_RE = re.compile(r'^\s*$')

    command = module.params['command']
    script = module.params['script']
    expect_disconnect = module.params['expect_disconnect']

    if command is None and script is None:
        module.fail_json(msg="A command or a script is required")
        return

    if command is not None and script is not None:
        module.fail_json(msg="Got both command and script")
        return

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
            autoconnect=False)
    except Exception as exception:
        module.fail_json(msg=str(exception))
        return

    try:
        client.connect()
    except Exception as exception:
        module.fail_json(msg=str(exception))
        return

    if command is not None:
        # execute single command
        try:
            response = client.send_command(command)
        except Exception as exception:
            if expect_disconnect and str(exception) == "Server disconnected":
                pass
            else:
                module.fail_json(msg=str(exception), result=response.output, 
                                 data=response.parser.serialize_data(), ret=response.ret)
                client.disconnect()
                return
        client.disconnect()
        module.exit_json(changed=True, result=response.output,
                         data=response.parser.serialize_data(), ret=response.ret)
    else:
        # execute script
        output = ""
        success = True
        for command in script.splitlines():
            command = command.strip('\r\n')
            output += command + "\n"
            if command.startswith('#'):
                continue
            if EMPTY_RE.match(command):
                continue
            try:
                response = client.send_command(command)
                output += response.output + "\n"
                if response.ret >= 200:
                    success = False
            except Exception as exception:
                if expect_disconnect and str(exception) == "Server disconnected":
                    pass
                else:
                    module.fail_json(msg=str(exception), output=output, success=False)
                    client.disconnect()
                    return

        client.disconnect()
        if success:
            module.exit_json(changed=True, output=output, success=True)
        else:
            module.fail_json(msg="Errors during the script execution", output=output, success=False)

if __name__ == '__main__':
    main()
