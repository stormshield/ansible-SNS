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
module: sns_getconf
short_description: Tool to parse sns api command results and extract individual values
description:
  SNS api commands return result in 'ini' format.

  [Section]
  token=value
  token2=value2

options:
  result:
    description:
      - Command result to parse
  section:
    description
      - Section to read
  token:
    description:
      - Token to extract
  default
    description:
      - Default value to return if token is not found
author: 
  - Remi Pauchet (@stormshield)
notes:
  - This module requires pySNSAPI python library
'''

EXAMPLES = '''
- name: Extract firmware version from SYSTEM PROPERTY
  sns_getconf:
    result: "{{ sysprop.result }}"
    section: Result
    token: Version
  register: myversion
'''

RETURN = '''
value:
  description: Extracted token value
  returned: changed
  type: string
  sample: 3.7.1
'''

from stormshield.sns.configparser import ConfigParser, serialize

from ansible.module_utils.basic import AnsibleModule

def main():
    module = AnsibleModule(
        argument_spec={
            "result": {"required": True, "type": "str"},
            "section": {"required": True, "type": "str"},
            "token": {"required": False, "type": "str"},
            "line": {"required": False, "type": "int"},
            "default": {"required": False, "type": "str"}
        }
    )

    result = module.params['result']
    section = module.params['section']
    token = module.params['token']
    line = module.params['line']
    default = module.params['default']

    if token is None and line is None:
        module.exit_json(changed=True,
                         value=serialize(ConfigParser(result).get(section=section,  default={})))

    if line is not None:
        module.exit_json(changed=True,
                         value=serialize(ConfigParser(result).get(section=section,
                                                       line=line,
                                                       default=default)))
    else:
        module.exit_json(changed=True,
                         value=serialize(ConfigParser(result).get(section=section,
                                                       token=token,
                                                       default=default)))

if __name__ == '__main__':
    main()
