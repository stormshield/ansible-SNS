# ANSIBLE STORMSHIELD SNS modules

Ansible modules to configure Stormshield Network Security Appliances.

This library includes the following modules:
- **sns_command**: to execute configuration command or script on a remote appliance using the HTTPS API.
- **sns_getconf**: to parse and extract values from command output in section/ini format.
- **sns_object_import**: to import objects to a remote appliance using a CSV file

Notes:
- These modules require the [python-SNS-API python library](https://github.com/stormshield/python-SNS-API)
- The python-SNS-API python library should be installed in the Ansible python environment and in the same python interpreter version. Use `ansible -version` to get the information.
- If you install the python3 version and if Ansible uses python2 by default, you have to set the `ansible_python_interpreter=/usr/bin/python3` configuration option in the task definition or the inventory.
- Ansible roles and additional how-to guide can be found at: [Ansible roles repository](https://github.com/stormshield/sns-scripting/tree/master/ansible-roles)


## sns_command

This module executes a configuration command or a script on the remote appliance.

Command output is saved in the `result` property, parsed output is available in the `data` property and return code is in `ret`.

```yaml
  tasks:
    - name: Get appliance information
      sns_command:
        appliance:
          host: 10.0.0.254
          password: password
          sslverifyhost: False
        command: SYSTEM PROPERTY
      delegate_to: localhost
      register: sysprop
```

```yaml
changed: [localhost] => changed=true
  data:
    Result:
      MachineType: amd64
      Model: V50-A
      Type: Firewall
      Version: 3.7.1
      ...
  invocation:
    module_args:
      appliance:
        ...
      command: SYSTEM PROPERTY
      expect_disconnect: false
      script: null
  result: |-
    101 code=00a01000 msg="Begin" format="section"
    [Result]
    Type=Firewall
    Model=V50-A
    MachineType=amd64
    Version=3.7.1
    ...
    100 code=00a00100 msg="Ok"
  ret: 100
```

```yaml
- set_fact:
    model: "{{ sysprop.data['Result']['Model'] }}"
```

Script execution is recorded in the `output` property. The `success` property indicates if all commands were successfully executed or not (scripts do not stop on the first error).

```yaml
  tasks:
    - name: Activate SSH service on remote firewall
      sns_command:
        appliance:
          host: 10.0.0.254
          password: password
          sslverifyhost: False
        script: |
          CONFIG CONSOLE SSH state=1 userpass=1
          CONFIG CONSOLE ACTIVATE
```

### About ssl validation

* For the first connection to a new appliance, ssl host name verification can be bypassed with `sslverifyhost: false` option.
* To connect to a well-known appliance with the default Stormshield certificate, use `host: <serial>` and `ip: <ip address>` to validate the appliance certificate.
* If a custom CA and certificate are installed on the appliance, use `cabundle: /path/to/ca.pem`, `host: <dns name>`.
* For client certificate authentication, the expected format is a PEM file with the certificate and the unencrypted key concatenated `usercert: /path/to/cert.pem`.

Example:

```yaml:
    appliance:
      vars:
        host: myappliance.local
        usercert: /cert/user.pem
        cabundle: /cert/ca.pem
```

## Proxy

The module supports http and socks proxy.

Example:

```yaml:
    appliance:
      vars:
        host: myappliance.local
        proxy: socks5://myproxy.local:1080
```

## Modify privilege

Add `force_modify: true` for scripts or action which require the modify privilege. That will disconnect any other administration session with the modify privilege and ensure the script or action can write changes.

## sns_getconf

This module extracts information from the result of a configuration command. The default parameters is the value returned if the token is not found in the analyzed result.

For example, the `SYSTEM PROPERTY` command returns:

```ini
101 code=00a01000 msg="Begin" format="section"
[Result]
Type="Firewall"
Model="V50-A"
MachineType="amd64"
Version="3.7.1"
[...]
```
Firmware version can be extracted with the following task:

```yaml
  tasks:
    - name: Extract version
      sns_getconf:
        result: "{{ mycommand.result }}"
        section: Result
        token: Version
        default: Unknown
      register: myversion
```

## sns_object_import

This module imports the specified CSV file to the remote appliance. 
Depending on the size of the file, an upload task can take some time.

```yaml
- name: Upload CSV OBJECT with a local file
  sns_object_import:
    force_modify: true
    path: path/to/objectFile.csv
    appliance:
      host: myappliance.local
      password: mypassword
  delegate_to: localhost
  register: sample_upload
# Sample output :
sample_upload: {'Status': 'OK', 'Code': '0', 'Num_line': '934', 'host': '402', 'network': '532'}"
```

> Please note that the import will fail if you are trying to insert more objects than the appliance supports

## Examples:

### sns-ssh.yaml

This playbook activates the ssh access and configure the corresponding filtering rule on the remote appliance.

The remote appliance connection parameters are defined in the `appliance` dict.

`$ ansible-playbook sns-ssh.yaml`

### sns-firmare-update

The playbook downloads firmware update from MyStormshield and updates the targeted appliance if needed.

The remote appliance connection parameters are defined in the `appliance` dict.

`$ ansible-playbook sns-firmware-update.yaml`

### sns-property.yaml

This playbook returns the firmware version and the model of all the appliances of the inventory.

`$ ansible-playbook -i inventory.yaml sns-property.yaml`

Or to filter by appliance:

`$ ansible-playbook -i inventory.yaml --extra-vars 'appliancelist=["appliance1"]' sns-property.yaml`

The inventory file declares the connection parameters of the appliances:

```yaml
sns_appliances:
  hosts:
    appliance1:
      vars:
        host: 10.0.0.254
        user: admin
        password: password
        sslverifyhost: false
    appliance2:
      vars:
       ...
```

### sns-basic-provisioning

This playbook configures NTP and DNS services, webadmin ACL and filtering.
This example shows how to use a script template (sns-basic-provisioning.script) with Ansible.

`$ ansible-playbook sns-basic-provisioning.yaml`

### sns-backup

This playbook backups the configuration of the appliances referenced in the inventory file.

`$ ansible-playbook -i inventory.yaml sns-backup.yaml`

### sns-object-import

This playbook uploads a CSV file in the object database of the appliance.

`$ ansible-playbook -i inventory.yaml sns-object-import.yaml`

> Exporting object database from an appliance is a good way to apprehend the expected format

## Links

* [Stormshield corporate website](https://www.stormshield.com)
* [CLI commands reference guide](https://documentation.stormshield.eu/SNS/v3/en/Content/CLI_Serverd_Commands_reference_Guide_v3/Introduction.htm)
