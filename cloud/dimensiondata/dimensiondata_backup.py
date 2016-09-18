#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2016 Dimension Data All Rights Reserved.
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible. If not, see <http://www.gnu.org/licenses/>.
#
# Authors:
#   Aimon Bustardo <Aimon.Bustardo@dimensiondata.com>
#   Jay Riddell    <Jay.Riddell@dimensiondata.com>

DOCUMENTATION = '''
---
module: dimensiondata_backup
short_description: Enable or Disable backups for a host.
description:
  - Creates, enables/disables backups for a host in the Dimension Data Cloud.
notes:
  - Does not support check-mode.
version_added: "2.2"
options:
  state:
    description:
      - The state you want the hosts to be in.
    required: false
    default: present
    choices: [present, absent]
  node_ids:
    description:
      - A list of server ids to work on.
    required: true
    aliases: [server_id, server_ids, node_id]
  region:
    description:
      - The target region.
    choices:
      - Regions choices are defined in Apache libcloud project [libcloud/common/dimensiondata.py]
      - Regions choices are also listed in https://libcloud.readthedocs.io/en/latest/compute/drivers/dimensiondata.html
      - Note that the region values are available as list from dd_regions().
      - Note that the default value "na" stands for "North America".  The code prepends 'dd-' to the region choice.
    default: na
  service_plan:
    description:
      - The service plan for backups.
    choices: [Essentials, Advanced, Enterprise]
    default: Essentials
  verify_ssl_cert:
    description:
      - Check that SSL certificate is valid.
    required: false
    default: true
  wait:
    description:
      - Should we wait for the task to complete before moving onto the next.
    required: false
    default: false
  wait_time:
    description:
      - Only applicable if wait is true.
        This is the amount of time in seconds to wait
    required: false
    default: 120
  wait_poll_interval:
    description:
      - The amount to time in between polling for task completion
    required: false
    default: 2

author:
    - "Jeff Dunham (@jadunham1)"
'''

EXAMPLES = '''
# Note: These examples do not include authorization.
# You can set these by exporting DIDATA_USER and DIDATA_PASSWORD vars:
# export DIDATA_USER=<username>
# export DIDATA_PASSWORD=<password>

# Basic enable backups example

- dimensiondata_backup:
    node_ids:
      - '7ee719e9-7ae9-480b-9f16-c6b5de03463c'

# Basic remove backups example
- dimensiondata_backup:
    node_ids:
      - '7ee719e9-7ae9-480b-9f16-c6b5de03463c'
    state: absent

# Full options enable
- dimensiondata_backup:
    node_ids:
      - '7ee719e9-7ae9-480b-9f16-c6b5de03463c'
    state: present
    wait: yes
    wait_time: 500
    service_plan: Advanced
    verify_ssl_cert: no
'''

RETURN = '''
servers:
  description: List of servers this worked on.
  returned: Always
  type: list
  contains: node_ids processed
'''

from ansible.module_utils.basic import *
from ansible.module_utils.dimensiondata import *
try:
    from libcloud.common.dimensiondata import DimensionDataAPIException
    from libcloud.backup.drivers.dimensiondata import DimensionDataBackupDriver
    import libcloud.security
    HAS_LIBCLOUD = True
except:
    HAS_LIBCLOUD = False
import time

# Get regions early to use in docs etc.
dd_regions = get_dd_regions()


def handle_backups(module, client):
    changed = False
    state = module.params['state']
    service_plan = module.params['service_plan']

    for server_id in module.params['node_ids']:
        try:
            backup_details = client.ex_get_backup_details_for_target(server_id)
        except DimensionDataAPIException as e:
            # Libcloud client returns throws an error if no backups for client
            # we'll catch this and set backup details to None instead of dying
            if e.msg.endswith('has not been provisioned for backup'):
                backup_details = None
            else:
                module.fail_json("Problem finding backup info for host: %s"
                                 % e.msg)

        if backup_details is None and state == 'absent':
            continue
        elif backup_details is not None and state == 'absent':
            changed = True
            disable_backup_for_server(client, module, server_id)
        elif backup_details is None and state == 'present':
            changed = True
            enable_backup_for_server(client, module, server_id, service_plan)
        elif backup_details is not None and state == 'present':
            if backup_details.service_plan != service_plan:
                changed = True
                modify_backup_for_server(client, module,
                                         server_id, service_plan)
        else:
            module.fail_json(msg="Unhandled state")

    module.exit_json(changed=changed, msg='Enabled host',
                     servers=module.params['node_ids'])


def enable_backup_for_server(client, module, server_id, service_plan):
    extra = {'servicePlan': service_plan}
    client.create_target(None, server_id, extra=extra)
    time.sleep(10)
    if module.params['wait'] is True:
        try:
            client.connection.wait_for_state(
                'NORMAL', client.ex_get_backup_details_for_target,
                module.params['wait_poll_interval'],
                module.params['wait_time'], server_id
            )
        except DimensionDataAPIException as e:
            module.fail_json(msg='Backup did not enable in time: %s' % e.msg)


def disable_backup_for_server(client, module, server_id):
    client.delete_target(server_id)


def modify_backup_for_server(client, module, server_id, service_plan):
    extra = {'servicePlan': service_plan}
    client.update_target(server_id, extra=extra)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            region=dict(default='na', choices=dd_regions),
            state=dict(default='present', choices=['present', 'absent']),
            node_ids=dict(required=True, type='list',
                          aliases=['server_id', 'server_ids', 'node_id']),
            service_plan=dict(default='Essentials',
                              choices=['Advanced',
                                       'Essentials',
                                       'Enterprise']),
            verify_ssl_cert=dict(required=False, default=True, type='bool'),
            wait=dict(required=False, default=False, type='bool'),
            wait_time=dict(required=False, default=120, type='int'),
            wait_poll_interval=dict(required=False, default=2, type='int')
        )
    )
    if not HAS_LIBCLOUD:
        module.fail_json(msg='libcloud is required for this module.')

    # set short vars for readability
    credentials = get_credentials()
    if credentials is False:
        module.fail_json("User credentials not found")
    user_id = credentials['user_id']
    key = credentials['key']
    region = 'dd-%s' % module.params['region']
    verify_ssl_cert = module.params['verify_ssl_cert']

    # Instantiate driver
    libcloud.security.VERIFY_SSL_CERT = verify_ssl_cert
    client = DimensionDataBackupDriver(user_id, key, region=region)

    handle_backups(module, client)

if __name__ == '__main__':
        main()
