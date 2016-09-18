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
module: dimensiondata_disk
short_description: Add/Remove/Modify Disks
description:
    - Add/Remove/Modify disks for a host in the Dimension Data Cloud.
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
  speed:
    description:
      - The speed of the disk.
    choices: [STANDARD, ECONOMY, HIGHPERFORMANCE]
    default: STANDARD
  size:
    description:
      - The size of the disk in GB
    required: false
  scsi_id:
    description:
      - The scsi_id for the disk.  Which slot the disk should be in.
    required: true
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
  wait_timeout:
    description:
      - Only applicable if wait is true.
      - This is the amount of time in seconds to wait
    required: false
    default: 300
  wait_poll_interval:
    description:
      - Only applicable if wait is true
      - The amount of time in between polling for task completion
      - This value should be no greater than wait_timeout
    required: false
    default: 2

author:
    - "Jeff Dunham (@jadunham1)"
'''

EXAMPLES = '''
# Note: These examples don't include authorization.
# You can set these by exporting DIDATA_USER and DIDATA_PASSWORD vars:
# export DIDATA_USER=<username>
# export DIDATA_PASSWORD=<password>

# Add a disk to slot 3 that is 40GB and ECONOMY speed

- dimensiondata_disk:
    node_ids:
      - '7ee719e9-7ae9-480b-9f16-c6b5de03463c'
    state: present
    scsi_id: 3
    size: 40
    speed: ECONOMY

# Modify a disk in slot 3 and wait up to 10 minutes for it to finish before returning success

- dimensiondata_disk:
    node_ids:
      - '7ee719e9-7ae9-480b-9f16-c6b5de03463c'
    state: present
    scsi_id: 3
    size: 45
    speed: HIGHSPEED
    wait: true
    wait_timeout: 600

# Remove a disk in slot 3
- dimensiondata_disk:
    node_ids:
      - '7ee719e9-7ae9-480b-9f16-c6b5de03463c'
    state: absent
    scsi_id: 3
'''

RETURN = '''
servers:
    description: the original List of servers/node_ids that were passed in
    returned: On success
    type: list
    contains: node_ids processed
'''

from ansible.module_utils.basic import *
from ansible.module_utils.dimensiondata import *
import time
try:
    from libcloud.common.dimensiondata import DimensionDataAPIException
    from libcloud.compute.drivers.dimensiondata import DimensionDataNodeDriver
    import libcloud.security
    HAS_LIBCLOUD = True
except:
    HAS_LIBCLOUD = False

# Get regions early to use in docs etc.
dd_regions = get_dd_regions()


def find_disk_from_scsi_id(node, scsi_id):
    found_disk = None
    for disk in node.extra['disks']:
        if disk.scsi_id == scsi_id:
            found_disk = disk
            break
    return found_disk


def handle_disk(module, client):
    changed = False
    state = module.params['state']
    scsi_id = module.params['scsi_id']
    speed = module.params['speed']
    size = module.params['size']
    for node_id in module.params['node_ids']:
        try:
            node = client.ex_get_node_by_id(node_id)
        except DimensionDataAPIException as e:
            module.fail_json("Problem finding information for node id: %s"
                             % e.msg)
        disk = find_disk_from_scsi_id(node, scsi_id)
        if disk is None and state == 'absent':
            continue
        elif disk is not None and state == 'absent':
            changed = True
            remove_disk_from_node(client, module, node, disk)
        elif disk is None and state == 'present':
            changed = True
            add_disk_to_node(client, module, node, size, speed, scsi_id)
        elif disk is not None and state == 'present':
            if disk.speed != speed:
                changed = True
                modify_speed_for_disk(client, module, node, disk, speed)
            if disk.size_gb < size:
                # If we have already made a change, we need to make sure that
                # we wait for the disk state to be normal before doing
                # another operation
                if changed is True:
                    wait_for_disk_state(client, module, node, disk)
                changed = True
                modify_size_for_disk(client, module, node, disk, size)
        else:
            module.fail_json(msg="Unhandled state")

    module.exit_json(changed=changed, msg='Disk operations successful',
                     servers=module.params['node_ids'])


def wait_for_disk_state(client, module, node, disk):
    cnt = 0
    timeout = module.params['wait_timeout']
    poll_interval = module.params['wait_poll_interval']
    state = module.params['state']
    while cnt < timeout / poll_interval:
        node = client.ex_get_node_by_id(node.id)
        found_disk = find_disk_from_scsi_id(node, disk.scsi_id)
        if state == 'absent':
            if found_disk is None:
                return
        elif state == 'present':
            if found_disk.state == 'NORMAL':
                return
        time.sleep(poll_interval)
        cnt += 1

    msg = 'Status check for object %s timed out' % (result)
    raise DimensionDataAPIException(code=object_state,
                                    msg=msg,
                                    driver=self.driver)


def remove_disk_from_node(client, module, node, disk):
    client.ex_remove_storage_from_node(node, disk.scsi_id)
    if module.params['wait'] is True:
        try:
            wait_for_disk_state(client, module, node, disk)
        except DimensionDataAPIException as e:
            module.fail_json(msg='Backup did not enable in time: %s' % e.msg)


def add_disk_to_node(client, module, node, size, speed, scsi_id):
    client.ex_add_storage_to_node(node, size, speed, scsi_id)
    if module.params['wait'] is True:
        try:
            node = client.ex_get_node_by_id(node.id)
            disk = find_disk_from_scsi_id(node, scsi_id)
            wait_for_disk_state(client, module, node, disk)
        except DimensionDataAPIException as e:
            module.fail_json(msg='Backup did not enable in time: %s' % e.msg)


def modify_speed_for_disk(client, module, node, disk, speed):
    client.ex_change_storage_speed(node, disk.id, speed)
    if module.params['wait'] is True:
        try:
            wait_for_disk_state(client, module, node, disk)
        except DimensionDataAPIException as e:
            module.fail_json(msg='Backup did not enable in time: %s' % e.msg)


def modify_size_for_disk(client, module, node, disk, size):
    client.ex_change_storage_size(node, disk.id, size)
    if module.params['wait'] is True:
        try:
            wait_for_disk_state(client, module, node, disk)
        except DimensionDataAPIException as e:
            module.fail_json(msg='Backup did not enable in time: %s' % e.msg)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            region=dict(default='na', choices=dd_regions),
            state=dict(default='present', choices=['present', 'absent']),
            node_ids=dict(required=True, type='list',
                          aliases=['server_id', 'server_ids', 'node_id']),
            scsi_id=dict(required=True, type='int'),
            speed=dict(default='STANDARD',
                       choices=['STANDARD',
                                'ECONOMY',
                                'HIGHPERFORMANCE']),
            size=dict(type='int'),
            verify_ssl_cert=dict(required=False, default=True, type='bool'),
            wait=dict(required=False, default=False, type='bool'),
            wait_timeout=dict(required=False, default=300, type='int'),
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
    client = DimensionDataNodeDriver(user_id, key, region=region)

    handle_disk(module, client)

if __name__ == '__main__':
        main()
