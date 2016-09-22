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
module: dimensiondata_backup client
short_description: add/delete backup client for a host
description:
    - Add or delete a backup client for a host in the Dimension Data Cloud
notes:
    - If given state = 'present' and backup client is found, it is not changed.
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
      - A list of server ids to work on
    required: true
    default: null
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
  client_type:
    description:
      - The service plan for backups.
    required: true
    choices: [FA.Win, FA.AD, FA.Linux, MySQL, PostgreSQL]
  verify_ssl_cert:
    description:
      - Check that SSL certificate is valid.
    required: false
    default: true
  schedule_policy:
    description:
      - The schedule policy for backups.
    choices: [12AM - 6AM, 6AM - 12PM, 12PM - 6PM, 6PM - 12AM]
  storage_policy:
    description:
      - The storage policy for backups.
    required: true
    choices: ['14 Day Storage Policy', '30 Day Storage Policy',
              '60 Day Storage Policy', '90 Day Storage Policy',
              '180 Day Storage Policy', '1 Year Storage Policy',
              '2 Year Storage Policy', '3 Year Storage Policy',
              '4 Year Storage Policy', '5 Year Storage Policy',
              '6 Year Storage Policy', '7 Year Storage Policy']
  notify_email:
    description:
      - The email to notify for a trigger.
    default: nobody@example.com
  notify_trigger:
    description:
      - When to send an email to the notify_email.
    default: ON_FAILURE
    choices: [ON_FAILURE, ON_SUCCESS]
author:
    - "Jeff Dunham (@jadunham1)"
'''

EXAMPLES = '''
# Note: These examples don't include authorization.
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
    verify_Sssl_cert: no
'''

RETURN = '''
servers:
  description: list of servers this worked on
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

# Get regions early to use in docs etc.
dd_regions = get_dd_regions()


def get_backup_client(details, client_type):
    if len(details.clients) > 0:
        for client in details.clients:
            if client.type.type == client_type:
                return client
    return None


def _backup_client_obj_to_dict(backup_client):
    backup_client_dict = {}
    backup_client_dict['id'] = backup_client.id
    backup_client_dict['client_type'] = backup_client.type.type
    backup_client_dict['storage_policy'] = backup_client.storage_policy
    backup_client_dict['schedule_policy'] = backup_client.schedule_policy
    backup_client_dict['download_url'] = backup_client.download_url
    return backup_client_dict


def get_backup_details_for_host(module, client, server_id):
    try:
        backup_details = client.ex_get_backup_details_for_target(server_id)
    except DimensionDataAPIException as e:
        if e.msg.endswith('has not been provisioned for backup'):
            module.fail_json(msg="Server %s does not have backup enabled"
                             % server_id)
        else:
            module.fail_json(msg="Problem finding backup info for host: %s"
                             % e.msg)
    return backup_details


def handle_backup_client(module, client):
    changed = False
    state = module.params['state']
    client_type = module.params['client_type']
    server_clients_return = {}

    for server_id in module.params['node_ids']:
        backup_details = get_backup_details_for_host(module, client, server_id)
        backup_client = get_backup_client(backup_details, client_type)
        if state == 'absent' and backup_client is None:
            continue
        elif state == 'absent' and backup_client is not None:
            changed = True
            remove_client_from_server(client, module, server_id, backup_client)
        elif state == 'present' and backup_client is None:
            changed = True
            add_client_to_server(client, module, server_id)
            backup_details = get_backup_details_for_host(module, client, server_id)
            backup_client = get_backup_client(backup_details, client_type)
            server_clients_return[server_id] = \
                _backup_client_obj_to_dict(backup_client)
        elif state == 'present' and backup_client is not None:
            existing_service_plan = backup_details.service_plan
            modify_backup_for_server(
                client, module, server_id, existing_service_plan)
            # needed? backup_details = get_backup_details_for_host(module, client, server_id)
            server_clients_return[server_id] = \
                _backup_client_obj_to_dict(backup_client)
        else:
            module.fail_json(msg="Unhandled state")

    module.exit_json(changed=changed, msg='Success',
                     backups=server_clients_return)


def remove_client_from_server(client, module, server_id, backup_client):
    try:
        client.ex_remove_client_from_target(server_id, backup_client)
    except DimensionDataAPIException as e:
        module.fail_json(msg="Failed removing client from host: %s" % e.msg)


def add_client_to_server(client, module, server_id):
    def getkeyordie(k):
        v = module.params[k]
        if v is None:
            module.fail_json(msg='Need key %s for adding a client' % k)
        return v

    storage_policy = getkeyordie('storage_policy')
    schedule_policy = getkeyordie('schedule_policy')
    client_type = getkeyordie('client_type')
    trigger = module.params['notify_trigger']
    notify_email = module.params['notify_email']

    try:
        backup_client = client.ex_add_client_to_target(
            server_id, client_type, storage_policy,
            schedule_policy, trigger, notify_email
        )
    except DimensionDataAPIException as e:
        module.fail_json(msg="Failed adding client to host: %s" % e.msg)
    return backup_client


def modify_backup_for_server(client, module, server_id, service_plan):
    extra = {'servicePlan': service_plan}
    client.update_target(server_id, extra=extra)


def _storage_policy_choices():
    storage_policy_lengths = ['14 Day', '30 Day', '60 Day', '90 Day',
                              '180 Day', '1 Year', '2 Year', '3 Year',
                              '4 Year', '5 Year', '6 Year', '7 Year']
    storage_policy_choices = []
    for storage_policy_length in storage_policy_lengths:
        storage_policy_choices.append(
            "%s Storage Policy" % storage_policy_length
        )
        storage_policy_choices.append(
            "%s Storage Policy + Secondary Copy" % storage_policy_length
        )
    return storage_policy_choices


def main():
    module = AnsibleModule(
        argument_spec=dict(
            region=dict(default='na', choices=dd_regions),
            state=dict(default='present', choices=['present', 'absent']),
            node_ids=dict(required=True, type='list',
                          aliases=['server_id', 'server_ids', 'node_id']),
            client_type=dict(required=True,
                             choices=['FA.Win', 'FA.AD', 'FA.Linux',
                                      'MySQL', 'PostgreSQL']),
            schedule_policy=dict(choices=['12AM - 6AM', '6AM - 12PM',
                                          '12PM - 6PM', '6PM - 12AM']),
            storage_policy=dict(choices=_storage_policy_choices()),
            notify_email=dict(required=False, default='nobody@example.com'),
            notify_trigger=dict(required=False, default='ON_FAILURE',
                                choices=['ON_FAILURE', 'ON_SUCCESS']),
            verify_ssl_cert=dict(required=False, default=True, type='bool'),
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

    handle_backup_client(module, client)

if __name__ == '__main__':
        main()
