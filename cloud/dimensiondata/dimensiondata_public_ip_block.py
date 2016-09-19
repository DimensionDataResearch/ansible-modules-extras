#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 Dimension Data
#
# This module is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this software.  If not, see <http://www.gnu.org/licenses/>.
#
# Authors:
#   - Aimon Bustardo <aimon.bustardo@dimensiondata.com>
#   - Bert Diwa      <Lamberto.Diwa@dimensiondata.com>
#
from ansible.module_utils.basic import *
from ansible.module_utils.dimensiondata import *
try:
    from libcloud.common.dimensiondata import DimensionDataAPIException
    from libcloud.compute.types import Provider
    from libcloud.compute.providers import get_driver
    import libcloud.security
    HAS_LIBCLOUD = True
except:
    HAS_LIBCLOUD = False

# Get regions early to use in docs etc.
dd_regions = get_dd_regions()

DOCUMENTATION = '''
---
module: dimensiondata_public_ip_block
short_description: Create, delete and list public IP blocks.
description:
  - Get specified number of free addresses;
  - Provision to reach requested number.
version_added: "2.2"
author: 'Aimon Bustardo (@aimonb)'
options:
  region:
    description:
      - The target region.
    choices:
      - Regions choices are defined in Apache libcloud project [libcloud/common/dimensiondata.py]
      - Regions choices are also listed in https://libcloud.readthedocs.io/en/latest/compute/drivers/dimensiondata.html
      - Note that the region values are available as list from dd_regions().
      - Note that the default value "na" stands for "North America".  The code prepends 'dd-' to the region choice.
    default: na
  network_domain:
    description:
      - The target network.
    required: true
  location:
    description:
      - The target datacenter.
    required: true
  block_id:
    description:
      - The id of the IP Address block.
      - This or base_ip is required when releasing existing block.
    required: false
    default: false
  base_ip:
    description:
      - The first IP address of the network block.
      - This or block_id is required when releasing existing block.
    required: false
    default: false
  action:
    description:
      - Get, add or delete public IP blocks,
    choices: [get, add, delete]
    required: true
  count:
    description:
      - Number of public IPs needed.
    required: false
    default: 1
  reuse_free:
    description:
      - If true existing free IPs will be used to fufill count.
    required: false
    default: true
  verify_ssl_cert:
    description:
      - Check that SSL certificate is valid.
    required: false
    default: true
'''

EXAMPLES = '''
# Add public IP block
- dimensiondata_public_ip_block:
    region: na
    location: NA5
    network_domain: test_network
    action: add
# Delete public IP Block by base IP.
- dimensiondata_public_ip_block:
    region: na
    location: NA5
    network_domain: test_network
    action: delete
    base_ip: 168.128.2.100
# Delete public IP Block by block ID.
- dimensiondata_public_ip_block:
    region: na
    location: NA5
    network_domain: test_network
    action: delete
    block_id: 6288ab1c-0000-0000-0000-b8ca3a5d9ef8
'''

RETURN = '''
public_ip_block:
    description: List of Dictionaries describing the public IP blocks.
    returned: On success when I(action) is 'add'
    type: dictionary
    contains:
      id:
          description: Block ID.
          type: string
          sample: "8c787000-a000-4050-a215-280893411a7d"
      addresses:
          description: IP address.
          type: list
          sample: ['168.128.2.100', '168.128.2.101']
      status:
          description: Status of IP block.
          type: string
          sample: NORMAL
'''


def public_ip_block_to_dict(block):
    addresses = expand_ip_block(block)
    return {'id': block.id, 'addresses': addresses, 'status': block.status}


def add_public_ip_block(module, driver, network_domain):
    try:
        block = driver.ex_add_public_ip_block_to_network_domain(network_domain)
        module.exit_json(changed=True, msg="Success!",
                         public_ip_block=public_ip_block_to_dict(block))
    except DimensionDataAPIException as e:
        module.fail_json(msg="Failed to add public IP block: %s" % str(e))


def delete_public_ip_block(module, driver, network_domain, block_id=False,
                           base_ip=False):
    # Get the block
    block = get_public_ip_block(module, driver, network_domain, block_id,
                                base_ip)
    # Now that we have the block, try to dselete it.
    if block is not False:
        try:
            driver.ex_delete_public_ip_block(block)
            module.exit_json(changed=True, msg="Deleted!")
        except DimensionDataAPIException as e:
            module.fail_json(msg="Error deleting Public Ip Block: %s" % e)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            region=dict(default='na', choices=dd_regions),
            network_domain=dict(required=True, type='str'),
            location=dict(required=True, type='str'),
            base_ip=dict(default=False, type='str'),
            block_id=dict(default=False, type='str'),
            action=dict(required=True, choices=['get', 'add', 'delete']),
            count=dict(required=False, default=1, type='int'),
            reuse_free=dict(required=False, default=True, type='bool'),
            verify_ssl_cert=dict(required=False, default=True, type='bool')
        )
    )

    if not HAS_LIBCLOUD:
        module.fail_json(msg='libcloud is required for this module.')

    # set short vars for readability
    credentials = get_credentials()
    if credentials is False:
        module.fail_json(msg="User credentials not found")
    user_id = credentials['user_id']
    key = credentials['key']
    region = 'dd-%s' % module.params['region']
    network_domain = module.params['network_domain']
    location = module.params['location']
    base_ip = module.params['base_ip']
    block_id = module.params['block_id']
    verify_ssl_cert = module.params['verify_ssl_cert']
    action = module.params['action']

    # Instantiate driver
    libcloud.security.VERIFY_SSL_CERT = verify_ssl_cert
    DimensionData = get_driver(Provider.DIMENSIONDATA)
    driver = DimensionData(user_id, key, region=region)

    # get the network domain object
    network_domain_obj = get_network_domain(driver, network_domain, location)
    if action == 'get':
        block = get_public_ip_block(module, driver, network_domain_obj,
                                    block_id)
        if block is not False:
            module.exit_json(changed=False,
                             msg="Sucessfully retreived block details",
                             public_ip_block=module.params['block_id'])

    elif action == 'delete':
        delete_public_ip_block(module, driver, network_domain_obj, block_id,
                               base_ip)
    elif action == 'add':
        add_public_ip_block(module, driver, network_domain_obj)
    else:
        module.fail_json(msg="Unexpected action " +
                             "'%s' is not 'delete' or 'add'" % action)

if __name__ == '__main__':
    main()
