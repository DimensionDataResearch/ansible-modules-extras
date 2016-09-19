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
#   - Jay Riddell   <Jay.Riddell@dimensiondata.com>
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
module: dimensiondata_get_unallocated_public_ips
short_description: Get specified number of free addresses.
description:
  - Get specified number of free addresses.
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
# Get 3 unallocated/free public IPs, reuse existing free.
- dimensiondata_get_unallocated_public_ips:
    region: na
    location: NA5
    network_domain: test_network
    count: 3
# Get 3 unallocated/free public IPs, do not reuse exisiting free.
- dimensiondata_get_unallocated_public_ips:
    region: na
    location: NA5
    network_domain: test_network
    count: 3
    reuse_free: false
'''

RETURN = '''
addresses:
    description: List of unalllocated public ips.
    returned: On success.
    type: list
    contains:
      - description: IP address.
        type: list
        sample: ['168.128.2.100', '168.128.2.101']
'''


def allocate_public_ip_block(module, driver, network_domain):
    try:
        return driver.ex_add_public_ip_block_to_network_domain(network_domain)
    except DimensionDataAPIException as e:
        module.fail_json(msg="Failed to allocate public ip block:" +
                             "%s" % e.message)


def delete_public_ip_block(module, driver, network_domain, block_id=False,
                           base_ip=False):

    # Block ID given, try to use it.
    if block_id is not 'False':
        block = False
        try:
            block = driver.ex_get_public_ip_block(block_id)
        except DimensionDataAPIException as e:
            # 'UNEXPECTED_ERROR' should be removed once upstream bug is fixed.
            # Currently any call to ex_get_public_ip_block where the block does
            # not exist will return UNEXPECTED_ERROR rather than
            # 'RESOURCE_NOT_FOUND'.
            if e.code == "RESOURCE_NOT_FOUND" or e.code == 'UNEXPECTED_ERROR':
                module.exit_json(changed=False, msg="Public IP Block does " +
                                 "not exist")
            else:
                module.fail_json(msg="Unexpected error while retrieving " +
                                     "block: %s" % e.code)
    # Block ID not given, try to use base_ip.
    else:
        blocks = list_public_ip_blocks(module, driver, network_domain)
        if blocks is not False:
            block = filter(lambda x: x.base_ip == base_ip, blocks)[0]
        else:
            module.exit_json(changed=False, msg="IP block starting with " +
                             "'%s' does not exist." % base_ip)
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
    reuse_free = module.params['reuse_free']
    count = module.params['count']
    verify_ssl_cert = module.params['verify_ssl_cert']

    # Instantiate driver
    libcloud.security.VERIFY_SSL_CERT = verify_ssl_cert
    DimensionData = get_driver(Provider.DIMENSIONDATA)
    driver = DimensionData(user_id, key, region=region)

    # get the network domain object
    network_domain_obj = get_network_domain(driver, network_domain, location)
    # Get addresses
    res = get_unallocated_public_ips(module, driver, network_domain_obj,
                                     reuse_free, count)
    module.exit_json(changed=res['changed'], msg=res['msg'],
                     addresses=res['addresses'])


if __name__ == '__main__':
    main()
