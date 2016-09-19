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
#   - Lamberto Diwa  <Lamberto.Diwa@nexusis.com>
#
from ansible.module_utils.basic import *
from ansible.module_utils.dimensiondata import *
try:
    from libcloud.common.dimensiondata import DimensionDataAPIException
    from libcloud.compute.types import Provider
    from libcloud.loadbalancer.types import Provider as LBProvider
    from libcloud.compute.providers import get_driver
    from libcloud.loadbalancer.providers import get_driver as get_lb_driver
    import libcloud.security
    HAS_LIBCLOUD = True
except:
    HAS_LIBCLOUD = False

# Get regions early to use in docs etc.
dd_regions = get_dd_regions()


DOCUMENTATION = '''
---
module: dimensiondata_nat
short_description: Create or Delete NAT rules.
description:
  - Create or Delete NAT rules.
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
  location:
    description:
      - The target datacenter.
    required: true
  network_domain:
    description:
      - The target network name or ID.
    required: true
  internal_ip:
    description:
      - The Internal IPv4 address.
    required: true
  external_ip:
    description:
      - The public/external IPv4 address.
      - This IP must exist already in your domain.
      - Note that external_ip is mutually exclusive with provision_external_ip
    required: false
    default: null
  provision_external_ip:
    description:
      - Auto allocates a public IP address.
      - Note that provision_external_ip is mutually exclusive with external_ip
    required: false
    default: true
  verify_ssl_cert:
    description:
      - Check that SSL certificate is valid.
    required: false
    default: true
  ensure:
    description:
      - present, absent
    choices: [present, absent]
    default: present
'''

EXAMPLES = '''
# Create NAT rule.
- dimensiondata_load_balancer:
    region: na
    location: NA12
    network_domain: test_network
    internal_ip: 10.0.0.45
    external_ip: 162.24.32.3
    ensure: present
# delete NAT rule.
- dimensiondata_load_balancer:
    region: na
    location: NA12
    network_domain: test_network
    internal_ip: 10.0.0.45
    external_ip: 162.24.32.3
    ensure: absent
'''

RETURN = '''
nat_rule:
    description: Dictionary describing the NAT rule.
    returned: On success when I(action) is 'present'.
    type: dictionary
    contains:
        id:
            description: NAT rule ID.
            type: string
            sample: "aaaaa000-a000-4050-a215-2808934ccccc"
        external_ip:
            description: External/public IP.
            type: string
            sample: "162.24.32.3"
        internal_ip:
            description: Internal/private IP.
            type: string
            sample: "10.0.0.45"
        status:
            description: Current status of NAT rule.
            type: string
            sample: NORMAL
'''


def get_nat_rule(module, client, network_domain, internal_ip):
    try:
        nat_rules = client.ex_list_nat_rules(network_domain)
    except DimensionDataAPIException as e:
        module.fail_json(msg="Unexpected API error: %s" % e)

    rules = filter(lambda x: x.internal_ip == internal_ip, nat_rules)
    if len(rules) > 0:
        return rules[0]
    else:
        return False


def nat_obj_to_dict(nat_obj):
    return {'id': nat_obj.id, 'external_ip': nat_obj.external_ip,
            'internal_ip': nat_obj.internal_ip, 'status': nat_obj.status}


def check_out_of_range(module, compute_driver, lb_driver, domain, ip):
    res = get_unallocated_public_ips(module, compute_driver, lb_driver, domain,
                                     reuse_free=True, count=0)

    if ip not in res['addresses']:
        module.fail_json(msg="IP address '%s'" % ip +
                         " is not associated with" +
                         " domain %s." % domain.id)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            region=dict(default='na', choices=dd_regions),
            location=dict(required=True, type='str'),
            network_domain=dict(required=True, type='str'),
            external_ip=dict(required=False, default=None, type='str'),
            internal_ip=dict(required=True, type='str'),
            ensure=dict(default='present', choices=['present', 'absent']),
            verify_ssl_cert=dict(required=False, default=True, type='bool'),
            provision_external_ip=dict(required=False, default=True,
                                       type='bool')
        ),
        mutually_exclusive=(["external_ip", "provision_external_ip"])
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
    location = module.params['location']
    network_domain = module.params['network_domain']
    external_ip = module.params['external_ip']
    internal_ip = module.params['internal_ip']
    verify_ssl_cert = module.params['verify_ssl_cert']
    ensure = module.params['ensure']

    # Instantiate client
    libcloud.security.VERIFY_SSL_CERT = verify_ssl_cert
    # Instantiate Load Balancer Driver
    DDLoadBalancer = get_lb_driver(LBProvider.DIMENSIONDATA)
    lb_client = DDLoadBalancer(user_id, key, region=region)
    # Instantiate compute driver
    DimensionData = get_driver(Provider.DIMENSIONDATA)
    client = DimensionData(user_id, key, region=region)

    # Get Network Domain Object
    net_domain = get_network_domain(client, network_domain, location)
    if net_domain is False:
        module.fail_json(msg="Network domain could not be found.")

    # Try to find NAT rule
    nat_rule = get_nat_rule(module, client, net_domain, internal_ip)
    # Process action
    if ensure == 'present':
        if nat_rule is False:
            # Get external IP
            if module.params['provision_external_ip'] is True and \
                    external_ip is None:
                # Get addresses
                res = get_unallocated_public_ips(module, client, lb_client,
                                                 net_domain, True, 1)
                ext_ip = res['addresses'][0]
            else:
                # Verify that provided IP exists.
                check_out_of_range(module, client, lb_client, net_domain,
                                   external_ip)
                ext_ip = external_ip
            try:
                res = client.ex_create_nat_rule(net_domain, internal_ip,
                                                ext_ip)
            except DimensionDataAPIException as e:
                module.fail_json(msg="Unexpected API error: %s" % e)
            # Sucess
            module.exit_json(changed=True, msg="Success.",
                             nat_rule=nat_obj_to_dict(res))
        else:
            module.exit_json(changed=False, msg="Nat rule already exists.",
                             nat_rule=nat_obj_to_dict(nat_rule))
    elif ensure == 'absent':
        if nat_rule is False:
            module.exit_json(changed=False, msg="NAT rule does not exist.")
        try:
            res = client.ex_delete_nat_rule(nat_rule)
        except DimensionDataAPIException as e:
            module.fail_json(msg="Unexpected error when attempting to delete" +
                                 " load balancer: %s" % e)
        if res is True:
            module.exit_json(changed=True, msg="NAT rule deleted.")
        else:
            module.fail_json(msg="Unexpected response while deleting NAT" +
                                 " rule: %s" % str(res))
    else:
        fail_json(msg="Requested ensure was " +
                  "'%s'. Status must be one of 'present', 'absent'." % ensure)

if __name__ == '__main__':
    main()
