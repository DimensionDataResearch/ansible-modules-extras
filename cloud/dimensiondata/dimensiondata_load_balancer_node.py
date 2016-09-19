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
#   - Jay Riddell    <Jay.Riddell@dimensiondata.com>
#
from ansible.module_utils.basic import *
from ansible.module_utils.dimensiondata import *
try:
    from libcloud.common.dimensiondata import DimensionDataAPIException
    from libcloud.loadbalancer.types import Provider as LBProvider
    from libcloud.compute.types import Provider as ComputeProvider
    from libcloud.loadbalancer.providers import get_driver as get_lb_driver
    from libcloud.compute.providers import get_driver as get_cp_driver
    import libcloud.security
    HAS_LIBCLOUD = True
except:
    HAS_LIBCLOUD = False

# Get regions early to use in docs etc.
dd_regions = get_dd_regions()

DOCUMENTATION = '''
---
module: dimensiondata_load_balancer_node
description:
  - Create, update or delete a Load Balancer Node.
short_description: Create, update or delete load balancer nodes.
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
  name:
    description:
      - Name of the node.
    required: true
  description:
    description:
      - Description of the node.
    required: false
    default: null
  ip:
    description:
        - Node IP address.
    required: false
    default: null
  connection_limit:
    description:
        - Maximum number of concurrent connections per second.
    required: false
    default: 2000
  connection_rate_limit:
    description:
        - Maximum number of concuurrent sessions.
    required: false
    default: 25000
  verify_ssl_cert:
    description:
      - Check that SSL certificate is valid.
    required: false
    default: true
  ensure:
    description:
      - present, absent.
    choices: ['present', 'absent']
    default: present
'''


EXAMPLES = '''
# Construct Load Balancer Node
- dimensiondata_load_balancer_node:
    region: na
    location: NA5
    network_domain: test_network
    name: web_lb01_node01
    ensure: present
'''


RETURN = '''
load_balancer_node:
    description: Dictionary describing the Load Balancer Node.
    returned: On success when I(ensure) is 'present'
    type: dictionary
    contains:
        id:
            description: Load Balancer Node ID.
            type: string
            sample: "aaaaa000-a000-4050-a215-2808934ccccc"
        name:
            description: Node name.
            type: string
            sample: "lb01_node01"
        ip:
            description: IP address of node.
            type: string
            sample: 10.0.0.4
        description:
            description: Node description.
            type: string
            sample: My web node 1.
        connection_limit:
            description: Maximum number of concurrent connections per second.
            type: integer
            sample: 2000
        connection_rate_limit:
            description: Maximum number of concurrent sessions.
            type: integer
            sample: 25000
        status:
            description: Node status.
            type: integer
            sample: NORMAL
'''


def list_nodes(module, lb_driver):
    try:
        nodes = lb_driver.ex_get_nodes()
        return nodes
    except DimensionDataAPIException as e:
        module.fail_json(msg="Failed to retrieve a list of nodes: %s" % e)


def node_obj_to_dict(node_obj):
    return {
        'id': node_obj.id,
        'name': node_obj.name,
        'ip': node_obj.ip,
        'connection_limit': node_obj.connection_limit,
        'connection_rate_limit': node_obj.connection_rate_limit,
        'status': node_obj.status
    }


def create_node(module, lb_driver, domain_id):
    try:
        node = lb_driver.ex_create_node(domain_id, module.params['name'],
                                        module.params['ip'],
                                        module.params['description'],
                                        module.params['connection_limit'],
                                        module.params['connection_rate_limit'])
        module.exit_json(changed=True, msg="Success.",
                         load_balancer_node=node_obj_to_dict(node))
    except DimensionDataAPIException as e:
        module.fail_json(msg="Error while creating load balancer node: %s" % e)


def destroy_node(module, lb_driver, node):
    try:
        res = lb_driver.ex_destroy_node(node.id)
        module.exit_json(changed=True, msg="Load balancer node deleted. " +
                         "Status: %s" % res)
    except DimensionDataAPIException as e:
        module.fail_json(msg="Faield to delete/destroy node '%s'" % node.name +
                         ': %s' % e)


def main():

    module = AnsibleModule(
        argument_spec=dict(
            region=dict(default='na', choices=dd_regions),
            location=dict(required=True, type='str'),
            network_domain=dict(required=True, type='str'),
            name=dict(required=True, type='str'),
            description=dict(default=None, type='str'),
            ip=dict(default=None, type='str'),
            connection_limit=dict(required=False, default=2000, type='int'),
            connection_rate_limit=dict(required=False, default=25000,
                                       type='int'),
            ensure=dict(default='present', choices=['present', 'absent']),
            verify_ssl_cert=dict(required=False, default=True, type='bool'),
        ),
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
    verify_ssl_cert = module.params['verify_ssl_cert']
    ensure = module.params['ensure']

    # -------------------
    # Instantiate drivers
    # -------------------
    libcloud.security.VERIFY_SSL_CERT = verify_ssl_cert
    # Instantiate Load Balancer Driver
    DDLoadBalancer = get_lb_driver(LBProvider.DIMENSIONDATA)
    lb_driver = DDLoadBalancer(user_id, key, region=region)
    # Instantiate Compute Driver
    DDCompute = get_cp_driver(ComputeProvider.DIMENSIONDATA)
    cp_driver = DDCompute(user_id, key, region=region)

    # Get Network Domain Object
    net_domain = get_network_domain(cp_driver, network_domain, location)
    if net_domain is False:
        module.fail_json(msg="Network domain could not be found.")

    # Set Load Balancer Driver network domain
    try:
        lb_driver.ex_set_current_network_domain(net_domain.id)
    except:
        module.fail_json(msg="Current network domain could not be set.")

    # Process action
    node = get_node_by_name_and_ip(module, lb_driver, module.params['name'],
                                   module.params['ip'])
    if ensure == 'present':
        if node is None:
            create_node(module, lb_driver, net_domain.id)
        else:
            module.exit_json(changed=False, msg="Load balancer node already " +
                             "exists.",
                             load_balancer_node=node_obj_to_dict(node))
    elif ensure == 'absent':
        if node is None:
            module.exit_json(changed=False, msg="Load balancer node with " +
                             "name %s does not exist." % module.params['name'])
        else:
            destroy_node(module, lb_driver, node)
    else:
        fail_json(msg="Requested ensure was " +
                  "'%s'. Status must be one of 'present', 'absent'." % ensure)

if __name__ == '__main__':
    main()
