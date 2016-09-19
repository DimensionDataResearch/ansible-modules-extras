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
    from libcloud.loadbalancer.base import Member, Algorithm
    import libcloud.security
    HAS_LIBCLOUD = True
except:
    HAS_LIBCLOUD = False

# Get regions early to use in docs etc.
dd_regions = get_dd_regions()

# Virtual Listener Protocols
protocols = ['any', 'tcp', 'udp', 'http', 'ftp', 'smtp']
# Load Balancing algorithms
lb_algs = ['ROUND_ROBIN', 'LEAST_CONNECTIONS',
           'SHORTEST_RESPONSE', 'PERSISTENT_IP']

DOCUMENTATION = '''
---
module: dimensiondata_load_balancer
description:
  - Create, update or delete load balancers.
short_description: Create, update or delete load balancers.
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
      - The target network name or UUID/ID for the network.
    required: true
    default: None
  name:
    description:
      - Name of the Load Balancer.
    required: true
  port:
    description:
        - An integer in the range of 1-65535.
        - If not supplied, it will be taken to mean "Any Port"
    required: false
    default: None
  listener_ip_address:
    description:
        - Must be a valid IPv4 in dot-decimal notation (x.x.x.x).
        - If not provided (or == ""), value will be auto-provisioned
    required: false
    default: None
  protocol:
    description:
        - Choice of an enumeration of protocols
    required: false
    choices: [any, tcp, udp, http, ftp, smtp]
    default: http
  algorithm:
    description:
        - Choice of an enumerations of algorithms
    required: false
    choices: [ROUND_ROBIN, LEAST_CONNECTIONS, SHORTEST_RESPONSE, PERSISTENT_IP]
    default: ROUND_ROBIN
  members:
    description:
      - List of members as dictionaries.
      - See Examples for format.
    required: true
  verify_ssl_cert:
    description:
      - Check that SSL certificate is valid.
    required: false
    default: true
  ensure:
    description:
      - present, absent.
    choices: [present, absent]
    default: present
'''


EXAMPLES = '''
# Construct Load Balancer
- dimensiondata_load_balancer:
    region: na
    location: NA5
    network_domain: test_network
    name: web_lb01
    port: 80
    protocol: http
    algorithm: ROUND_ROBIN
    members:
        - name: webserver1
          port: 8080
          ip: 192.168.0.11
        - name: webserver3
          port: 8080
          ip: 192.168.0.13
    ensure: present
'''

RETURN = '''
load_balancer:
    description: Dictionary describing the Load Balancer.
    returned: On success when I(ensure) is 'present'
    type: dictionary
    contains:
        id:
            description: Load Balancer ID.
            type: string
            sample: "aaaaa000-a000-4050-a215-2808934ccccc"
        name:
            description: Virtual Listener name.
            type: string
            sample: "My Virtual Listener"
        state:
            description: state of the Load Balancer
            type: integer
            sample: 0=RUNNING,  1=PENDING, 2=UNKNOWN, 3=ERROR, 4=DELETED
        ip:
            description: Listener IP of Load Balancer.
            type: string
            sample: 168.128.1.1
        port:
            description: Port of Load Balancer listener (if port was supplied; else = 'Any Port')
            type: integer
            sample: 80
'''


def get_balancer(module, lb_driver, name):
    if is_uuid(name):
        try:
            return lb_driver.get_balancer(name)
        except DimensionDataAPIException as e:
            if e.code == 'RESOURCE_NOT_FOUND':
                return False
            else:
                module.fail_json("Unexpected API error code: %s" % e.code)
    else:
        balancers = list_balancers(module, lb_driver)
        found_balancers = filter(lambda x: x.name == name, balancers)
        if len(found_balancers) > 0:
            lb_id = found_balancers[0].id
            try:
                return lb_driver.get_balancer(lb_id)
            except DimensionDataAPIException as e:
                module.fail_json(msg="Unexpected error while retrieving load" +
                                 " balancer details with id %s" % lb_id)
        else:
            return False


def balancer_obj_to_dict(lb_obj):
    return {
        'id': lb_obj.id,
        'name': lb_obj.name,
        'state': int(lb_obj.state),
        'ip': lb_obj.ip,
        'port': 'Any Port' if lb_obj.port is None else int(lb_obj.port)
    }


def create_balancer(module, lb_driver, cp_driver, network_domain):
    # Build mebers list
    members_list = [Member(m['name'], m['ip'], m.get('port'))
                    for m in module.params['members']]

    listener_ip_address = module.params['listener_ip_address']
    if not(listener_ip_address and listener_ip_address.strip()):
        # Get addresses
        res = get_unallocated_public_ips(module, cp_driver, lb_driver,
                                         network_domain, True, 1)
        listener_ip_address = res['addresses'][0]

    try:
        balancer = lb_driver.create_balancer(
            module.params['name'],
            module.params['port'],
            module.params['protocol'],
            getattr(Algorithm, module.params['algorithm']),
            members_list,
            ex_listener_ip_address=listener_ip_address)
        module.exit_json(changed=True, msg="Success.",
                         load_balancer=balancer_obj_to_dict(balancer))
    except DimensionDataAPIException as e:
        module.fail_json(msg="Error while creating load balancer: %s" % e)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            region=dict(default='na', choices=dd_regions),
            location=dict(required=True, type='str'),
            network_domain=dict(required=True, type='str'),
            name=dict(required=True, type='str'),
            port=dict(default=None, type='int'),
            protocol=dict(default='http', choices=protocols),
            algorithm=dict(default='ROUND_ROBIN', choices=lb_algs),
            members=dict(default=None, type='list'),
            ensure=dict(default='present', choices=['present', 'absent']),
            verify_ssl_cert=dict(required=False, default=True, type='bool'),
            listener_ip_address=dict(required=False, default=None, type='str')
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
    name = module.params['name']
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
    if ensure == 'present':
        balancer = get_balancer(module, lb_driver, name)
        if balancer is False:
            create_balancer(module, lb_driver, cp_driver, net_domain)
        else:
            module.exit_json(changed=False, msg="Load balancer already " +
                             "exists.", load_balancer=balancer_obj_to_dict(
                                 balancer))
    elif ensure == 'absent':
        balancer = get_balancer(module, lb_driver, name)
        if balancer is False:
            module.exit_json(changed=False, msg="Load balancer with name " +
                             "%s does not exist" % name)
        try:
            pool_id = balancer.extra.get('pool_id')
            if pool_id:
                pool = lb_driver.ex_get_pool(pool_id)

            res = lb_driver.destroy_balancer(balancer)

            if pool:
                members = lb_driver.ex_get_pool_members(pool_id)
                for member in members:
                    lb_driver.ex_destroy_pool_member(member, destroy_node=True)
                lb_driver.ex_destroy_pool(pool)

            module.exit_json(changed=True, msg="Load balancer deleted. " +
                             "Status: %s" % res)
        except DimensionDataAPIException as e:
            module.fail_json(msg="Unexpected error when attempting to delete" +
                             " load balancer: %s" % e)
    else:
        fail_json(msg="Requested ensure was " +
                  "'%s'. Status must be one of 'present', 'absent'." % ensure)

if __name__ == '__main__':
    main()
