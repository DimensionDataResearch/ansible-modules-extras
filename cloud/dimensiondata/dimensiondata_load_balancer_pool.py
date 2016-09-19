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

# Virtual Listener Protocols
protocols = ['any', 'tcp', 'udp', 'http', 'ftp', 'smtp']
# Load Balancing algorithms
lb_algs = ['ROUND_ROBIN', 'LEAST_CONNECTIONS',
           'SHORTEST_RESPONSE', 'PERSISTENT_IP']

DOCUMENTATION = '''
---
module: dimensiondata_load_balancer_pool
description:
  - Create, update or delete .
short_description: Create, update or delete load balancer pools.
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
      - The target network name or target network ID.
    required: true
  name:
    description:
      - Name of the Load Balancer Pool.
    required: true
  description:
    description:
      - Description of the Load Balancer Pool.
    required: false
    default: null
  load_balance_method:
    description:
        - The load balancer algorithm (required).
    required: False
    choices:
        - 'ROUND_ROBIN'
        - 'LEAST_CONNECTIONS'
        - 'SHORTEST_RESPONSE'
        - 'PERSISTENT_IP'
    default: ROUND_ROBIN
  health_monitor_1:
    description:
        - Health monitor 1.
    required: false
    default: null
    choices: ['Http', 'Https', 'Tcp', 'TcpHalfOpen', 'Udp']
  health_monitor_2:
    description:
        - Health monitor 2.
    required: false
    default: null
    choices: ['Http', 'Https', 'Tcp', 'TcpHalfOpen', 'Udp']
  service_down_action:
    description:
      -  What to do when node is unavailable NONE, DROP or RESELECT.
    required: false
    choices: ['NONE', 'DROP', 'RESELECT']
    default: 'NONE'
  slow_ramp_time:
    description:
        - Number of seconds to stagger ramp up of nodes.
    required: false
    default: 30
  members:
    description:
      - Nested dictionaries of pool members name ip and port.
      - "In format of {<name>: {'ip': <ip>, 'port': <port>}, ...}"
    required: false
    default: null
  destroy_nodes:
    description:
      - Destroy nodes when removing members.
    required: false
    type: bool
    default: true
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
# Construct Load Balancer Pool
- dimensiondata_load_balancer_pool:
    region: na
    location: NA5
    network_domain: test_network
    name: web_lb01_pool01
    load_balance_method: ROUND_ROBIN
    members:
        node01:
            ip: 10.0.0.4
            port: 80
        node02
            ip: 10.0.0.5
            port: 80
        10.0.0.6
            ip: 10.0.0.6
            port: 8080
    ensure: present
# Remove one member from same Load Balancer Pool
- dimensiondata_load_balancer_pool:
    region: na
    location: NA5
    network_domain: 09bb085f-c1cb-5c59-aa1d-53b3d8be214c
    name: web_lb01_pool01
    load_balance_method: ROUND_ROBIN
    members:
        node01:
            ip: 10.0.0.4
            port: 80
        node02:
            ip: 10.0.0.5
            port: 80
    ensure: present
# Delete Pool
- dimensiondata_load_balancer_pool:
    region: na
    location: NA5
    network_domain: test_network
    name: web_lb01_pool01
    ensure: absent
'''


RETURN = '''
load_balancer_pool:
    description: Dictionary describing the Load Balancer Pool.
    returned: On success when I(ensure) is 'present'
    type: dictionary
    contains:
        id:
            description: Load Balancer Pool ID.
            type: string
            sample: "aaaaa000-a000-4050-a215-2808934ccccc"
        name:
            description: Pool name.
            type: string
            sample: "lb01_pool01"
        load_balance_method:
            description: Member load balancing method.
            type: string
            sample: ROUND_ROBIN
        slow_ramp_time:
            description: Number of seconds to stagger ramp up of nodes.
            type: integer
            sample: 30
        service_down_action:
            description: What to do when node is unavailable.
            type: string
            sample: RESELECT
        health_monitor_id:
            description: ID of chosen health monitor.
            type: string
            example: None
        members:
            description: List of attached nodes and their ports.
            type: list
            example:
                node01:
                    id: b78dfbf8-ff7c-48c3-8fc9-aaaaaaaaaaaa
                    node_id: 618f5527-3d83-4539-aaaaaaaaaaaa
                    ip: 192.168.0.4
                    port: 80
                    status: NORMAL
                node02:
                    id: b78dfbf8-ff7c-48c3-8fc9-bbbbbbbbbbbb
                    node_id: 618f5527-3d83-4539-bbbbbbbbbbbb
                    ip: 192.168.0.5
                    port: 80
                    status: NORMAL
        status:
            description: Load balancer pool status.
            type: integer
            sample: NORMAL
'''


def list_pools(module, lb_driver):
    try:
        pools = lb_driver.ex_get_pools()
        return pools
    except DimensionDataAPIException as e:
        module.fail_json(msg="Failed to retrieve a list of pools: %s" % e)


def get_pool(module, lb_driver):
    if is_uuid(module.params['name']):
        try:
            return lb_driver.ex_get_pool(module.params['name'])
        except DimensionDataAPIException as e:
            if e.code == 'RESOURCE_NOT_FOUND':
                return False
            else:
                module.fail_json("Unexpected API error code: %s" % e.code)
    else:
        pools = list_pools(module, lb_driver)
        found_pools = filter(lambda x: x.name == module.params['name'], pools)
        if len(found_pools) > 0:
            pool_id = found_pools[0].id
            try:
                return lb_driver.ex_get_pool(pool_id)
            except DimensionDataAPIException as e:
                module.fail_json(msg="Unexpected error while retrieving load" +
                                 " balancer pool details with id" +
                                 " %s" % pool_id)
        else:
            return False


def pool_obj_to_dict(pool_obj, members):
    return {
        'id': pool_obj.id,
        'name': pool_obj.name,
        'description': pool_obj.description,
        'status': pool_obj.status,
        'load_balance_method': pool_obj.load_balance_method,
        'slow_ramp_time': pool_obj.slow_ramp_time,
        'service_down_action': pool_obj.service_down_action,
        'health_monitor_id': pool_obj.health_monitor_id,
        'members': pool_members_to_dict(members)
    }


def pool_members_to_dict(members):
    members_dict = {}
    for member in members:
        members_dict[member.name] = {'id': member.node_id,
                                     'ip': member.ip,
                                     'port': member.port
                                     }
    return members_dict


def to_health_monitor(module, domain_id, lb_driver, monitor_txt):
    mon_string = 'CCDEFAULT.%s' % monitor_txt
    try:
        monitors = lb_driver.ex_get_default_health_monitors(domain_id)
        monitor_list = filter(lambda x: x.name == mon_string, monitors)
        if len(monitor_list) > 0:
            return monitor_list[0]
        else:
            module.fail_json(msg="Health monitor '%s' not found." % mon_string)
    except DimensionDataAPIException as e:
        module.fail_json(msg='Failed to get monitor list: %s' % e)


def create_pool(module, lb_driver, domain_id):
    # Build monitors
    monitors = [to_health_monitor(module, domain_id, lb_driver,
                module.params['health_monitor_1']),
                to_health_monitor(module, domain_id, lb_driver,
                module.params['health_monitor_2'])
                ]
    try:
        pool = lb_driver.ex_create_pool(domain_id, module.params['name'],
                                        module.params['load_balance_method'],
                                        module.params['description'],
                                        monitors,
                                        module.params['service_down_action'],
                                        module.params['slow_ramp_time'])
        return pool
    except DimensionDataAPIException as e:
        module.fail_json(msg="Error while creating load balancer pool: %s" % e)


def quiesce_members(module, lb_driver, pool):
    changed = False
    # Desired members
    desired_members = module.params['members']
    # Get current list of members
    existing_members = lb_driver.ex_get_pool_members(pool.id)
    # Quiesced members
    quiesced_members = []
    # Get desired members details / Make sure they exist
    for name, data in desired_members.iteritems():
        # Quiesce node
        node = get_node_by_name_and_ip(module, lb_driver, name, data['ip'])
        if node is None:
            # Exit with error since nodes should pre-exist
            module.fail_json(msg="Node '%s' does not exist. " % name +
                             "You must create node first.")
        else:
            # node exists, let see if its attached and attach if not.
            res = filter(lambda x: x.node_id == node.id,
                         existing_members)
            if len(res) == 0:
                # We need to attach it (create member object)
                try:
                    mem_port = module.params['members'][node.name]['port']
                    n_member = lb_driver.ex_create_pool_member(pool=pool,
                                                               node=node,
                                                               port=mem_port)
                    # Add to quiesced list
                    quiesced_members.append(n_member)
                    changed = True
                except DimensionDataAPIException as e:
                    module.fail_json(msg="Creation of pool member failed: " +
                                     "%s" % e)
            else:
                # Node is attached, add to quiesced list
                quiesced_members.append(res[0])
    # Remove unlisted nodes
    to_delete = list(set(existing_members) - set(quiesced_members))
    for member in to_delete:
        dn = module.params['destroy_nodes']
        lb_driver.ex_destroy_pool_member(member, destroy_node=dn)
        changed = True
    return (changed, quiesced_members)


def main():

    monitor_methods = ['Http', 'Https', 'Tcp', 'TcpHalfOpen', 'Udp']
    down_actions = ['DROP', 'RESELECT', 'NONE']
    lb_methods = ['ROUND_ROBIN', 'LEAST_CONNECTIONS', 'SHORTEST_RESPONSE',
                  'PERSISTENT_IP']
    module = AnsibleModule(
        argument_spec=dict(
            region=dict(default='na', choices=dd_regions),
            location=dict(required=True, type='str'),
            network_domain=dict(required=True, type='str'),
            name=dict(required=True, type='str'),
            description=dict(default=None, type='str'),
            load_balance_method=dict(default='ROUND_ROBIN',
                                     choices=lb_methods),
            health_monitor_1=dict(default=None, choices=monitor_methods),
            health_monitor_2=dict(default=None, choices=monitor_methods),
            service_down_action=dict(default='NONE', choices=down_actions),
            slow_ramp_time=dict(required=False, default=30, type='int'),
            members=dict(required=False, default=None, type='dict'),
            destroy_nodes=dict(required=False, default=True, type='bool'),
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
    pool = get_pool(module, lb_driver)
    if ensure == 'present':
        if pool is False:
            pool = create_pool(module, lb_driver, net_domain.id)
        changed, qm = quiesce_members(module, lb_driver, pool)
        module.exit_json(changed=changed, msg="Load balancer pool " +
                         "successfully quiesced.",
                         load_balancer_pool=pool_obj_to_dict(pool, qm))
    elif ensure == 'absent':
        if pool is False:
            module.exit_json(changed=False, msg="Load balancer pool with " +
                             "name %s does not exist" % module.params['name'])
        try:
            res = lb_driver.ex_destroy_pool(pool)
            module.exit_json(changed=True, msg="Load balancer pool deleted. " +
                             "Status: %s" % res)
        except DimensionDataAPIException as e:
            module.fail_json(msg="Unexpected error when attempting to delete" +
                             " load balancer pool: %s" % e)
    else:
        fail_json(msg="Requested ensure was " +
                  "'%s'. Status must be one of 'present', 'absent'." % ensure)

if __name__ == '__main__':
    main()
