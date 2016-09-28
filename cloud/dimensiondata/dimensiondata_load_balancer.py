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
#   - Mark Maglana   <mark.maglana@dimensiondata.com>

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.dimensiondata import \
    get_credentials, get_dd_regions, get_network_domain, is_uuid, \
    get_unallocated_public_ips

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


# ==========
# EXCEPTIONS
# ==========

class CreateError(Exception):
    pass


class DeleteError(Exception):
    pass


class GetLoadBalancerError(Exception):
    pass


class InitializeError(Exception):
    pass


# =========
# FUNCTIONS
# =========

def create_lb(lb_con, compute_con, net_domain, name, port, protocol,
              listener_ip_address, members, algorithm, mod, **kwargs):
    members = [Member(m['name'], m['ip'], m.get('port'))
               for m in members]

    ip_address = str(listener_ip_address).strip()

    if not ip_address:
        # This is the only part where mod is used. Once the method call
        # below is freed from its dependency on AnsibleModule, this function
        # will also no longer need it.
        res = get_unallocated_public_ips(mod, compute_con, lb_con,
                                         net_domain, True, 1)
        ip_address = res['addresses'][0]

    algorithms = getattr(Algorithm, algorithm)

    try:
        balancer = lb_con.create_balancer(name,
                                          port,
                                          protocol,
                                          algorithms,
                                          members,
                                          ex_listener_ip_address=ip_address)
    except DimensionDataAPIException as err:
        msg = "Failed to create load balancer %s: %s" % (name, err)
        raise CreateError(msg)

    balancer_d = {
        'id': balancer.id,
        'name': balancer.name,
        'state': int(balancer.state),
        'ip': balancer.ip,
        'port': int(balancer.port) if balancer.port else 'Any Port'
    }

    return True, "Load balancer created.", balancer_d


def delete_lb(lb, lb_con, **kwargs):
    pool_id = lb.extra.get('pool_id')
    if pool_id:
        pool = lb_con.ex_get_pool(pool_id)

    try:
        res = lb_con.destroy_balancer(lb)
    except DimensionDataAPIException as err:
        msg = "Could not delete load balancer %s: %s" % (lb.name, err)
        raise DeleteError(msg)

    if pool:
        members = lb_con.ex_get_pool_members(pool_id)
        for member in members:
            lb_con.ex_destroy_pool_member(member, destroy_node=True)

        lb_con.ex_destroy_pool(pool)

    balancer_d = {
        'id': lb.id,
        'name': lb.name
    }

    return True, "Load balancer %s deleted" % res, balancer_d


def do_nothing(name, ensure, lb, **kwargs):
    if lb:
        balancer_d = {
            'id': lb.id,
            'name': lb.name
        }
    else:
        balancer_d = {}

    return False, "Load balancer %s already %s" % (name, ensure), balancer_d


def get_action(lb, ensure):
    if ensure == "present" and not lb:
        return create_lb
    elif ensure == "absent" and lb:
        return delete_lb
    else:
        return do_nothing


def get_lb(lb_con, name, **kwargs):
    """
    Retrieves and returns the load balancer object referred to by ``name``.
    Returns None if the load balancer is not found.
    """
    if is_uuid(name):
        return get_lb_by_id(lb_con, name)
    else:
        return get_lb_by_name(lb_con, name)


def get_lb_by_id(lb_con, name):
    try:
        return lb_con.get_balancer(name)
    except DimensionDataAPIException as err:
        if err.code == 'RESOURCE_NOT_FOUND':
            return None
        else:
            msg = "Error in retrieving load balancer %s: %s" % (name, err)
            raise GetLoadBalancerError(msg)


def get_lb_by_name(lb_con, name):
    balancers = lb_con.list_balancers()
    found = filter(lambda x: x.name == name, balancers)

    if found:
        return found[0]
    else:
        return None


def initialize(region, location, network_domain, verify_ssl_cert, **kwargs):
    """
    Initialize backend sessions/connections required by this module
    """
    credentials = get_credentials()
    username = credentials["user_id"]
    password = credentials["key"]
    region = 'dd-%s' % region

    # Verify the API server's SSL certificate?
    libcloud.security.VERIFY_SSL_CERT = verify_ssl_cert

    # Connect to compute service
    compute_drv = get_cp_driver(ComputeProvider.DIMENSIONDATA)
    compute_con = compute_drv(username, password, region=region)

    # Get Network Domain Object
    net_domain = get_network_domain(compute_con, network_domain, location)

    if not net_domain:
        raise InitializeError("Network domain %s could not be found" %
                              network_domain)

    # Connect to load balancer service
    lb_drv = get_lb_driver(LBProvider.DIMENSIONDATA)
    lb_con = lb_drv(username, password, region=region)

    lb_con.ex_set_current_network_domain(net_domain.id)

    return lb_con, compute_con, net_domain


def start(mod):
    if not HAS_LIBCLOUD:
        mod.fail_json(msg="apache-libcloud is required for this module.")

    try:
        lb_con, compute_con, net_domain = initialize(**mod.params)

        lb = get_lb(lb_con=lb_con, **mod.params)

        action = get_action(lb=lb, ensure=mod.params["ensure"])

        # Passing in the AnsibleModule instance below is not ideal, but I
        # don't have much choice (and time) right now. Ideally, none of the
        # methods called by start() should have to know about AnsibleModule
        # but since the dependency on it runs deep in the underlying code,
        # we'll have to pass it in until we can clean the various parts.
        changed, msg, lb_dict = action(lb=lb,
                                       lb_con=lb_con,
                                       compute_con=compute_con,
                                       net_domain=net_domain,
                                       mod=mod,
                                       **mod.params)

        mod.exit_json(changed=changed,
                      msg=msg,
                      load_balancer=lb_dict)
    except (CreateError,
            DeleteError,
            GetLoadBalancerError,
            InitializeError) as err:
        msg = "%r" % err
        mod.fail_json(msg=msg)


def main():
    regions = get_dd_regions()

    protocols = ['any', 'tcp', 'udp', 'http', 'ftp', 'smtp']

    algorithms = ['ROUND_ROBIN',
                  'LEAST_CONNECTIONS',
                  'SHORTEST_RESPONSE',
                  'PERSISTENT_IP']

    module = AnsibleModule(
        argument_spec=dict(
            region=dict(default='na', choices=regions),
            location=dict(required=True, type='str'),
            network_domain=dict(required=True, type='str'),
            name=dict(required=True, type='str'),
            port=dict(default=None, type='int'),
            protocol=dict(default='http', choices=protocols),
            algorithm=dict(default='ROUND_ROBIN', choices=algorithms),
            members=dict(default=None, type='list'),
            ensure=dict(default='present', choices=['present', 'absent']),
            verify_ssl_cert=dict(default=True, type='bool'),
            listener_ip_address=dict(default=None, type='str')
        ),
    )

    start(module)

if __name__ == '__main__':
    main()
