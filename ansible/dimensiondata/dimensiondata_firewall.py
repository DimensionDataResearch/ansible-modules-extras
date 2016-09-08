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
#   - Some code adopted from Lawrence Lui's <lawrence.lui@dimensiondata.com>
#     didata_cli contributions.
#
from ansible.module_utils.basic import *
from ansible.module_utils.dimensiondata import *
try:
    from libcloud.common.dimensiondata import DimensionDataAPIException
    from libcloud.common.dimensiondata import DimensionDataFirewallRule
    from libcloud.common.dimensiondata import DimensionDataFirewallAddress
    from libcloud.compute.base import NodeLocation
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
module: dimensiondata_firewall
short_description:
    - Create, update, and delete MCP 2.0 firewall rules.
    - Requires MCP 2.0.
version_added: '2.1'
author: 'Aimon Bustardo (@aimonb)'
options:
  region:
    description:
      - The target region.
    choices: %s
    default: na
  location:
    description:
      - The target datacenter.
    required: true
  network_domain:
    description:
      - The target network.
    required: true
  name:
    description:
      - Firewall rule name.
    rquired: true
  state:
    description:
      - State the resource should be in - present, absent, enabled, disabled.
      - If 'enabled' or 'present' given and rule does not exist, rule will be created and enabled.
      - If 'disabled' given and rule does not exist, rule will be created and disabled.
      - If 'absent' given, rule will be deleted.
    choices: [present, absent, enabled, disabled]
    default: present
  action:
    description:
      - Action to take when rule matched.
      - ACCEPT_DECISIVELY or DROP
    choices: [ACCEPT_DECISIVELY, DROP]
    default: Accept
  ip_version:
    description:
      - IPv4 or IPv6.
    choices: [IPv4, IPv6]
    default: IPv4
  protocol:
    description:
      - Network protocol type.
      - IP, ICMP, TCP, or UDP.
    choices: [IP, ICMP, TCP, UDP]
    default: TCP
  source:
    description:
      - Source host IP or subnet as CIDR.
    default: ANY
  source_port:
    description:
      - Source ANY, single port or port range.
    default: ANY
  destination:
    description:
      - Destination host IP or subnet as CIDR.
    default: ANY
  destination_port:
    description:
      - Destination ANY, single port or port range.
    default: ANY
  position:
    description:
      - Placement of rule in relation to others.
      - One of FIRST, LAST, BEFORE, AFTER.
    default: last
  relative_to_rule:
    description:
      - BEFORE or AFTER this rule.
      - Required when position is BEFORE or AFTER.
    default: false
  verify_ssl_cert:
    description:
      - Check that SSL certificate is valid.
    default: true
''' % str(dd_regions)

EXAMPLES = '''
# Create and enable an IPv4 single port TCP allow rule to single destination:
- dimensiondata_firewall:
    region: na
    location: NA5
    network_domain: MyNet1
    name: Allow_HTTPs
    action:  ACCEPT_DECISIVELY
    protocol: TCP
    destination: 10.1.2.3
    destination_port: 443
# Delete a rule:
- dimensiondata_firewall:
    region: na
    location: NA5
    network_domain: MyNet1
    name: Allow HTTPs
    state: absent
'''

RETURN = '''
firewall_rule:
    description: Dictionary describing the firewall rule.
    returned: On success when I(state) is 'present'
    type: dictionary
    contains:
        id:
            description: Rule ID.
            type: string
            sample: "8c787000-a000-4050-a215-280893411a7d"
        network_domain:
            description: Network name.
            type: string
            sample: MyNet1
        name:
            description: Rule name.
            type: string
            sample: "Allow HTTPs to Web Servers"
        action:
            description: Rule action.
            type: string
            sample: ACCEPT_DECISIVELY
        ip_version:
            description: IP version.
            type: string
            sample: IPv4
        protocol:
            description: Network protocol.
            type: string
            sample: TCP
        enabled:
            description: Rule state.
            type: string
            sample: true
        source:
            description: Source rule attributes.
            type: dictionary
            sample:
                any_ip:
                    description: Set if address is ANY.
                    type: string
                    sample: ANY
                ip_address:
                    description: IP address.
                    type: string
                    sample: 4.2.2.250
                ip_prefix_size:
                    description: Subnet mask as integer.
                    type: integer
                    sample: 32
                port_begin:
                    description: Start port.
                    type: string
                    sample: null
                port_end:
                    description: End port.
                    type: string
                    sample: null
        destination:
            description: Destination rule attributes.
            type: dictionary
            sample:
                any_ip:
                    description: Set if address is ANY.
                    type: string
                    sample: ANY
                ip_address:
                    description: IP address.
                    type: string
                    sample: 10.23.253.253
                ip_prefix_size:
                    description: Subnet mask as integer.
                    type: integer
                    sample: 32
                port_begin:
                    description: Start port.
                    type: integer
                    sample: 443
                port_end:
                    description: End port.
                    type: integer
                    sample: 443
        location:
            description: Datacenter location code.
            type: string
            sample: NA12
        status:
            description: Rule state.
            type string
            sample: enabled
'''


def get_network_by_name(driver, name, location):
    networks = driver.ex_list_network_domains(location=location)
    network = filter(lambda x: x.name == name, networks)
    if len(network) > 0:
        return network[0]
    else:
        return None


def get_firewall_rule_by_name(driver, name, network_id):
    firewall_rules = driver.ex_list_firewall_rules(network_domain=network_id)
    rule = filter(lambda x: x.name == name, firewall_rules)
    if len(rule) > 0:
        return rule[0]
    else:
        return None


def create_firewall_rule(module, driver, name, action, networkid, ip_version,
                         protocol, source_ip, source_ip_prefix_size,
                         source_start_port, source_end_port, destination_ip,
                         destination_ip_prefix_size, destination_start_port,
                         destination_end_port, position,
                         position_relative_to_rule):
    try:
        network_domain = driver.ex_get_network_domain(networkid)
        source_any = True if source_ip == 'ANY' else False
        dest_any = True if destination_ip == 'ANY' else False
        source_address = DimensionDataFirewallAddress(source_any, source_ip,
                                                      source_ip_prefix_size,
                                                      source_start_port,
                                                      source_end_port)
        dest_address = DimensionDataFirewallAddress(dest_any, destination_ip,
                                                    destination_ip_prefix_size,
                                                    destination_start_port,
                                                    destination_end_port)
        rule = DimensionDataFirewallRule(id=None, name=name, action=action,
                                         location=network_domain.location,
                                         network_domain=network_domain,
                                         status=None, ip_version=ip_version,
                                         protocol=protocol,
                                         source=source_address,
                                         destination=dest_address,
                                         enabled=True)
        return driver.ex_create_firewall_rule(network_domain, rule, position,
                                              position_relative_to_rule)
    except DimensionDataAPIException as e:
        module.fail_json(msg="Create Firewall Rule failed with: '%s'" % e)


def delete_firewall_rule(module, driver, rule_id):
    try:
        res = driver.ex_delete_firewall_rule(rule_id)
        if res is True:
            module.exit_json(changed=True,
                             msg="Deleted firewall rule with id: '%s'" %
                             rule_id)
        module.fail_json("Unexpected failure deleting rule %s" % name)
    except DimensionDataAPIException as e:
        module.fail_json(msg="Failed to delete firewall rule: %s" % str(e))


def to_source_or_destination(addresses, ports):
    if addresses.lower() == 'any':
        ip_address = 'ANY'
        any_ip = True
        ip_prefix_size = None
    else:
        any_ip = False
        # Get and set address parts
        addr_parts = addresses.split('/')
        ip_address = addr_parts[0]
        if len(addr_parts) == 2:
            ip_prefix_size = addr_parts[1]
        else:
            ip_prefix_size = None
    if ports.lower() == 'any':
        start_port = None
        end_port = None
    else:
        # Get and set port(s) parts
        port_parts = ports.split('-')
        if len(port_parts) == 2:
            start_port = port_parts[0]
            end_port = port_parts[1]
        else:
            start_port = port_parts[0]
            end_port = port_parts[0]
    return Bunch(any_ip=any_ip, ip_address=ip_address,
                 ip_prefix_size=ip_prefix_size, port_begin=start_port,
                 port_end=end_port)


def sync_firewall_rule_state(driver, fw_rule, state):
    if state == 'disabled' and fw_rule.enabled != 'false':
        enable = False
    elif state != 'disabled' and fw_rule.enabled == 'true':
        return {'success': True, 'result': 'nochange'}
    elif state != 'disabled' and fw_rule.enabled != 'true':
        enable = True
    try:
        # State doesnt match, so set state.
        # TBD handle result code 'IN_PROGRESS'
        res_code = driver.ex_set_firewall_rule_state(fw_rule, enable)
        return {'success': True, 'result': res_code}
    except DimensionDataAPIException as e:
        return {'success': False, 'result': e}


def rule_obj_to_dict(rule):
    rule_dict = dict(id=rule.id, name=rule.name, action=rule.action)
    if isinstance(rule.location, NodeLocation):
        rule_dict['location'] = dict(id=rule.location.id,
                                     name=rule.location.name,
                                     country=rule.location.country)
    else:
        rule_dict['location'] = rule.location
    rule_dict['status'] = rule.status
    rule_dict['ip_version'] = rule.ip_version
    rule_dict['protocol'] = rule.protocol
    rule_dict['enabled'] = rule.enabled

    return rule_dict


# Create Bunch class to hold arbitrary attributes
class Bunch:
    def __init__(self, **kwds):
        self.__dict__.update(kwds)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            region=dict(default='na', choices=dd_regions),
            location=dict(required=True, type='str'),
            network_domain=dict(required=True, type='str'),
            name=dict(required=True, type='str'),
            state=dict(default='present', choices=['present', 'absent',
                       'enabled', 'disabled']),
            action=dict(default='ACCEPT_DECISIVELY',
                        choices=['ACCEPT_DECISIVELY', 'DROP']),
            ip_version=dict(default='IPv4', choices=['IPv4', 'IPv6']),
            protocol=dict(default='TCP', choices=['IP', 'ICMP', 'TCP', 'UDP']),
            source=dict(required=False, default='ANY', type='str'),
            source_port=dict(required=False, default='ANY', type='str'),
            destination=dict(required=False, default='ANY', type='str'),
            destination_port=dict(required=False, default='ANY', type='str'),
            position=dict(default='LAST', choices=['FIRST', 'LAST',
                                                   'BEFORE', 'AFTER']),
            relative_to_rule=dict(required=False, default=None, type='str'),
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
    location = module.params['location']
    network_domain = module.params['network_domain']
    name = module.params['name']
    state = module.params['state']
    action = module.params['action']
    ip_version = module.params['ip_version']
    protocol = module.params['protocol']
    source = module.params['source']
    source_port = module.params['source_port']
    destination = module.params['destination']
    destination_port = module.params['destination_port']
    position = module.params['position']
    relative_to_rule = module.params['relative_to_rule']
    verify_ssl_cert = module.params['verify_ssl_cert']

    # Instantiate driver
    libcloud.security.VERIFY_SSL_CERT = verify_ssl_cert
    DimensionData = get_driver(Provider.DIMENSIONDATA)
    driver = DimensionData(user_id, key, region=region)

    # Get network object by name
    network_obj = get_network_by_name(driver, network_domain, location)

    position = position.upper()
    # Check if relative_to_rule exists
    if position == 'BEFORE' or position == 'AFTER':
        if relative_to_rule is None:
            module.fail_json(msg="'relative_to_rule' must be a valid rule " +
                                 "name when 'position' is " +
                                 "'BEFORE' or 'AFTER'")
        target_rule = get_firewall_rule_by_name(driver, relative_to_rule,
                                                network_obj.id)
        if target_rule is None:
            module.fail_json(msg="Rule '%s' specifed in " % relative_to_rule +
                                 " 'relative_to_rule' not found")

    # Get rule if exists
    existing_rule = get_firewall_rule_by_name(driver, name, network_obj.id)

    # Process state
    if state == 'present' or state == 'enabled' or state == 'disabled':
        # Get SOURCE network parts
        source_obj = to_source_or_destination(source, source_port)
        # Get DESTINATION network parts
        destination_obj = to_source_or_destination(destination,
                                                   destination_port)
        if existing_rule is None:
            # Create Firewall Rule
            created = True
            fw_rule = create_firewall_rule(module, driver, name, action,
                                           network_obj.id,
                                           ip_version, protocol,
                                           source_obj.ip_address,
                                           source_obj.ip_prefix_size,
                                           source_obj.port_begin,
                                           source_obj.port_end,
                                           destination_obj.ip_address,
                                           destination_obj.ip_prefix_size,
                                           destination_obj.port_begin,
                                           destination_obj.port_end, position,
                                           relative_to_rule)
        else:
            created = False
            # Rule already exists
            fw_rule = existing_rule

        # Exit now if state doesnt need updating
        if fw_rule.enabled == 'false' and state == 'disabled':
            module.exit_json(changed=False,
                             msg="Firewall rule exists and is disabled.",
                             firewall_rule=rule_obj_to_dict(fw_rule))
        elif fw_rule.enabled == 'true' and state != 'disabled':
            module.exit_json(changed=False,
                             msg="Firewall rule exists and is enabled.",
                             firewall_rule=rule_obj_to_dict(fw_rule))

        # Sync Rule state
        sync_res = sync_firewall_rule_state(driver, fw_rule, state)

        if sync_res['success'] is True and created is True:
            module.exit_json(changed=True,
                             msg="Firewall rule %s created and disabled." %
                             name, firewall_rule=rule_obj_to_dict(fw_rule))
        elif sync_res['success'] is True and created is False:
            module.exit_json(changed=True,
                             msg="Firewall rule %s disabled." %
                             name, firewall_rule=rule_obj_to_dict(fw_rule))
        elif sync_res['success'] is False and created is False:
            module.fail_json(msg="Firewall rule state change failed.")
        elif sync_res['success'] is False and created is True:
            module.fail_json(msg="Firewall rule created but state change " +
                             "failed: %s", firewall_rule=sync_res['result'])
        else:
            module.fail_json(msg="Unexpected result while changing rule state")
    elif state == "absent":
        if existing_rule is None:
            module.exit_json(msg="Rule with name '%s' not found." % name)
        else:
            # Delete rule
            delete_firewall_rule(module, driver, existing_rule)
    else:
        module.fail_json(msg="Unrecongnized state given. Must be one of: " +
                         "present, absent, enabled, disabled")


main()
