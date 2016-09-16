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
#   - Aimon Bustardo <Aimon.Bustardo@dimensiondata.com>
#   - Jay Riddell    <Jay.Riddell@dimensiondata.com>

DOCUMENTATION = '''
---
module: dimensiondata_compute
short_description: create, terminate, start or stop an server in dimensiondata
description:
    - Creates, terminates, starts or stops servers in the Dimension Data Cloud
version_added: "2.2"
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
  ensure:
    description:
      - The state you want the hosts to be in.
    default: present
    choices: [present, absent, running, stopped]
  nodes:
    description:
      - A list of server ID or names to work on.
    default: null
    aliases: [server_id, server_ids, node_id]
  image:
    description:
      - The image name or ID to provision with.
    default: null
  vlans:
    description:
      - List of names or IDs of the VLANs to connect to.
      - They will be connected in order specified.
      - Cannot have BOTH vlans and ipv4_addresses values present.
    required: false
    default: None
  ipv4_addresses:
    description:
      - List of IPv4 addresses to connect.
      - Only one address per VLAN/Network is allowed.
    reqauired: false
    default: None
  network_domain:
    description:
      - The name or ID of the network domain to provision to.
    required: true
    aliases: [network]
  location:
    description:
      - The target datacenter.
    required: true
  admin_password:
    description:
      - The administrator account password for a new server.
    required: false
    default: null
  description:
    description:
      - The description for the new node.
    required: false
    default: null
  memory_gb:
    description:
      - The amount of memory for the new host to have in GB.
    required: false
    default: null
  primary_dns:
    description:
      - Primary DNS server IP or FQDN.
    required: false
    default: None
  secondary_dns:
    description:
      - Secondary DNS server IP or FQDN.
    required: false
    default: None
  unique_names:
    description:
      - By default Dimension Data allows the same name for multiple servers.
      - This will make sure we do not create a new server if the name already exists.
    required: false
    default: true
    choices: [true, false]
  operate_on_multiple:
    description:
      - By default Dimension Data allows the same name for multiple servers.
      - This will allow this module to operate on mulitple nodes/servers if names are given instead of IDs.
      - WARNING- This can be dangerous!!
    required: false
    default: false
    choices: [true, false]
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
  wait_time:
    description:
      - Only applicable if wait is true. This is the amount of time in seconds to wait.
    required: false
    default: 600
  wait_poll_interval:
    description:
      - Only applicable if wait is true.
      - The amount of time (in seconds) in between polling for task completion.
      - Should obviously not be greater than wait_time.
    required: false
    default: 2

author:
    - "Jeff Dunham (@jadunham1)"
    - "Aimon Bustardo (@aimonb)"
'''

EXAMPLES = '''
# Note: These examples don't include authorization.
#       You can set these by exporting DIDATA_USER and DIDATA_PASSWORD var:
# export DIDATA_USER=<username>
# export DIDATA_PASSWORD=<password>

# Basic create node example

- dimensiondata_compute:
    vlan: '{{ vlan }}'
    network_domain: '{{ network_domain_id }}'
    location: '{{ location }}'
    image: 'RedHat 7 64-bit 2 CPU'
    nodes:
      - ansible-test-image
    admin_password: fakepass

# Ensure servers are running and wait for it to come up
- dimensiondata_compute:
    vlan: '{{ vlan }}'
    network_domain: '{{ network_domain_id }}'
    location: '{{ location }}'
    ensure: running
    nodes:
      - my_node_1
      - my_node_2
    wait: yes

# Ensure servers are stopped and wait for them to stop
- dimensiondata_compute:
    vlan: '{{ vlan }}'
    network_domain: '{{ network_domain_id }}'
    location: '{{ location }}'
    ensure: stopped
    nodes:
      - my_node_1
      - {{ node_id }}
    wait: yes

# Destroy servers
- dimensiondata_compute:
    vlan: '{{ vlan }}'
    network_domain: '{{ network_domain_id }}'
    location: '{{ location }}'
    ensure: absent
    nodes:
      - my_node_1
      - my_node_2

# ---------------
# Working with
# non unique names
# ---------------

# Create nodes
- dimensiondata_compute:
    vlan: '{{ vlan }}'
    network_domain: '{{ network_domain_id }}'
    location: '{{ location }}'
    image: 'RedHat 7 64-bit 2 CPU'
    nodes:
      - ansible-test-image1
      - ansible-test-image2
      - ansible-test-image1
      - ansible-test-image2
    admin_password: fakepass
    unique_names: false
    primary_dns: 4.2.2.1
    secondary_dns: 8.8.8.8
    operate_on_multiple: true

# Shutdown nodes
- dimensiondata_compute:
    vlan: '{{ vlan }}'
    network_domain: '{{ network_domain_id }}'
    location: '{{ location }}'
    nodes:
      - ansible-test-image1
      - ansible-test-image2
      - ansible-test-image1
      - ansible-test-image2
    ensure: stopped
    unique_names: false
    operate_on_multiple: true

# Delete nodes
- dimensiondata_compute:
    vlan: '{{ vlan }}'
    network_domain: '{{ network_domain_id }}'
    location: '{{ location }}'
    nodes:
      - ansible-test-image1
      - ansible-test-image2
      - ansible-test-image1
      - ansible-test-image2
    ensure: absent
    unique_names: false
    operate_on_multiple: true
'''

RETURN = '''
nodes:
    description: List of quiesced nodes
    returned: On success.
    type: list
    contains:
        id:
            description: node ID.
            type: string
            sample: "7D59BC28-0322-4374-A409-B28ED80424D3"
        name:
            description: node name.
            type: string
            sample: "My Node"
        ipv6:
            description: the ipv6 address (if it has been assigned)
            type: string
            sample: ''
        os-type:
            description: type of the os running on the node
            type: string
            sample: linux
        private_ipv4:
            description: the ipv4 private address
            type: string
            sample: 192.168.1.1
        public_ipv4:
            description: the ipv4 public address
            type: string
            sample: 10.0.0.4
        location:
            description: name of the datacenter
            type: string
            sample: na12
        state:
            description: server/node state
            type: string
            sample: "running"
        password:
            description: only returned if admin_password was not provided
            type: string
            sample: somethingOrAnother23
'''
from ansible.module_utils.basic import *
from ansible.module_utils.dimensiondata import *
HAS_LIBCLOUD = True
try:
    from libcloud.common.dimensiondata import DimensionDataAPIException
    from libcloud.compute.types import Provider, InvalidCredsError
    from libcloud.compute.providers import get_driver
    import libcloud.security
except ImportError:
    HAS_LIBCLOUD = False

# Get regions early to use in docs etc.
dd_regions = get_dd_regions()


def node_to_node_obj(node):
    node_obj = {}
    node_obj['id'] = node.id
    node_obj['name'] = node.name
    node_obj['ipv6'] = node.extra['ipv6']
    node_obj['os_type'] = node.extra['OS_type']
    node_obj['private_ipv4'] = node.private_ips
    node_obj['public_ipv4'] = node.public_ips
    node_obj['location'] = node.extra['datacenterId']
    node_obj['state'] = node.state.lower()
    # Password object will only be set if the password is randomly generated
    if 'password' in node.extra:
        node_obj['password'] = node.extra['password']
    return node_obj


# ---------------------------------------------
# Get Servers/Nodes object by name or id
# ---------------------------------------------
def get_nodes(client, module):
    nodes_dict = {}
    location = module.params['location'].upper()
    nodes = list(set(module.params['nodes']))
    for node in nodes:
        if is_uuid(node):
            matched_nodes = [node]
        else:
            nodes = client.list_nodes(location)

            matched_nodes = list(filter(lambda x: x.name == node,
                                        nodes))

        if len(matched_nodes) < 1:
            nodes_dict[node] = {'id': [], 'name': [], 'node': []}
        elif len(matched_nodes) >= 1:
            # Build name, id list
            nodes_dict[node] = {'id': [], 'name': [], 'node': []}
            for m_node in matched_nodes:
                nodes_dict[node]['id'].append(m_node.id)
                nodes_dict[node]['name'].append(m_node.name)
                nodes_dict[node]['node'].append(m_node)
    return nodes_dict


def get_all_nodes(client, module):
    location = module.params['location'].upper()
    domain = module.params['network_domain']
    try:
        return client.list_nodes(ex_location=location,
                                 ex_network_domain=domain)
    except DimensionDataAPIException as e:
        module.fail_json(msg="Unexpected error while retriving existing " +
                             "nodes: %s" % e)


# ---------------------------------------------
# Get a Image object by its name or id
# ---------------------------------------------
def get_image(client, module, location):
    if is_uuid(module.params['image']):
        image_id = module.params['image']
    else:
        image_match_name = module.params['image']
        images = client.list_images(location)
        images.extend(client.ex_list_customer_images(location))

        matched_images = list(filter(lambda x: x.name == image_match_name,
                              images))

        if len(matched_images) < 1:
            module.fail_json(msg='No images matched this name')
        elif len(matched_images) > 1:
            module.fail_json(msg='Multile images matched this please'
                                 ' specify a single unique image id')
        image_id = matched_images[0].id
    try:
        image = client.ex_get_image_by_id(image_id)
    except DimensionDataAPIException as e:
        module.fail_json(msg="Unexpected API error: %s" % e)
    return image


def validate_unique_names(client, module):
    nodes = module.params['nodes']
    dupes = False
    # Check for dupes
    if len(nodes) != len(list(set(nodes))):
        dupes = True
    if module.params['unique_names'] is True and dupes is True:
        module.fail_json(msg="Argument 'unique_names' is set to True " +
                             "but duplicate names are present.")
    if module.params['operate_on_multiple'] is False and dupes is True:
        module.fail_json(msg="Argument 'operate_on_multiple' is set to False" +
                             " but duplicate names are present.")
    return True


def create_node(client, module, name, wait):
    location = module.params['location'].upper()
    admin_password = module.params['admin_password']
    network_domain = get_network_domain(client,
                                        module.params['network_domain'],
                                        location)
    if not network_domain:
        module.fail_json(msg="Network Domain %s not found in location %s" %
                         (module.params["network_domain"],
                          module.params["location"]))

    pri_dns = module.params['primary_dns']
    sec_dns = module.params['secondary_dns']

    # Check if we are using vlans or ipv4_addresses
    vlan = None
    add_vlans = None
    ipv4 = None
    add_ipv4s = None
    if module.params['vlans'] is not None:
        pri_vlan = module.params['vlans'][0]
        vlan = get_vlan(client, pri_vlan, location, network_domain)
        if not vlan:
            module.fail_json(msg="VLAN ID %s not found in location %s, "
                             "network domain %s" % (pri_vlan, location,
                                                    network_domain.id))
        if len(module.params['vlans']) > 1:
            add_vlans = []
            for v in module.params['vlans'][1:]:
                res = get_vlan(client, v, location, network_domain)
                add_vlans.append(res.id)
    else:
        ipv4 = module.params['ipv4_addresses'][0]
        if len(module.params['ipv4_addresses']) > 1:
            add_ipv4s = module.params['ipv4_addresses'][1:]
    # Get image
    image = get_image(client, module, network_domain.location.id)
    if get_mcp_version == '1.0':
        node = client.create_node(name, image.id, admin_password,
                                  module.params['description'],
                                  ex_network=network_domain.id,
                                  ex_vlan=vlan,
                                  ex_primary_ipv4=ipv4,
                                  ex_memory_gb=module.params['memory_gb'],
                                  ex_primary_dns=pri_dns,
                                  ex_secondary_dns=sec_dns)
    else:
        node = client.create_node(name, image.id, admin_password,
                                  module.params['description'],
                                  ex_network_domain=network_domain.id,
                                  ex_vlan=vlan,
                                  ex_primary_ipv4=ipv4,
                                  ex_memory_gb=module.params['memory_gb'],
                                  ex_primary_dns=pri_dns,
                                  ex_secondary_dns=sec_dns,
                                  ex_additional_nics_vlan=add_vlans,
                                  ex_additional_nics_ipv4=add_ipv4s)
    if wait is True:
        node = wait_for_server_state(client, module, node.id, 'running')
    return node


def wait_for_server_state(client, module, server_id, state_to_wait_for):
    try:
        return client.connection.wait_for_state(
            state_to_wait_for, client.ex_get_node_by_id,
            module.params['wait_poll_interval'],
            module.params['wait_time'], server_id
        )
    except DimensionDataAPIException as e:
        module.fail_json(msg='Server did not reach %s state in time: %s' %
                             (state_to_wait_for, e.msg))


def start_stop_server(client, module, action, node, wait):
    err = "Failed to %s node '%s':" % (action, node.id)
    res = False
    try:
        if action == 'stop' or action == 'shutdown':
            res = client.ex_shutdown_graceful(node)
        elif action == 'start' or action == 'boot':
            res = client.ex_start_node(node)
    except DimensionDataAPIException as e:
        module.fail_json(msg=err + e)
    if res is False:
        module.fail_json(msg=err + e)
    try:
        quiesced_node = client.ex_get_node_by_id(node.id)
    except DimensionDataAPIException as e:
        module.fail_json(msg="Failed to get node details after %s " % action +
                         "action. However server did %s." % action +
                         "Error: %s" % e)
    return {'changed': True, "node": quiesced_node}


def quiesce_servers_states(client, module, nodes_dict):
    changed = False
    wait = module.params['wait']
    desired_state = module.params['ensure']
    quiesced_nodes = []
    for key, node in nodes_dict.iteritems():
        # Listed number of this named node
        req_node_count = module.params['nodes'].count(key)

        # Existing number of this named node
        exi_node_count = len(node['node'])

        # Get difference
        needed_num_nodes = 0
        if req_node_count > exi_node_count:
            needed_num_nodes = req_node_count - exi_node_count

        # Quiesce
        if desired_state in ('present', 'running', 'stopped'):
            # Die if node/server does not exist and needed args are not present
            if needed_num_nodes > 0:
                module_key_die_if_none(module, 'admin_password')
                module_key_die_if_none(module, 'image')
            pre_wait = wait
            if desired_state == 'stopped':
                pre_wait = True
            try:
                # Launch missing
                for i in range(needed_num_nodes):
                    quiesced_nodes.append(
                        node_to_node_obj(create_node(client, module, key,
                                                     pre_wait)))
                    changed = True
            except DimensionDataAPIException as e:
                module.fail_json(msg="Error while creating node '%s': %s" %
                                 (key, e))
            if desired_state == 'stopped':
                for n in node['node']:
                    if n.state.lower() not in ('stopped', 'terminated'):
                        res = start_stop_server(client, module, 'shutdown', n,
                                                wait)
                        changed = True
                        quiesced_nodes.append(node_to_node_obj(res['node']))
                    else:
                        quiesced_nodes.append(node_to_node_obj(n))
            elif desired_state in ('running', 'present'):
                for n in node['node']:
                    if n.state.lower() in ('stopped', 'terminated'):
                        res = start_stop_server(client, module, 'boot', n,
                                                wait)
                        changed = True
                        quiesced_nodes.append(node_to_node_obj(res['node']))
                    else:
                        quiesced_nodes.append(node_to_node_obj(n))

        elif desired_state == 'absent' and len(node['node']) == 0:
            changed = False
            for n in node['node']:
                quiesced_nodes.append(node_to_node_obj(n))
        elif desired_state == 'absent' and len(node['node']) > 0:
            if req_node_count < exi_node_count:
                module.fail_json(msg="UNSAFE OPERATION DETECTED: More nodes " +
                                     "exist with a listed name than were " +
                                     "specified.")
            for n in node['node']:
                try:
                    if n.state.lower() == 'starting':
                        wait_for_server_state(client, module, n.id,
                                              'terminated')
                    if n.state.lower() != 'stopped':
                        client.ex_power_off(n)
                        wait_for_server_state(client, module, n.id,
                                              'stopped')
                    client.destroy_node(n)
                    changed = True
                except DimensionDataAPIException as e:
                    module.fail_json(msg="Error while destroying node " +
                                     "'%s' in state '%s': " % (n.id, n.state) +
                                     "%s" % e)
                quiesced_nodes.append(node_to_node_obj(n))
    return {'changed': changed, 'nodes': quiesced_nodes}


def module_key_die_if_none(module, key):
    v = module.params[key]
    if v is None:
        module.fail_json(msg='Unable to load %s' % key)
    return v


def validate_ipv4s_node_count(client, module):
    if len(module.params['nodes']) > 1 and \
            module.params['ipv4_addresses'] is not None:
        module.fail_json(msg="'ipv4s' argument is not valid when specifying " +
                         "more than one node.")


def core(module):
    changed = False
    credentials = get_credentials()
    if credentials is False:
        module.fail_json(msg="User credentials not found")
    user_id = credentials['user_id']
    key = credentials['key']
    region = 'dd-%s' % module.params['region']
    verify_ssl_cert = module.params['verify_ssl_cert']

    # Instantiate driver
    libcloud.security.VERIFY_SSL_CERT = verify_ssl_cert
    DimensionData = get_driver(Provider.DIMENSIONDATA)
    client = DimensionData(user_id, key, region=region)

    validate_unique_names(client, module)

    validate_ipv4s_node_count(client, module)

    # Get nodes/servers details
    # Return: {<module.params['nodes'][n]>: {'id': [], 'name': [], 'node': []}}
    nodes_dict = get_nodes(client, module)

    res = quiesce_servers_states(client, module, nodes_dict)
    quiesced_nodes = res['nodes']
    changed = res['changed']
    # Exit with nodes details
    module.exit_json(changed=changed, msg="Successfully quiesced nodes.",
                     nodes=quiesced_nodes)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            ensure=dict(default='present', choices=['present',
                                                    'absent',
                                                    'running',
                                                    'stopped']),
            nodes=dict(type='list', aliases=['server_id',
                                             'server_ids',
                                             'node_id']),
            image=dict(),
            vlans=dict(required=False, type='list', default=None),
            ipv4_addresses=dict(required=False, type='list', default=None),
            network_domain=dict(),
            location=dict(required=True, type='str'),
            admin_password=dict(),
            description=dict(),
            memory_gb=dict(),
            primary_dns=dict(required=False, default=None,
                             type='str'),
            secondary_dns=dict(required=False, default=None,
                               type='str'),
            operate_on_multiple=dict(required=False, default=False,
                                     type='bool'),
            region=dict(default='na', choices=dd_regions),
            unique_names=dict(required=False, default=True, type='bool'),
            verify_ssl_cert=dict(required=False, default=True, type='bool'),
            wait=dict(required=False, default=False, type='bool'),
            wait_time=dict(required=False, default=600, type='int'),
            wait_poll_interval=dict(required=False, default=2, type='int')
        ),
        mutually_exclusive=(["vlans", "ipv4_addresses"])
    )
    if not HAS_LIBCLOUD:
        module.fail_json(msg='libcloud >= 1.0.0pre required for this module')

    try:
        core(module)
    except (InvalidCredsError) as e:
        module.fail_json(msg="Invalid Credentials Error: please check the "
                         "Dimension Data Cloud credentials you provided then "
                         "try again.")
    except (Exception) as e:
        module.fail_json(msg=str(e))


if __name__ == '__main__':
        main()
