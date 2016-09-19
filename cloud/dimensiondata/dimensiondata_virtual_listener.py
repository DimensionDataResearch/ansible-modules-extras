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
#   - Jay Riddell <jay.riddell@dimensiondata.com>
#   - Bert Diwa      <Lamberto.Diwa@dimensiondata.com>
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

# enumerated type/choices
persis_type_choices = ['STANDARD', 'PERFORMANCE_LAYER_4',
                       'standard', 'performance_layer_4']
std_protocol_choices = ['ANY', 'TCP', 'UDP', 'HTTP', 'FTP', 'SMTP',
                        'any', 'tcp', 'udp', 'http', 'ftp', 'smtp']
combined_protocol_choices = ['ANY', 'TCP', 'UDP', 'HTTP', 'FTP', 'SMTP',
                             'any', 'tcp', 'udp', 'http', 'ftp', 'smtp']
perf4_protocol_choices = ['ANY', 'TCP', 'UDP', 'HTTP',
                          'any', 'tcp', 'udp', 'http']
source_port_choices = ['PRESERVE', 'PRESERVE_STRICT', 'CHANGE',
                       'preserve', 'preserve_strict', 'change']
ensure_choices = ['PRESENT', 'ABSENT',
                  'present', 'absent']

# Get regions early to use in docs etc.
dd_regions = get_dd_regions()

DOCUMENTATION = '''
---
module: dimensiondata_virtual_listener
description:
  - Create or delete virtual listeners
short_description: Create or delete virtual listeners
version_added: 2.2
author: 'Jay Riddell (@jr2730)'
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
      - Name of the Virtual Listener.
    required: true
  ex_description:
    description:
        - description of the virtual listener
    required: false
    default: None
  pool_name:
    description:
        - name of the listener pool
    required: false
    default: None
  port:
    description:
        - An integer in the range of 1-65535.
        - If not supplied, it will be taken to mean "Any Port"
    required: false
    default: None
  persis_prof_type:
    description:
        - Describes the TYPE of the Persistence Profile that is desired
        - One of STANDARD or PERFORMANCE_LAYER_4
        - If this is not None, then persis_prof_protocol must be not None
        - If this is None, then persis_prof_protocol must be None
    required: false
    choices: ['STANDARD', 'PERFORMANCE_LAYER_4']
    default: None
  persis_prof_protocol:
    description:
        - Describes the protocol of the Persistence Profile that is desired
        - The value of persis_prof_type controls the legal values here
        - STANDARD- choices are ANY, TCP, UDP, HTTP, FTP, SMTP
        - PERFORMANCE_LAYER_4- choices are ANY, TCP, UDP, HTTP
        - If this is not None, then persis_prof_type must be not None
        - If this is None, then persis_prof_type must be None
    required: false
    choices: ['ANY', 'TCP', 'UDP', 'HTTP', 'FTP', 'SMTP']
    default: None
  fb_persis_prof_type:
    description:
        - This describes the Fallback persistence profile that is desired
        - (All same persis_* "rules" apply here)
        - Also, cannot have fb_* (aka Fallback) unless you have "regular"
        - So, fb_* cannot be not None unless persis_* values are not None
        - Also, fb_* values must be different than persis_* values
    required: false
    choices: ['STANDARD', 'PERFORMANCE_LAYER_4']
    default: None
  fb_persis_prof_protocol:
    description:
        - (see fb_persis_prof_type)
    required: false
    choices: ['ANY', 'TCP', 'UDP', 'HTTP', 'FTP', 'SMTP']
    default: None
  irule_persis_prof_type:
    description:
        - This describes the iRule persistence profile that is desired
        - (All same persis_* "rules" apply here)
    required: false
    choices: ['STANDARD', 'PERFORMANCE_LAYER_4']
    default: None
  irule_persis_prof_protocol:
    description:
        - (see irule_persis_prof_type)
    required: false
    choices: ['ANY', 'TCP', 'UDP', 'HTTP', 'FTP', 'SMTP']
    default: None
  protocol:
    description:
        - The protocol for the connection.
        - Permitted range of value are govened by the port value.
        - If port is 80 or 443, then STANDARD else Layer4
        - STANDARD- choose from ['ANY', 'TCP', 'UDP', 'HTTP', 'FTP', 'SMTP']
        - PERFORMANCE_LAYER_4- choose from ['ANY', 'TCP', 'UDP', 'HTTP']
    choices: ['ANY', 'TCP', 'UDP', 'HTTP', 'FTP', 'SMTP']
    required: true
    default: HTTP
  verify_ssl_cert:
    description:
      - Check that SSL certificate is valid.
    required: false
    default: true
  listener_ip_address:
    description:
        - The address on which the virtual listener should listen
        - Must be a valid IPv4 in dot-decimal notation (x.x.x.x).
        - Is opt here; but must be supplied before this object is viable
    required: false
    default: None
  connection_limit:
    description:
        - Integer in range 1..25,000
    required: false
    default: 25000
  connection_rate_limit:
    description:
        - Integer in range 1..4,000
    required: false
    default: 2000
  source_port_preservation:
    description:
        - Must be one of PRESERVE, PRESERVE_STRICT or CHANGE
    required: true
    choices: ['PRESERVE', 'PRESERVE_STRICT', 'CHANGE']
    default: PRESERVE
  ensure:
    description:
      - Indicates state that is desired.
      - present = create as needed
      - absent = delete as needed
    choices: ['present', 'absent']
    default: present
'''


EXAMPLES = '''
# Construct Virtual Listener
    - name: Create a Virtual Listener with new params
      dimensiondata_virtual_listener:
        region: na
        location: NA12
        network_domain: my_network
        name: my_virtual_listener
        pool_name: my_pool
        port: 80
        persis_prof_type: STANDARD
        persis_prof_protocol: SMTP
        protocol: HTTP
        ensure: present
'''

RETURN = '''
virtual_listener:
    description: Dictionary describing the Virtual Listener.
    returned: On success when I(ensure) is 'present'
    type: dictionary
    contains:
        id:
            description: Virtual Listener ID.
            type: string
            sample: "aaaaa000-a000-4050-a215-2808934ccccc"
        name:
            description: Virtual Listener name.
            type: string
            sample: "My Virtual Listener"
        status:
            description: state returned from libcloud.loadbalancer.types.State
            type: integer
            sample: 0
        ip:
            description: Listen VIP of Virtual Listener.
            type: string
            sample: 168.128.1.1
'''


def does_virt_compat_match_type_and_protocol(vl_compat_list,
                                             type_to_match,
                                             protocol_to_match):
    retval = False
    if vl_compat_list is None or \
       type_to_match is None or \
       protocol_to_match is None or \
       vl_compat_list.compatible_listeners is None:
        retval = False
    else:
        up_protocol_to_match = protocol_to_match.upper()
        for vl_compat in vl_compat_list.compatible_listeners:

            if vl_compat.type != type_to_match:
                retval = False
            else:
                if vl_compat.protocol.upper() == 'ANY':
                    retval = True
                else:
                    retval = vl_compat.protocol.upper() == up_protocol_to_match
            if retval:
                return True

    return False


def list_pools(module, lb_driver):
    try:
        pools = lb_driver.ex_get_pools()
        return pools
    except DimensionDataAPIException as e:
        module.fail_json(msg="Failed to retrieve a list of pools: %s" % e)


def get_pool_given_name(module, lb_driver, name):
    if name is None:
        return None
    pools = list_pools(module, lb_driver)
    found_pools = filter(lambda x: x.name == name, pools)
    if len(found_pools) > 0:
        pool = found_pools[0]
        return pool
    else:
        return None


def get_vl_given_name(lb_driver, name):
    virt_list = lb_driver.list_balancers()
    found_vl = filter(lambda x: x.name == name, virt_list)
    if len(found_vl) > 0:
        vl = found_vl[0]
        return vl
    else:
        return None


def vl_obj_to_dict(vl_obj, is_really_balancer):
    return {
        'id': vl_obj.id,
        'name': vl_obj.name,
        'status': vl_obj.state if is_really_balancer else vl_obj.status,
        'ip': vl_obj.ip
    }


# if this returns, then the validation passed
# else it calls module.fail_json with an error
# Allows for 2 different error messages
# (to allow you to figure out which case was hit)
def validate_type_and_protocol(module,
                               the_type,
                               the_protocol,
                               the_error_message_1,
                               the_error_message_2):

    if (the_type is None and the_protocol is not None) or \
       (the_type is not None and the_protocol is None):
        module.fail_json(msg=the_error_message_1)

    # AnsibleModule checked if protocol was in COMBINED list
    # now check if in particular list for the given listener
    if the_type is not None:
        ppt = the_type.upper()
        ppp = the_protocol.upper()
        aok = True
        if ppt == 'STANDARD':
            aok = (ppp in std_protocol_choices)
        else:
            # ppt is layer4
            aok = (ppp in perf4_protocol_choices)
            if not aok:
                module.fail_json(msg=the_error_message_2)


def create_virtual_listener(module,
                            network_domain,
                            name,
                            ex_description,
                            port,
                            listener_pool_name,
                            lb_driver,
                            cp_driver,
                            listener_ip_address=None,
                            persis_prof_type=None,
                            persis_prof_protocol=None,
                            fb_persis_prof_type=None,
                            fb_persis_prof_protocol=None,
                            irule_persis_prof_type=None,
                            irule_persis_prof_protocol=None,
                            protocol='TCP',
                            connection_limit=25000,
                            connection_rate_limit=2000,
                            source_port_preservation='PRESERVE'):

    matched_persis = None
    fb_matched_persis = None
    irule_matched_persis = None

    # so we have to search for matching profile(s)
    default_persis_profiles = \
        lb_driver.ex_get_default_persistence_profiles(network_domain.id)

    # loop through all the profiles that are compat with this network
    for this_persis_prof in default_persis_profiles:

        # persis
        if does_virt_compat_match_type_and_protocol(this_persis_prof,
           persis_prof_type, persis_prof_protocol):
            matched_persis = this_persis_prof
        else:
            # same prof cannot be both "regular" and fb
            # so if didn't match as "regularr", then attempt to match as FB
            if this_persis_prof.fallback_compatible:
                if does_virt_compat_match_type_and_protocol(this_persis_prof,
                   fb_persis_prof_type, fb_persis_prof_protocol):
                    fb_matched_persis = this_persis_prof

    # now do mostly the same thing for iRules
    default_irules = \
        lb_driver.ex_get_default_irules(network_domain.id)

    for this_persis_prof in default_irules:

        if does_virt_compat_match_type_and_protocol(this_persis_prof,
           irule_persis_prof_type, irule_persis_prof_protocol):
            irule_matched_persis = this_persis_prof

    # get the pool for the the given pool name
    listener_pool = get_pool_given_name(module, lb_driver, listener_pool_name)

    try:
        virt_list = lb_driver.ex_create_virtual_listener(
            network_domain_id=network_domain.id,
            name=name,
            ex_description=ex_description,
            port=port,
            pool=listener_pool,
            listener_ip_address=listener_ip_address,
            persistence_profile=matched_persis,
            fallback_persistence_profile=fb_matched_persis,
            irule=irule_matched_persis,
            protocol=protocol.upper(),
            connection_limit=connection_limit,
            connection_rate_limit=connection_rate_limit,
            source_port_preservation=source_port_preservation)

        module.exit_json(changed=True, msg="Success.",
                         virtual_listener=vl_obj_to_dict(virt_list, False))
    except DimensionDataAPIException as e:
        module.fail_json(msg="Error while creating virtual listener: %s" % e)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            region=dict(default='na', choices=dd_regions),
            location=dict(required=True, type='str'),
            network_domain=dict(required=True, type='str'),
            name=dict(required=True, type='str'),
            ex_description=dict(default=None, type='str'),
            pool_name=dict(default=None, type='str'),
            port=dict(default=None, type='int'),
            persis_prof_type=dict(default=None,
                                  choices=persis_type_choices),
            persis_prof_protocol=dict(default=None,
                                      choices=combined_protocol_choices),
            fb_persis_prof_type=dict(default=None,
                                     choices=persis_type_choices),
            fb_persis_prof_protocol=dict(default=None,
                                         choices=combined_protocol_choices),
            irule_persis_prof_type=dict(default=None,
                                        choices=persis_type_choices),
            irule_persis_prof_protocol=dict(default=None,
                                            choices=combined_protocol_choices),
            protocol=dict(default='HTTP', choices=combined_protocol_choices),
            verify_ssl_cert=dict(required=False, default=True, type='bool'),
            listener_ip_address=dict(required=False, default=None, type='str'),
            connection_limit=dict(required=False, default=25000, type='int'),
            connection_rate_limit=dict(required=False, default=2000,
                                       type='int'),
            source_port_preservation=dict(default=source_port_choices[0],
                                          choices=source_port_choices),
            ensure=dict(default='present', choices=ensure_choices)
        ),
    )

    # validation
    #
    # first, persis profile type and persis profile protocol
    persis_prof_type = module.params['persis_prof_type']
    persis_prof_protocol = module.params['persis_prof_protocol']
    ppt = None
    ppp = None
    if persis_prof_type is not None:
        ppt = persis_prof_type.upper()
    if persis_prof_protocol is not None:
        ppp = persis_prof_protocol.upper()

    # want slightly different errors so I can tell why it failed
    validate_type_and_protocol(
        module,
        ppt,
        ppp,
        'VirtListener: Persis Prof params do not match.',
        'VirtListener: Persis Profile params do not match.')

    # next, fallback persis profile type and fallback persis profile protocol
    fb_persis_prof_type = module.params['fb_persis_prof_type']
    fb_persis_prof_protocol = module.params['fb_persis_prof_protocol']
    fbppt = None
    fbppp = None

    if fb_persis_prof_type is not None:
        fbppt = fb_persis_prof_type.upper()
    if fb_persis_prof_protocol is not None:
        fbppp = fb_persis_prof_protocol.upper()

    validate_type_and_protocol(
        module,
        fbppt,
        fbppp,
        'VirtListener: Fallback Persis Prof params do not match.',
        'VirtListener: Fallback Persis Profile params do not match.')

    # lastly, irule persis profile type and fallback persis profile protocol
    irule_persis_prof_type = module.params['irule_persis_prof_type']
    irule_persis_prof_protocol = module.params['irule_persis_prof_protocol']
    irppt = None
    irppp = None

    if irule_persis_prof_type is not None:
        irppt = irule_persis_prof_type.upper()
    if irule_persis_prof_protocol is not None:
        irppp = irule_persis_prof_protocol.upper()

    validate_type_and_protocol(
        module,
        irppt,
        irppp,
        'VirtListener: iRule Persis Prof params do not match.',
        'VirtListener: iRule Persis Profile params do not match.')

    # attempt to validate protocol
    port = module.params['port']
    if port is not None:
        protocol = module.params['protocol']
        # imply listener type by port specification
        if port is 80 or 443:
            # listener_type = 'PERFORMANCE_LAYER_4'
            # validate protocol against the compatible choices
            if (protocol not in perf4_protocol_choices):
                module.fail_json(
                    msg="Protocol was " + "'%s'. " +
                    "Not in list of choices for PERFORMANCE_LAYER_4 type."
                    % protocol)
        else:
            # listener_type = 'STANDARD'
            # validate protocol against the compatible choices
            if (protocol not in std_protocol_choices):
                module.fail_json(
                    msg="Protocol was " + "'%s'. " +
                    "Not in list of choices for STANDARD type."
                    % protocol)

    # check if libcloud was found
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
    ex_description = module.params['ex_description']
    verify_ssl_cert = module.params['verify_ssl_cert']
    pool_name = module.params['pool_name']
    port = module.params['port']
    protocol = module.params['protocol']
    listener_ip_address = module.params['listener_ip_address']
    connection_limit = module.params['connection_limit']
    connection_rate_limit = module.params['connection_rate_limit']
    source_port_preservation = module.params['source_port_preservation']
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

    module.debug("%s" % net_domain)

    # Set network domain
    try:
        lb_driver.ex_set_current_network_domain(net_domain.id)
    except:
        module.fail_json(msg="Current network domain could not be set.")

    # get the existing Virtual Listener with the given name (if exists)
    vl = get_vl_given_name(lb_driver, name)

    if ensure.lower() == 'present':
        if vl is None:
            # create it
            vl = create_virtual_listener(
                module,
                net_domain,
                name,
                ex_description,
                port,
                pool_name,
                lb_driver,
                cp_driver,
                listener_ip_address,
                ppt,
                ppp,
                fbppt,
                fbppp,
                irppt,
                irppp,
                protocol,
                connection_limit,
                connection_rate_limit,
                source_port_preservation)
        else:
            module.exit_json(changed=False, msg="Virtual Listener already " +
                             "exists.", virtual_listener=vl_obj_to_dict(vl,
                                                                        True))
    elif ensure.lower() == 'absent':
        if vl is None:
            module.exit_json(changed=False, msg="Virtual Listener with " +
                             "name %s does not exist" % module.params['name'])
        try:
            res = lb_driver.destroy_balancer(vl)
            module.exit_json(changed=True, msg="Virtual Listener deleted. " +
                             "Status: %s" % res)
        except DimensionDataAPIException as e:
            module.fail_json(msg="Unexpected error when attempting to delete" +
                             " virtual listener: %s" % e)
    else:
        fail_json(msg="Requested ensure was " +
                  "'%s'. Status must be one of 'present', 'absent'." % ensure)

    return vl

if __name__ == '__main__':
    main()
