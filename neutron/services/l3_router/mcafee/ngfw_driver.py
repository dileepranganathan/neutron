# Copyright 2015 Intel Corporation.
#
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import os
import ngfw_smc_driver
import time
from eventlet import greenthread
from novaclient.v1_1 import client as novaclient
from oslo.config import cfg
#from neutron.openstack.common import log as logging
from oslo_log import log as logging
from neutron.common import exceptions
from neutron.api.v2 import attributes
from neutron.extensions import l3
from neutron import manager
import json
import pprint

LOG = logging.getLogger(__name__)

cfg.CONF.register_opts([
    cfg.StrOpt('tenant_admin_name', help="Name of tenant admin user"),
    cfg.StrOpt('tenant_admin_password', help='Tenant admin password'),
    cfg.StrOpt('tenant_id', help="Tenant UUID used to hold router instances"),
    cfg.StrOpt('tenant_name', help="Tenant name used to hold router instances"),
    cfg.StrOpt('shim_image_id', help="Shim VM image UUID"),
    cfg.StrOpt('ngfw_image_id', help="Sg-engine image UUID"),
    cfg.StrOpt('shim_network_id', help="UUID of network for connecting shim VMs and sg-engine"),
    cfg.StrOpt('ngfw_network_id', help="UUID of network for connecting ngfw/shim_vm and SMC"),
    cfg.StrOpt('shim_flavor_id', help="Shim VM flavor UUID"),
    cfg.StrOpt('ngfw_flavor_id', help="Sg-engine flavor UUID"),
    cfg.IntOpt('vm_status_polling_interval', help="seconds between two polls of VM (ngfw/shim_vm) status"),
    cfg.IntOpt('vm_spawn_timeout', help="Timeout value to wait for VM spawn"),
    cfg.IntOpt('fw_status_polling_interval', help="seconds between two polls of single fw"),
    cfg.IntOpt('fw_status_polling_timeout', help="Timeout value to wait for single fw status polling"),
    cfg.StrOpt('smc_url', help="SMC server URL"),
    cfg.StrOpt('smc_api_version', help="SMC API version"),
    cfg.StrOpt('smc_api_auth_key', help="Authentication key to SMC API"),
    ],
    "NGFW")

class NgfwRouterDriver(object):

    def __init__(self):
        """
        Create Nova client handle
        """
        self._pp=pprint.PrettyPrinter()
        self._smc_ref = cfg.CONF.NGFW.smc_url + '/' + cfg.CONF.NGFW.smc_api_version + '/'
        
        self._router2ports = {}
        
        self._smc_connection = ngfw_smc_driver.SMCAPIConnection(cfg.CONF.NGFW.smc_url,
                                                          cfg.CONF.NGFW.smc_api_version,
                                                          cfg.CONF.NGFW.smc_api_auth_key)
        
        self._novaclient = novaclient.Client(username=cfg.CONF.NGFW.tenant_admin_name,
                                             api_key=cfg.CONF.NGFW.tenant_admin_password,
                                             project_id=cfg.CONF.NGFW.tenant_name,
                                             auth_url=cfg.CONF.nova_admin_auth_url)

    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()

    def create_router(self, context, router):
        """
        Bring up sg-engine VM
        Set gateway info correctly
        """
        random = os.urandom(6).encode('hex')
        router_name = 'ngfw_{0}'.format(random)
        shim_name = 'shim_{0}'.format(random)
                
        # create a port on ngfw network and get its IP address
        ngfw_port = self._core_plugin.create_port(context.elevated(), {
                                'port': {'tenant_id': cfg.CONF.NGFW.tenant_id,
                                         'network_id': cfg.CONF.NGFW.ngfw_network_id,
                                         'mac_address': attributes.ATTR_NOT_SPECIFIED,
                                         'fixed_ips': attributes.ATTR_NOT_SPECIFIED,
                                         'device_owner': '',
                                         'device_id': '',
                                         'admin_state_up': True,
                                         'name': ''}})
        print "XXXXXXXXXX"
        print router
        
        filters = {'network_id': [cfg.CONF.NGFW.ngfw_network_id]}
        print filters
        subnet = self._core_plugin.get_subnets(context.elevated(), filters)[0]
        mask = '/' + str(subnet['cidr']).split('/')[1]
        print "XXXXXXXXX"
        print subnet
        if not ngfw_port['fixed_ips']:
            raise Exception(_("Failed to create port on ngfw network for router {0}".format(router['router']['name'])))
        ngfw_manage_ip = str(ngfw_port['fixed_ips'][0]['ip_address']) + mask
        LOG.debug("Using IP address {0} as management IP for router {1}".format(ngfw_manage_ip, router['router']['name']))

        gw_info = router.pop(l3.EXTERNAL_GW_INFO, attributes.ATTR_NOT_SPECIFIED)
        
        '''
        if gw_info != attributes.ATTR_NOT_SPECIFIED:
            shim_network = gw_info['network_id']
            ngfw_ip = gw_info['external_fixed_ips'][0]
            
            filters = {'network_id': gw_info['network_id']}
            # do not handle multiple subnets for one network
            subnet = self._core_plugin.get_subnets(context, filters)[0]
            cider = subnet['cidr']
            print "XXXXXXXXXXXXXXXXXXXXXX"
            print gw_info
            print 'xxxxxxxxxxxxxxxxxxx'
            print cider
            print "XXXXXXXXXXXXXXXXXXXXX"
        '''

        # need to handle exceptions
        contact = ngfw_smc_driver.create_L3FW(router_name, ngfw_manage_ip)

        # Get the ref to the newly declared single_fw
        # TODO: may need to gracefully handle smc exceptions
        router_ref = self._get_ngfw_ref(router_name)
        smc_connection = self._smc_connection

        # Prepare to create ngfw VM
        files = {'/config/base/cloud/engine.cfg' : contact}
        
        nics = [{'port-id' : ngfw_port['id']},
                {'net-id' : cfg.CONF.NGFW.shim_network_id}]

        try:
            ngfw = self._novaclient.servers.create(name=router_name,
                                                   image=cfg.CONF.NGFW.ngfw_image_id,
                                                   flavor=cfg.CONF.NGFW.ngfw_flavor_id,
                                                   nics=nics,
                                                   files=files)
        except:
            LOG.error("Failed to create ngfw instance")
            self._core_plugin.delete_port(context.elevated(), ngfw_port['id'], l3_port_check=False)
            smc_connection.login()
            smc_connection.delete(router_ref)
            smc_connection.logout()
            raise

        def _vm_status(vm_id, vm_type):
            while True:
                try:
                    vm = self._novaclient.servers.get(vm_id)
                except:
                    LOG.error("Failed to get VM (id = {0}) status".format(vm_id))
                    raise

                LOG.debug("{0} {1} spawn status: {2}".format(vm_type, vm_id, vm.status))

                if vm.status not in ('ACTIVE', 'ERROR'):
                    yield cfg.CONF.NGFW.vm_status_polling_interval
                elif vm.status == 'ERROR':
                    raise VmStatusError(vm_type)
                else:
                    break
                
        try:
            self._wait(_vm_status, cfg.CONF.NGFW.vm_spawn_timeout, ngfw.id, 'ngfw')
        except:
            LOG.error("Failed to spawn ngfw id = {0}".format(ngfw.id))
            #self._novaclient.servers.delete(ngfw)
            self._core_plugin.delete_port(context.elevated(), ngfw_port['id'])
            smc_connection.login()
            smc_connection.delete(router_ref)
            smc_connection.logout()
            raise

        nics = [{'net-id' : cfg.CONF.NGFW.ngfw_network_id}]
        
        try:
            shim = self._novaclient.servers.create(name=shim_name,
                                                   image=cfg.CONF.NGFW.shim_image_id,
                                                   flavor=cfg.CONF.NGFW.shim_flavor_id,
                                                   nics = nics)
        except:
            LOG.error("Failed to create shim VM instance")
            self._novaclient.servers.delete(ngfw)
            self._core_plugin.delete_port(context.elevated(), ngfw_port['id'])
            smc_connection.login()
            smc_connection.delete(router_ref)
            smc_connection.logout()
            raise

        try:
            self._wait(_vm_status, cfg.CONF.NGFW.vm_spawn_timeout, shim.id, 'shim')
        except:
            LOG.error("Failed to spawn shim VM id = {0}".format(shim.id))
            self._novaclient.servers.delete(shim)
            self._novaclient.servers.delete(ngfw)
            self._core_plugin.delete_port(context.elevated(), ngfw_port['id'])
            smc_connection.login()
            smc_connection.delete(router_ref)
            smc_connection.logout()
            raise

        # verify ngfw's connection to SMC
        def _fw_status(router_ref, wait_for_status):
            smc_connection.login()
            while True:
                try:
                    result = smc_connection.get(router_ref)
                    fw_node_status_ref = None
                    fw_node_link_list = result[0]['nodes'][0]['firewall_node']['link']
                    for f in fw_node_link_list:
                        if f['rel'] == 'status':
                            fw_node_status_ref = str(f['href']).replace(self._smc_ref, '')
                            break
                    result = smc_connection.get(fw_node_status_ref)
                    status = result[0]['status']
                    if status != wait_for_status:
                        LOG.debug("Firewall status {0}".format(status))
                        yield cfg.CONF.NGFW.fw_status_polling_interval
                    else:
                        smc_connection.logout()
                        break
                except:
                    LOG.error("Failed to get fw status {0}".format(router_ref))
                    smc_connection.logout()
                    raise

        try:
            self._wait(_fw_status, cfg.CONF.NGFW.fw_status_polling_timeout, router_ref, 'No Policy Installed')
        except:
            LOG.error("Failed to wait for fw status {0}".format(router_ref))
            self._novaclient.servers.delete(shim)
            self._novaclient.servers.delete(ngfw)
            self._core_plugin.delete_port(context.elevated(), ngfw_port['id'])
            smc_connection.login()
            smc_connection.delete(router_ref)
            smc_connection.logout()
            raise

        # Create an empty policy and upload to ngfw
        smc_connection.login()
        r = smc_connection.get('elements/fw_template_policy')
        fw_template_list = r[0]['result']
        for tplt in fw_template_list :
            if tplt['name'] == "Firewall Template":
                fw_template_ref = tplt['href'].replace(self._smc_ref, '')

        if not fw_template_ref:
            LOG.error("Failed to find Firewall Template")
            raise exceptions.NotFound

        policy_name = router_name + "-policy"
        fw_policy = {
                     "name" : policy_name,
                     "template" : fw_template_ref
        }

        json_data = json.dumps(fw_policy)

        r = smc_connection.post_element('fw_policy', json_data)
        policy_ref = r.headers['location']
        policy_ref = str(policy_ref).replace(self._smc_ref, '')

        r = smc_connection.session.post(self._smc_ref + router_ref + "/upload?filter={0}".format(policy_name))
        self._pp.pprint(r)
        smc_connection.logout()
        # TODO: wait for status turns to "Online"
        try:
            self._wait(_fw_status, cfg.CONF.NGFW.fw_status_polling_timeout, router_ref, 'Online')
        except:
            LOG.error("Failed to wait for fw status {0}".format(router_ref))
            self._novaclient.servers.delete(shim)
            self._novaclient.servers.delete(ngfw)
            self._core_plugin.delete_port(context.elevated(), ngfw_port['id'])
            smc_connection.login()
            smc_connection.delete(router_ref)
            smc_connection.delete(policy_ref)
            smc_connection.logout()
            raise

        return random
        

    def _wait(self, poll_fn, timeout=0, *poll_fn_args):
            now = time.time()
            for interval in poll_fn(*poll_fn_args):
                greenthread.sleep(interval)
                if timeout > 0 and (time.time() - now) > timeout:
                    raise TimeoutException()

    def delete_router(self, context, router_id):
        ngfw_name = 'ngfw_' + router_id
        shim_name = 'shim_' + router_id
        
        router_ref = self._get_ngfw_ref(ngfw_name)
        if router_ref is None:
            return
        
        # TODO: also has to remove the policies and rules from SMC
        self._smc_connection.login()
        self._smc_connection.delete(router_ref)
        policy = self._get_ngfw_policy_ref(ngfw_name)
        self._smc_connection.delete(policy)
        self._smc_connection.logout()
        
        # TODO: delete the port
        self._delete_vm_by_name(ngfw_name)
        self._delete_vm_by_name(shim_name)

    ''' XXXX Warning: this function logs out the smc connection session '''
    def _get_ngfw_ref(self, router_name):
        smc_connection = self._smc_connection
        smc_connection.login()
        router_ref = None
        try:
            result = smc_connection.get("elements/single_fw")
        except:
            smc_connection.logout()
            raise
        
        firewall_list = result[0]['result']
        for fw in firewall_list:
            if fw['name'] == router_name:
                router_ref = str(fw['href']).replace(self._smc_ref, '')
                print "XXXXXXXXX"
                print "router_ref", router_ref
                break
        if router_ref == None:
            LOG.error("failed to lookup router {0} in SMC".format(router_name))
            return router_ref 
            raise NoRouterException

        smc_connection.logout()
        return router_ref

    def _get_ngfw_policy_ref(self, policy_name):
        smc_connection = self._smc_connection
        smc_connection.login()

        try:
            result = smc_connection.get("elements/fw_policy?filter={0}".format(policy_name))
        except:
            LOG.error("Failed to get fw policy {0}".format(policy_name))
            raise
        
        policy_ref = result[0]['result'][0]['href']
        policy_ref = str(policy_ref).replace(self._smc_ref, '')
        
        return policy_ref

    def add_router_interface(self, context, router_id, dict_info):
        self._add_router_interface(context, router_id, dict_info['port_id'])

    def _add_router_interface(self, context, router_id, router_port_id ):
        port = self._core_plugin._get_port(context.elevated(), router_port_id)
        print "XXXXXXXXXXX add_router_interace() print port"
        print port
        "<neutron.db.models_v2.Port[object at 7faf5bb03350] {tenant_id=u'de37d87e3f214b87a2290f04bf0ce17e', id=u'b7f417c7-2617-4a56-9e77-881eac5b9c54', name=u'', network_id=u'676482a1-6ccc-4702-94b9-a90c9ed3c0e4', mac_address=u'fa:16:3e:ab:24:ad', admin_state_up=True, status=u'DOWN', device_id=u'1234', device_owner=u'network:router_interface'}>"
        print port.fixed_ips
        "[<neutron.db.models_v2.IPAllocation[object at 7f757a821710] {port_id=u'65b15ad8-5e04-441f-adb9-9f69f2f483b7', ip_address=u'192.168.1.1', subnet_id=u'bf2b05a0-679a-4b91-a82e-863ad9bf53b4', network_id=u'3a63e828-4440-4753-95e0-283d002a3233'}>]"

        self._router2ports[router_id] = {router_port_id: []}
        
        gw_ip = port.fixed_ips[0]['ip_address']
        #subnet = self._core_plugin._get_subnet(context, dict_info['subnet_id'])
        subnet = self._core_plugin._get_subnet(context, port.fixed_ips[0]['subnet_id'])
        print "XXXXXXXXX print subnet"
        print subnet
        "<neutron.db.models_v2.Subnet[object at 7f4e2d9fd7d0] {tenant_id=u'de37d87e3f214b87a2290f04bf0ce17e', id=u'bf2b05a0-679a-4b91-a82e-863ad9bf53b4', name=u'test subnet', network_id=u'3a63e828-4440-4753-95e0-283d002a3233', ip_version=4L, cidr=u'192.168.1.0/24', gateway_ip=u'192.168.1.1', enable_dhcp=True, shared=False, ipv6_ra_mode=None, ipv6_address_mode=None}>"

        
        ngfw_name = 'ngfw_' + router_id
        shim_name = 'shim_' + router_id
        policy_name = ngfw_name + "-policy"

        '''
        self._core_plugin.update_port(context.elevated(), dict_info['port_id'],
                                      {'port': {'tenant_id': cfg.CONF.NGFW.tenant_id,
                                                'device_id': ''
                                                }
                                       })
        '''
        
        new_port = self._core_plugin.create_port(context.elevated(), {
                                'port': {'tenant_id': cfg.CONF.NGFW.tenant_id,
                                         'network_id': subnet['network_id'],
                                         'mac_address': attributes.ATTR_NOT_SPECIFIED,
                                         'fixed_ips': attributes.ATTR_NOT_SPECIFIED,
                                         'device_owner': '',
                                         'device_id': '',
                                         'admin_state_up': True,
                                         'name': ''}})

        self._router2ports[router_id][router_port_id].append(new_port['id'])
               
        shim_vm = self._get_vm_by_name(shim_name)
        shim_vm.interface_attach(new_port['id'], None, None)
        
        '''
        # Change the device owner back to the router to let it show in horizon
        self._core_plugin.update_port(context.elevated(), dict_info['port_id'],
                                      {'port': {'tenant_id': cfg.CONF.NGFW.tenant_id,
                                                'device_id': router_id
                                                }
                                       })
        '''
        shim_port = self._core_plugin.create_port(context.elevated(), {
                                'port': {'tenant_id': cfg.CONF.NGFW.tenant_id,
                                         'network_id': cfg.CONF.NGFW.shim_network_id,
                                         'mac_address': attributes.ATTR_NOT_SPECIFIED,
                                         'fixed_ips': attributes.ATTR_NOT_SPECIFIED,
                                         'device_owner': '',
                                         'device_id': '',
                                         'admin_state_up': True,
                                         'name': ''}})
        self._pp.pprint(shim_port)
        self._router2ports[router_id][router_port_id].append(shim_port['id'])
        
        shim_vm.interface_attach(shim_port['id'], None, None)

        self._ngfw_add_new_ip(ngfw_name, gw_ip, subnet['cidr'])

        ngfw_network_ref = self._create_ngfw_network(ngfw_name, subnet['cidr'])
        
        policy_ref = self._get_ngfw_policy_ref(policy_name)

        rule_allow_to_any = {
                  "name" : subnet['cidr'] + '-allow_to_any',
                  "comment" : subnet['cidr'],
                  "action":
                          {
                                "action": 'allow',
                                "connection_tracking_options":
                                    {
                                    }
                           },
                          "destinations": { 'any' : True },
                          "services": { 'any' : True},
                          "sources": { "src" : [ ngfw_network_ref ] }
                          }

        smc_connection = self._smc_connection
        smc_connection.login()
        
        json_data = json.dumps(rule_allow_to_any)
        LOG.debug("Inserting rule rule_allow_to_any")
        r = smc_connection.post(policy_ref + "/fw_ipv4_access_rule", json_data)
        print r
        rule_allow_from_any = {
                               "name" : subnet['cidr'] + '-allow_from_any',
                               "comment" : subnet['cidr'],
                               "action" : {
                                           "action": 'allow',
                                           "connection_tracking_options":
                                                                        {
                                                                        }
                                           },
                               "destinations": { 'dst' : [ ngfw_network_ref ] },
                               "services": { 'any' : True},
                               "sources": { 'any' : True }
                               }

        json_data = json.dumps(rule_allow_from_any)
        LOG.debug("Inserting rule rule_allow_from any")
        r = smc_connection.post(policy_ref + "/fw_ipv4_access_rule", json_data)
        print r        

        # refresh the policy
        ngfw_ref = self._get_ngfw_ref(ngfw_name)
        #r = smc_connection.session.post(self._smc_ref + ngfw_ref + "/upload?filter={0}".format(policy_name))
        smc_connection.login()
        print self._smc_ref + ngfw_ref + "/refresh"
        r = smc_connection.session.post(self._smc_ref + ngfw_ref + "/refresh")
        print "XXXXX refreshing policy"
        print r
        # TODO: wait for refreshing to end
        smc_connection.logout()

    def remove_router_interface(self, context, router_id, dict_info, port):
        self._remove_router_interface(context, router_id,
                                      dict_info['subnet_id'],
                                      dict_info['port_id'],
                                      port.fixed_ips[0]['ip_address'])

    def _remove_router_interface(self, context, router_id, subnet_id, router_port_id, ip_address):
        ngfw_name = 'ngfw_' + router_id
        shim_name = 'shim_' + router_id
        policy_name = ngfw_name + "-policy"
        
        subnet = self._core_plugin._get_subnet(context, subnet_id)
        
        shim_vm = self._get_vm_by_name(shim_name)
        
        for port_id in self._router2ports[router_id][router_port_id]:
            shim_vm.interface_detach(port_id)
            self._core_plugin.delete_port(context, port_id, l3_port_check=False)

        policy_ref = self._get_ngfw_policy_ref(policy_name)
        
        smc_connection = self._smc_connection
        smc_connection.login()
        r = smc_connection.get(policy_ref + "/fw_ipv4_access_rule")
        r = r[0]['result']
        
        for l in r:
            rule_ref = str(l['href']).replace(self._smc_ref, '')
            rule = smc_connection.get(rule_ref)
            comment = rule[0]['comment']
            if comment == subnet['cidr']:
                smc_connection.delete(rule_ref)

        networks = smc_connection.get('elements/network')[0]['result']
        for net in networks:
            if net['name'] == "network-%s-%s" % (ngfw_name, subnet['cidr']):
                smc_connection.delete(str(net['href']).replace(self._smc_ref, ''))

        self._ngfw_delete_ip(ngfw_name, ip_address)
        
        # refresh the policy
        ngfw_ref = self._get_ngfw_ref(ngfw_name)
        smc_connection.login()
        #r = smc_connection.session.post(self._smc_ref + ngfw_ref + "/upload?filter={0}".format(policy_name))
        r = smc_connection.session.post(self._smc_ref + ngfw_ref + "/refresh")
        # TODO: wait for policy refreshing to end
        smc_connection.logout()

    def _create_ngfw_network(self, ngfw_name, cidr):
        net_json_def = {
                        #currently we do not support adding multiple interfaces to one subnet
                        "name" : "network-%s-%s" % (ngfw_name, str(cidr)),
                        "ipv4_network" : cidr
                       }

        json_data = json.dumps(net_json_def)
        smc_connection = self._smc_connection
        smc_connection.login()

        # public and internal network are pre-created in smp_api.createL3FW() if corresponding cidrs are passed in
        r = smc_connection.get("elements/network")
        networks = r[0]['result']
        for net in networks:
            if net['name'] == "network-%s-%s" % (ngfw_name, cidr):
                ref = net['href']
                smc_connection.logout()
                return ref

        r = smc_connection.post_element("network", json_data)
        smc_connection.logout()
        ref = r.headers['location']
        return ref

    def _get_vm_by_name(self, vm_name):
        servers = self._novaclient.servers.list()
        for server in servers:
            if server.name == vm_name:
                return server
        return None

    def _delete_vm_by_name(self, vm_name):
        vm = self._get_vm_by_name(vm_name)
        if vm == None:
            LOG.error("Failed to find VM with name {0}".format(vm_name))
            return
        self._novaclient.servers.delete(vm)

    def _ngfw_add_new_ip(self, ngfw_name, new_ip, cidr):
        
        ngfw_ref = self._get_ngfw_ref(ngfw_name)
        smc_connection = self._smc_connection
        smc_connection.login()
        r = smc_connection.get(ngfw_ref, etag=True)
        
        etag = r[1]
        data = r[0]
        self._pp.pprint(data)

        single_node_interface_template = {
            "single_node_interface": {
              "address": new_ip,
              "auth_request": False,
              "auth_request_source": False,
              "backup_heartbeat": False,
              "backup_mgt": False,
              "dynamic_ip": False,
              "igmp_mode": "none",
              "modem": False,
              "network_value": cidr,
              "nicid": "1",
              "nodeid": 1,
              "outgoing": False,
              "pppoa": False,
              "pppoe": False,
              "primary_heartbeat": False,
              "primary_mgt": False,
              "relayed_by_dhcp": False,
              "reverse_connection": False,
              "vrrp": False,
              "vrrp_id": -1,
              "vrrp_priority": -1
            }
        }

        itfce = None
        for phy_itfce in data["physicalInterfaces"]:
            if phy_itfce["physical_interface"]["interfaces"][0]["single_node_interface"]["address"] == "0.0.0.0":
                itfce = phy_itfce["physical_interface"]["interfaces"][0]["single_node_interface"]
                single_node_interface_template["single_node_interface"]["nicid"] = itfce["nicid"]
                single_node_interface_template["single_node_interface"]["nodeid"] = itfce["nodeid"]
                phy_itfce["physical_interface"]["interfaces"].append(single_node_interface_template)

        if itfce is None:
            LOG.error("Failed to look up NGFW outgoing interface")
            raise exceptions.Invalid
        
        #data["physicalInterfaces"][0]["physical_interface"]["interfaces"].append(single_node_interface_template)
        print "XXXXXXXXXXXXXXXXx"
        print
        print
        self._pp.pprint(data)

        data = json.dumps(data)
        r = smc_connection.put(ngfw_ref, data, etag=etag)
        smc_connection.logout()
        
    def _ngfw_delete_ip(self, ngfw_name, delete_ip):
        
        ngfw_ref = self._get_ngfw_ref(ngfw_name)
        smc_connection = self._smc_connection
        smc_connection.login()
        r = smc_connection.get(ngfw_ref, etag=True)
        
        etag = r[1]
        data = r[0]
        self._pp.pprint(data)
 
        
        found = False
        for phy_itfce in data["physicalInterfaces"]:
            index = 0
            for itfce in phy_itfce["physical_interface"]["interfaces"]:
                print "interface address = %s delete_ip = %s" % (itfce['single_node_interface']['address'], delete_ip)
                if itfce['single_node_interface']['address'] == delete_ip:
                    phy_itfce["physical_interface"]["interfaces"].pop(index)
                    found = True
                    break
                index += 1
                
        print "XXXXXXXXXXXXXXXXx"
        print
        print
        
        if not found:
            LOG.error("Can not find the ip address in SMC")
            raise exceptions.Invalid
        
        self._pp.pprint(data)

        data = json.dumps(data)
        r = smc_connection.put(ngfw_ref, data, etag=etag)
        smc_connection.logout()

    def create_floatingip(self, router_id, internal_ip, external_ip, external_cidr):
        internal_host = self._ngfw_create_host(internal_ip)
        external_host = self._ngfw_create_host(external_ip)
        
        policy_name = 'ngfw_' + router_id + '-policy'
        
        policy_ref = self._get_ngfw_policy_ref(policy_name)
              
        nat_rule = {
                    "name" : external_ip + "nat rule",
                    "destinations": { 'dst' : [ external_host ] },
                    "options" : {
                                 "name": external_ip + "nat rule options",
                                 "static_dst_nat": {
                                                    "name": external_ip + "static dst nat",
                                                    "automatic_proxy": True,
                                                    "original_value": { "ip_descriptor": external_ip,
                                                                        "element": external_host },
                                                    "translated_value": {
                                                                          "ip_descriptor": internal_ip,
                                                                          "element": internal_host}
                                                    }
                                 },
                    "services": { 'any' : True},
                    "sources": { 'any' : True }
                    }

        print nat_rule
        json_data = json.dumps(nat_rule)
        LOG.debug("Inserting static dst NAT rule")
                
        smc_connection = self._smc_connection
        smc_connection.login()
        print policy_ref + "/fw_ipv4_nat_rule"
        print "XXXXXXX"
        print "XXXXXXX"
        print "XXXXXXX"
        print json_data
        r = smc_connection.post(policy_ref + "/fw_ipv4_nat_rule", json_data)
        self._pp.pprint(r)
        smc_connection.logout()
        
        self._ngfw_add_new_ip("ngfw_" + router_id, external_ip, external_cidr)
        
        ngfw_ref = self._get_ngfw_ref('ngfw_' + router_id)
        smc_connection.login()
        print self._smc_ref + ngfw_ref + "/refresh"
        r = smc_connection.session.post(self._smc_ref + ngfw_ref + "/refresh")
        print "XXXXX refreshing policy"
        print r
        # TODO: wait for refreshing to end
        smc_connection.logout()

        
    
    def delete_floatingip(self, router_id, external_ip, internal_ip):
        policy_name = 'ngfw_' + router_id + '-policy'
        policy_ref = self._get_ngfw_policy_ref(policy_name)
        nat_rule_name = external_ip + 'nat rule'
        smc_connection = self._smc_connection
        smc_connection.login()
        r = smc_connection.get(policy_ref + "/fw_ipv4_nat_rule?filter={0}".format(nat_rule_name))
        rule_ref = r[0]['result'][0]['href']
        rule_ref = str(rule_ref).replace(self._smc_ref, '')
        smc_connection.delete(rule_ref)
        
        r = smc_connection.get('elements/host?filter=floatingip-host-{0}'.format(external_ip))
        external_host = r[0]['result'][0]['href']
        external_host = str(external_host).replace(self._smc_ref, '')
        r = smc_connection.delete(external_host)
        print "XXXXXXXXX delete external host result"
        print r

        r = smc_connection.get('elements/host?filter=floatingip-host-{0}'.format(internal_ip))
        internal_host = r[0]['result'][0]['href']
        internal_host = str(internal_host).replace(self._smc_ref, '')
        r = smc_connection.delete(internal_host)
        print "XXXXXXXXX delete internal host result"
        print r    
    
        smc_connection.logout()

    def _ngfw_create_host(self, host_ip):
        host_json_def = {
                       "name": "floatingip-host-%s" % str(host_ip),
                       "address": host_ip
                       }

        json_data = json.dumps(host_json_def)

        smc_connection = self._smc_connection
        smc_connection.login()
        r = smc_connection.post_element("host", json_data)
        smc_connection.logout()
        ref = r.headers['location']
        
        return ref

        
class VmStatusError(exceptions.NeutronException):
    def __init__(self, vm_type):
        """ vm_type is 'ngfw' or 'shim' """
        self._vm_type = vm_type

    def __str__(self):
        return "Failed to spawn {0} VM instance".format(self._vm_type)

class TimeoutException(exceptions.NeutronException):
    message = _("Waiting VM spawn timed out")

class NoRouterException(exceptions.NeutronException):
    message = _("Failed to get Router reference in SMC")
