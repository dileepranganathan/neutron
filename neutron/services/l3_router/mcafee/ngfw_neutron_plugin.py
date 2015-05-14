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

import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc

from oslo.config import cfg
from oslo.utils import importutils

from neutron.db import common_db_mixin
from neutron.db import extraroute_db
from neutron.db import l3_gwmode_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.api.rpc.agentnotifiers import l3_rpc_agent_api
from neutron.api.rpc.handlers import l3_rpc
from neutron.common import constants as q_const
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.db import l3_hascheduler_db
from neutron.db.l3_db import RouterPort
from neutron.plugins.common import constants
from neutron.services.l3_router.mcafee import ngfw_driver
#from neutron.openstack.common import log as logging
from oslo_log import log as logging
from neutron.db import l3_db
from neutron.extensions import l3
import pprint

LOG = logging.getLogger(__name__)

class NgfwRouterPlugin(common_db_mixin.CommonDbMixin,
                       extraroute_db.ExtraRoute_dbonly_mixin,
                       l3_gwmode_db.L3_NAT_db_mixin,
                       l3_hascheduler_db.L3_HA_scheduler_db_mixin):
    """
    McAfee Neutron L3 plugin for NGFW
    """

    supported_extension_aliases = ["router", "ext-gw-mode", "extraroute"]

    def __init__(self):
        LOG.debug("XXXXXXX__init__()")
        super(NgfwRouterPlugin, self).__init__()
        self.setup_rpc()
        LOG.debug("XXXXXXX 1 __init__()")

        self.router_scheduler = importutils.import_object(
            cfg.CONF.router_scheduler_driver)
        LOG.debug("XXXXXXX 2 __init__()")
        #self.start_periodic_agent_status_check()

        LOG.debug("XXXXXXX 3 __init__()")
        self.driver = ngfw_driver.NgfwRouterDriver()
        LOG.debug("XXXXXXX 4 __init__()")

        self._pp=pprint.PrettyPrinter()
        LOG.debug("XXXXXXX end of __init__()")

    def setup_rpc(self):
        # RPC support
        self.topic = topics.L3PLUGIN
        self.conn = n_rpc.create_connection(new=True)
        self.agent_notifiers.update(
            {q_const.AGENT_TYPE_L3: l3_rpc_agent_api.L3AgentNotifyAPI()})
        self.endpoints = [l3_rpc.L3RpcCallback()]
        self.conn.create_consumer(self.topic, self.endpoints,
                                  fanout=False)
        self.conn.consume_in_threads()

    def get_plugin_type(self):
        return constants.L3_ROUTER_NAT

    def get_plugin_description(self):
        """Returns string description of the plugin"""
        return ("McAfee NGFW Router Service Plugin for basic L3 forwarding "
                "between neutron networks and external networks")

    # Replace _create_router_db in l3_db.L3_NAT_dbonly_mixin
    # To use router['id'] (which is the random number in ngfw/shim VM name) as router ID
    def _create_router_db(self, context, router, tenant_id):
        """Create the DB object."""
        with context.session.begin(subtransactions=True):
            # pre-generate id so it will be available when
            # configuring external gw port
            router_db = l3_db.Router(id=router['id'],
                               tenant_id=tenant_id,
                               name=router['name'],
                               admin_state_up=router['admin_state_up'],
                               status="ACTIVE")
            context.session.add(router_db)
            return router_db

    def create_router(self, context, router):
    
        #router['router']['id'] = 1234
        router['router']['id'] = self.driver.create_router(context, router)

        router_dict = super(NgfwRouterPlugin, self).create_router(context, router)

        if router_dict[l3.EXTERNAL_GW_INFO]:
            gw_port_id = router_dict['gw_port_id']
            self.driver._add_router_interface(context, router_dict['id'], gw_port_id)

        return router_dict

    def update_router(self, context, router_id, router):
        '''
        self.driver.update_router(context, router_id, router)
        '''

        r = self._get_router(context, router_id)
        print "XXXXXXXXXX"
        self._pp.pprint(r)
        
        if r['gw_port_id']:
            old_gw_port_id = r['gw_port_id']
            old_gw_port = self._core_plugin._get_port(context.elevated(), old_gw_port_id)
            subnet_id = old_gw_port['fixed_ips'][0]['subnet_id']
            ip_address = old_gw_port['fixed_ips'][0]['ip_address']
            print "XXXXXXXXXXXXXXX in update_router XXXXXXXXXXX"
            print "ip_address = " + ip_address
            self.driver._remove_router_interface(context, router_id, subnet_id, old_gw_port_id, ip_address)

        dict_info = super(NgfwRouterPlugin, self).update_router(context, router_id, router)

        print "XXXXXXXXXX"
        self._pp.pprint(dict_info)

        if dict_info[l3.EXTERNAL_GW_INFO]:
            self.driver._add_router_interface(context, router_id, dict_info['gw_port_id'])
        else:
            print "XXXXXXX"
            LOG.debug("update_router without gw info")
        
        return dict_info
    def delete_router(self, context, router_id):
        """
        with context.session.begin(subtransactions=True):
            qry = context.session.query(Ngfw_db)
            ngfw_db = qry.filter_by(router_id=router_id)
            print "XXXXXXXXXXX"
            print ngfw_db
            print ngfw_db[0]
            context.session.delete(ngfw_db[0])
        """
        self.driver.delete_router(context, router_id)
        return super(NgfwRouterPlugin, self).delete_router(context, router_id)

    # l3_db.L3_NAT_dbonly_mixin add_router_interface() set the device owner to 
    # DEVICE_OWNER_ROUTER_INTF, may need to unset to get the port attached to shim_VM
    #def _get_device_owner(self, context, router_id):
    #    return ''

    def add_router_interface(self, context, router_id, interface_info):
        self._pp.pprint(interface_info)
        "{u'subnet_id': u'bf2b05a0-679a-4b91-a82e-863ad9bf53b4'}"
        # if it is subnet, l3_db.add_router_interface will create the port on behalf of us
        dict_info = super(NgfwRouterPlugin, self).add_router_interface(context, router_id, interface_info)

        print "XXXXXXXXXXXX add_router_interface() print dict_info"
        print dict_info
        "{'subnet_id': u'bf2b05a0-679a-4b91-a82e-863ad9bf53b4', 'tenant_id': u'de37d87e3f214b87a2290f04bf0ce17e', 'port_id': '1b7c11af-e3c9-4159-a649-ecf0248b80f3', 'id': u'1234'}"
        self.driver.add_router_interface(context, router_id, dict_info)
        #self.notify_router_interface_action(context, dict_info, 'add')
        
        return dict_info

    def remove_router_interface(self, context, router_id, interface_info):
        port_id = interface_info.get('port_id')
        subnet_id = interface_info.get('subnet_id')
        port = None

        if port_id:
            port = self._core_plugin._get_port(context.elevated(), interface_info.get('port_id'))

        elif subnet_id:
            subnet = self._core_plugin._get_subnet(context, subnet_id)
            device_owner = self._get_device_owner(context, router_id)
            ports = None

            try:
                rport_qry = context.session.query(models_v2.Port).join(RouterPort)
                ports = rport_qry.filter(
                    RouterPort.router_id == router_id,
                    RouterPort.port_type == device_owner,
                    models_v2.Port.network_id == subnet['network_id']
                )
            except exc.NoResultFound:
                raise l3.RouterInterfaceNotFoundForSubnet(router_id=router_id,
                                                      subnet_id=subnet_id)

            port = ports[0]
 
        dict_info = super(NgfwRouterPlugin, self).remove_router_interface(context, router_id, interface_info)
        self.driver.remove_router_interface(context, router_id, dict_info, port)
        #self.notify_router_interface_action(context, dict_info, 'remove')
        return dict_info

    def create_floatingip(self, context, floatingip):
        fip_dict =  super(NgfwRouterPlugin, self).create_floatingip(context, floatingip)
        
        if fip_dict['fixed_ip_address'] is None:
            return fip_dict
        
        floating_network_id = fip_dict['floating_network_id']
        floating_subnet = self._core_plugin._get_subnets_by_network(context,
                                                                floating_network_id)[0]
        external_cidr = floating_subnet['cidr']
        external_ip = fip_dict['floating_ip_address']
        internal_ip = fip_dict['fixed_ip_address']
        router_id = fip_dict['router_id']
        self.driver.create_floatingip(router_id, internal_ip, external_ip, external_cidr)
        
        return fip_dict

    def update_floatingip(self, context, floatingip_id, floatingip):
        fip = floatingip['floatingip']
        #return super(NgfwRouterPlugin, self).update_floatingip(context, floatingip_id, floatingip)
        if fip['port_id'] is None:
            fip_db = self._get_floatingip(context, floatingip_id)
            router_id = fip_db['router_id']
            external_ip = fip_db['floating_ip_address']
            internal_ip = fip_db['fixed_ip_address']
            self.driver.delete_floatingip(router_id, external_ip, internal_ip)
            return super(NgfwRouterPlugin, self).update_floatingip(context, floatingip_id, floatingip)
        
        fip_dict = super(NgfwRouterPlugin, self).update_floatingip(context, floatingip_id, floatingip)
        
        floating_network_id = fip_dict['floating_network_id']
        floating_subnet = self._core_plugin._get_subnets_by_network(context,
                                                                floating_network_id)[0]
        external_cidr = floating_subnet['cidr']
        external_ip = fip_dict['floating_ip_address']
        internal_ip = fip_dict['fixed_ip_address']
        router_id = fip_dict['router_id']
        self.driver.create_floatingip(router_id, internal_ip, external_ip, external_cidr)
        
        return fip_dict

    def delete_floatingip(self, context, floatingip_id):
        floatingip = self._get_floatingip(context, floatingip_id)
        router_id = floatingip['router_id']
        external_ip = floatingip['floating_ip_address']
        internal_ip = floatingip['fixed_ip_address']
        if router_id:
            ''' router_id is None means the floatingip is not associated with any router '''
            self.driver.delete_floatingip(router_id, external_ip, internal_ip)
        
        return super(NgfwRouterPlugin, self).delete_floatingip(context, router_id)

    '''
    def disassociate_floatingips(self, context, port_id, do_notify=True):
        pass

    def disassociate_floatingip(self, context, router_id, floatingip):
        pass
    
    def notify_routers_updated(self, context, router_ids):
        """
        core plugin delete_port needs this, need to understand more
        """
        pass
    '''
