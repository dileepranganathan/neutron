import traceback
import sys, json, requests
import netaddr
import pprint

from oslo.config import cfg

#
# Edit IP and PORT for you SMC
#HOST_URL="http://172.24.4.4:8082"
#HOST_URL=cfg.CONF.ngfw.smc_url
DEBUG = True
# Get this from SMC Administrations-> Access Rights -> API Clients
#SMC_API_AUTH_KEY="vGEv9qAoYCbTwhonV8Bi0001"
#SMC_API_AUTH_KEY=cfg.CONF.ngfw.smc_api_auth_key
DEFAULT = 0
CAPTURE = 1
JSON_DATA = 0
ETAG = 1


def usage(extra_info = None):
    print
    print(sys.argv[0] + " element_type element_name control_ip/XX")
    print("   Where element_type  L2FW or L3FW")
    print
    if extra_info:
        print("Error -> %s\n" % extra_info)
    exit(1)



class SMCAPIResult:
    def __init__(self, type):
        self.type = type
        self.result = None
        self.code = "200"
        self.headers = None

    def is_json(self):
        return self.type == "json"

    def is_text(self):
        return self.type == "text"

    def __str__(self):
        return self.result



class SMCAPIConnection:

    def __init__(self, host, api_version, authentication_key):
        self.cookies = {}
        self.host = host
        self.api_version = api_version
        self.host_api_url = self.host + "/" + self.api_version
        self.auth_key = authentication_key
        self.session = None

    def login(self):
        self.session = requests.session()
        try:
            res = self.session.post("%s/login?authenticationkey=%s&beta=true" %
                                    (self.host_api_url, self.auth_key))
            if res.status_code != 200:
                print("Authentication to %s failed (%s/ code %s)" %
                      (self.host, res.net_http_res.message, res.status_code))
                return

        #print "RES #{res.raw_headers}"
        #print "body #{body.headers}"
        #self.cookies = "JSESSIONID=#{res.cookies['JSESSIONID']}"
        except Exception, e:
            print("Could not connect to %s: %s" % (self.host, e))
            return

    def logout(self):
        """ Logout """
        result = self.session.put("%s/logout" % (self.host_api_url))
        print result

    def put(self, path, json_element, etag=None):
        headers = {'accept': '*/*',
                   'content-type': 'application/json'}
        if etag:
            headers['etag'] = etag 

        json_result = SMCAPIResult("text")
        json_result.result = "N/A"
        try:
            result = self.session.put("%s/%s" % (self.host_api_url,path),
                                       data = json_element, headers = headers)
            if result.status_code == "404":
                print("SMC Error 404 %s" % (result.reason))
        
            #print Nokogiri::HTML(res.body).text
            elif result.status_code != 200:
                if DEBUG:
                    print("POST ELEMENT result code: %s/%s (%s)" %
                          (result.status_code, result.reason, result.text))
                    print("for path %s/%s" % (self.host_api_url, path))
                json_result.type = "text"
                json_result.result = result.text
            else:
                if result.headers.get('content-type') == "application/json":
                    json_result.type = "json"
                    json_result.result = result.json
                else:
                    json_result.type = "text"
                    json_result.result = result.content
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print "Error Post %s %s %s %s" % (path, e, exc_type, traceback.format_exc())

        json_result.code = result.status_code
        json_result.headers = result.headers
        return json_result

    def post(self, path, json_element):
        headers = {'accept': '*/*',
                   'content-type': 'application/json'}
        json_result = SMCAPIResult("text")
        json_result.result = "N/A"
        try:
            result = self.session.post("%s/%s" % (self.host_api_url,path),
                                       data = json_element, headers = headers)
            if result.status_code == "404":
                print("SMC Error 404 %s" % (result.reason))

            elif result.status_code != 200:
                if DEBUG:
                    print("POST ELEMENT result code: %s/%s (%s)" %
                          (result.status_code, result.reason, result.text))
                    print("for path %s/%s" % (self.host_api_url, path))
                json_result.type = "text"
                json_result.result = result.text
            else:
                if result.headers.get('content-type') == "application/json":
                    json_result.type = "json"
                    json_result.result = result.json
                else:
                    json_result.type = "text"
                    json_result.result = result.content
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print "Error Post %s %s %s %s" % (path, e, exc_type, traceback.format_exc())
            raise

        json_result.code = result.status_code
        json_result.headers = result.headers
        return json_result

    def post_element(self, element_type, json_element):
        return self.post("elements/%s" % (element_type), json_element)

    def get(self, path, etag = None):
        json_result = None
        etag_out = None
        headers = {'accept': 'application/json',
                   'content-type': 'application/json'}
        if etag:
            headers['etag'] = etag

        try:
            result = self.session.get("%s/%s" % (self.host_api_url, path),
                                      headers = headers);
            if DEBUG:
                print "RES %s" %(result.headers)
            if result.headers.__contains__('etag'):
                etag_out = result.headers['etag']
        #print "body #{body.headers}"

            try:
                json_result = result.json()
            except Exception, json_exc:
                print "Could not get the data:"
                print
                print result.content
                print
                raise

            if result.status_code == "404":
                print json_result["message"]
                print json_result["details"]

        except Exception, e:
            print "EX: %s  "  % ( e )
            raise

        r = [json_result]
        if etag_out:
            r.append(etag_out)
        return r

    def delete(self, path):
        json_result = SMCAPIResult("text")
        json_result.result = "N/A"
        try:
            result = self.session.delete("%s/%s" % (self.host_api_url,path))
            if result.status_code == "404":
                print("SMC Error 404 %s" % (result.reason))

            elif result.status_code != 200:
                if DEBUG:
                    print("POST ELEMENT result code: %s/%s (%s)" %
                          (result.status_code, result.reason, result.text))
                    print("for path %s/%s" % (self.host_api_url, path))
                json_result.type = "text"
                json_result.result = result.text
            else:
                if result.headers.get('content-type') == "application/json":
                    json_result.type = "json"
                    json_result.result = result.json
                else:
                    json_result.type = "text"
                    json_result.result = result.content
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print "Error Post %s %s %s %s" % (path, e, exc_type, traceback.format_exc())

        json_result.code = result.status_code
        return json_result

class SMCAPIElement:
    def __init__(self, name, smc_api_connection, control_ip = None):
        self.element_type = "N/A"

        if not name:
            usage("name of element missing.")

        self.name = name
        self.element_id = 0
        self.json_element = None
        self.element_template = None
        self.smc_api_connection = smc_api_connection
        self.keyboard = None
        self.timezone = None
        if control_ip:
            self.control_ip = netaddr.IPNetwork(control_ip)
            if self.control_ip.prefixlen == 32:
                usage("Control_ip %s needs to netmask bits e.g x.x.x.x/yy" %
                      (self.control_ip))
        else:
            self.control_ip = None

    def to_json(self):
        return json.dumps(self.json_element)

    def create(self):
        raise("Not Implemented")

    def update(self):
        raise("Not Implemented")

    def delete(self):
        raise("Not Implemented")

    def get_element(self, path):
        if DEBUG:
            print "Getting path: %s" % (path)
        return self.smc_api_connection.get("elements/%s" % (path))

    def get_elements(self, element_type=None):
        if not element_type:
            element_type = self.element_type

        return self.smc_api_connection.get("elements/%s" % (element_type))

    def fetch_element_id(self):
        json_result = self.get_elements()

        if not json_result[JSON_DATA]['result']:
            print "No #{element_type} defined in SMC"
        else:
            for element in json_result[JSON_DATA]['result']:
                href = element['href']
                self.element_id = int(href.split('/')[-1])
                if element['name'] == self.name:
                    if DEBUG:
                        print("%s element with name %s FOUND %s" %
                              (self.element_type, self.name, href))
                    break

        if DEBUG:
            print "Got ID %s" % (self.element_id)

        return self.element_id

    def get_initial_contact_data(self):
        data = None
        result = self.get_element("%s/%s/node" %
                                  (self.element_type,self.element_id))
        if DEBUG:
            print result
            print result[JSON_DATA]

        node_ref = result[JSON_DATA]['result'][0]['href'].replace(
                    self.smc_api_connection.host_api_url + "/elements/", "")

        if DEBUG:
            print "Node ref is %s" % (node_ref)

        extra_options = []
        if self.keyboard:
            extra_options.append("keyboard=%s" % (self.keyboard))   
        if self.timezone:
            extra_options.append("time_zone=%s" % (self.timezone))

        if extra_options:
            extra_options = "&".join(extra_options)
            extra_options = "&" + extra_options
        else:
            extra_options = ""
    
        result = self.smc_api_connection.post_element(
                                                      "%s/initial_contact?enable_ssh=true%s" %
                                                      (node_ref, extra_options), "")
        if result.is_text():
            d1 = result.__str__().split("\n")
            idx = 0
            for l in d1:
                if l.find("ssh/enabled") != -1:
                    l = l.replace("false", "true")
                    d1[idx] = l
            #if l.find("XXXXsystem/keymap") != -1:
            #    l = l.replace("null", "i386/qwerty/fi-latin1")
            #    d1[idx] = l
                idx += 1
            result.result = "\n".join(d1)
            data = result

        result = self.smc_api_connection.post_element(
                    "%s/bind_license" % (node_ref), "")

        if result.code != 200:
            print "#"
            print "# Could not bind license. Maybe SMC license pool " \
                "is empty"
            print "# SMC API details:"
            print "# %s" % (result)

        return data


class SMCAPIElementL2FWSingle(SMCAPIElement):

    def __init__(self, name, smc_api_connection, control_ip):
        SMCAPIElement.__init__(self, name, smc_api_connection, control_ip)
        self.element_type = "single_layer2"
        self.element_id = 0
        self.json_element = None
        self.element_template = """
{
  "log_server_ref":"http://localhost:8082/5.7/elements/log_server/1441",
  "name":"@PLACE_HOLDER@ L2 FW",
  "nodes":
  [
   {
     "fwlayer2_node":{
       "name":"@PLACE_HOLDER@ L2 FW node 1",
       "nodeid":1
     }
   }
  ],
  "physicalInterfaces":
  [
   {
     "physical_interface":{
       "interface_id":"1",
       "interfaces":
       [
        {
          "inline_interface":{
            "failure_mode":"normal",
            "logical_interface_ref":"http://localhost:8082/5.7/elements/logical_interface/1",
            "nicid":"1-2"
          }
        }
       ]
     }
   },
   {
     "physical_interface":{
       "interface_id":"0",
       "interfaces":
       [
        {
          "node_interface":{
            "address":"192.168.2.10",
            "network_value":"192.168.2.0/24",
            "nicid":"0",
            "nodeid":1,
            "outgoing":true,
            "primary_mgt":true
          }
        }
       ]
     }
   } ,
   {
     "physical_interface":{
       "interface_id":"3",
       "interfaces":
       [
        {
          "capture_interface":{
            "logical_interface_ref":"http://localhost:8082/5.7/elements/logical_interface/1073741835",
            "nicid":"3"
          }
        }
       ]
     }
   }
  ]
}
"""

    def create(self):
        logical_interfaces = [None, None]
        found = 0;
        json_result = self.get_elements("log_server")
        log_server_ref = json_result[JSON_DATA]['result'][0]['href']
        if DEBUG:
            print("Using log server '%s', ref %s" %
                  (json_result[JSON_DATA]['result'][0]['name'],
                   log_server_ref))

        json_result = self.get_elements("logical_interface")
        for logical_iface in json_result[JSON_DATA]['result']:

            if (logical_iface['name'] != "default_eth" or
                logical_iface['name'] != 'capture'):
                    next

            if logical_iface['name'] == 'default_eth':
                logical_interfaces[DEFAULT] = {}
                logical_interfaces[DEFAULT]['href'] = logical_iface['href']
                logical_interfaces[DEFAULT]['name'] = logical_iface['name']
                found += 1
            if logical_iface['name'] == 'capture':
                logical_interfaces[CAPTURE] = {}
                logical_interfaces[CAPTURE]['href'] = logical_iface['href']
                logical_interfaces[CAPTURE]['name'] = logical_iface['name']
                found += 1

            if found == 2:
                break

        if DEBUG:
            print("Using logical interface %s ref %s" %
                  (logical_interfaces[DEFAULT]['name'],
                   logical_interfaces[DEFAULT]['href']))
            print("Using capture interface %s ref %s" %
                  (logical_interfaces[CAPTURE]['name'],
                   logical_interfaces[CAPTURE]['href']))

        json_data = json.loads(self.element_template)

        json_data['log_server_ref'] = log_server_ref
        json_data['name'] = self.name
        json_data['nodes'][0]['fwlayer2_node']['name'] = self.name + " node 1"

        physical_ifaces = json_data['physicalInterfaces']
        #print physical_ifaces
        for phys_iface in physical_ifaces:
            #print phys_iface
            for iface in phys_iface['physical_interface']['interfaces']:
                #print iface['inline_interface']
                if 'inline_interface' in iface:
                    inline_iface = iface['inline_interface']
                    if DEBUG:
                        print("FFF %s" % (inline_iface))
                    inline_iface['logical_interface_ref'] = \
                        logical_interfaces[DEFAULT]['href']
                elif 'capture_interface' in iface:
                    capture_iface = iface['capture_interface']
                    capture_iface['logical_interface_ref'] = \
                        logical_interfaces[CAPTURE]['href']
                elif 'node_interface' in iface:
                    node_iface = iface['node_interface']
                    if not node_iface['primary_mgt']:
                        next
                    node_iface['address'] = str(self.control_ip.ip)
                    node_iface['network_value'] = str(self.control_ip.cidr)

        self.json_element = json_data
        self.smc_api_connection.post_element(self.element_type, self.to_json())
        self.fetch_element_id()

    def update(self):
        """ Update element """

    def delete(self):
        """ Delete element """


class SMCAPIElementL3FWSingle(SMCAPIElement):
    def __init__(self, name, smc_api_connection, control_ip):
        SMCAPIElement.__init__(self, name, smc_api_connection, control_ip)
        self.element_type = "single_fw"
        self.element_id = 0
        self.json_element = None
        self.element_template = """
         {
         "alias_value": [
         ],
         "antivirus": {
         "antivirus_enabled": false,
         "virus_log_level": "none",
         "virus_mirror": "database.clamav.net"
         },
         "auto_reboot_timeout": 10,
         "connection_limit": 0,
         "connection_timeout": [
         {
         "protocol": "icmp",
         "timeout": 5
         },
         {
         "protocol": "other",
         "timeout": 180
         },
         {
         "protocol": "tcp",
         "timeout": 1800
         },
         {
         "protocol": "udp",
         "timeout": 50
         }
         ],
         "contact_timeout": 60000,
         "default_nat": false,
         "domain_server_address": [
         ],
         "dos_protection": "always_off",
         "excluded_interface": -1,
         "is_cert_auto_renewal": true,
         "is_config_encrypted": true,
         "is_fips_compatible_operating_mode": false,
         "is_loopback_tunnel_ip_address_enforced": false,
         "is_virtual_defrag": true,
         "log_moderation": [
         {
         "burst": 1000,
         "log_event": "1",
         "rate": 100
         },
         {
         "log_event": "2"
         }
         ],
         "log_server_ref": "@PLACE_HOLDER@",
         "log_spooling_policy": "discard",
         "loopback_cluster_virtual_interface": [
         ],
         "name": "@PLACE_HOLDER@",
         "nodes": [
         {
         "firewall_node": {
         "activate_test": true,
         "disabled": false,
         "loopback_node_dedicated_interface": [
         ],
         "name": "@NODE_NAME_PLACE_HOLDER@",
         "nodeid": 1
         }
         }
         ],
         "passive_discard_mode": false,
         "physicalInterfaces": [
         ],
         "read_only": false,
         "rollback_timeout": 60,
         "scan_detection": {
         "scan_detection_icmp_events": 252,
         "scan_detection_icmp_timewindow": 60,
         "scan_detection_tcp_events": 252,
         "scan_detection_tcp_timewindow": 60,
         "scan_detection_type": "default off",
         "scan_detection_udp_events": 252,
         "scan_detection_udp_timewindow": 60
         },
         "slow_request_blacklist_timeout": 300,
         "slow_request_sensitivity": "off",
         "strict_tcp_mode": false,
         "syn_flood_sensitivity": "off",
         "syn_mode": "off",
         "system": false,
         "tcp_reset_sensitivity": "OFF",
         "tester_parameters": {
         "alert_interval": 3600,
         "auto_recovery": true,
         "boot_delay": 30,
         "boot_recovery": true,
         "restart_delay": 5,
         "status_delay": 5
         },
         "tracking_mode": "normal"
         }
         """
        self.physical_interfaces = []

    def modify_interface_property(self, physical_interface, name, value):
        iface = physical_interface['physical_interface']
        iface = iface['interfaces'][0]['single_node_interface']
        iface[name] = value

    def add_physical_interface(self, ip_and_network, interface_id):
        ip = netaddr.IPNetwork(ip_and_network)
        physical_interface_template = """
{
   "physical_interface": {
        "aggregate_mode": "none",
        "arp_entry": [

        ],
        "cvi_mode": "none",
        "dhcp_server_on_interface": {
          "dhcp_range_per_node": [

          ]
        },
        "interface_id": "@PLACE_HODLER@",
        "interfaces": [
          {
            "single_node_interface": {
              "address": "@PLACE_HOLDER_IP@",
              "auth_request": false,
              "auth_request_source": false,
              "backup_heartbeat": false,
              "backup_mgt": false,
              "dynamic_ip": false,
              "igmp_mode": "none",
              "key": 200,
              "modem": false,
              "network_value": "@PLACE_HOLDER_IP_NETWORK@",
              "nicid": "0",
              "nodeid": 1,
              "outgoing": false,
              "pppoa": false,
              "pppoe": false,
              "primary_heartbeat": false,
              "primary_mgt": false,
              "relayed_by_dhcp": false,
              "reverse_connection": false,
              "vrrp": false,
              "vrrp_id": -1,
              "vrrp_priority": -1
            }
          }
        ],
        "log_moderation": [
          {
            "burst": 1000,
            "log_event": "1",
            "rate": 100
          },
          {
            "log_event": "2"
          }
        ],
        "managed_address_flag": false,
        "mtu": -1,
        "other_configuration_flag": false,
        "qos_limit": -1,
        "qos_mode": "no_qos",
        "router_advertisement": false,
        "syn_mode": "default",
        "virtual_engine_vlan_ok": false,
        "vlanInterfaces": [
        ]
      }
}
"""
        json_data = json.loads(physical_interface_template)
        phys_iface = json_data['physical_interface']
        phys_iface['interface_id'] = interface_id
        iface = json_data['physical_interface']['interfaces'][0]
        iface = iface['single_node_interface']
        iface['address'] = str(ip.ip)
        iface['network_value'] = str(ip.cidr)
        self.physical_interfaces.append(json_data)
        return json_data

    def create(self):
        json_result = self.get_elements("log_server")
        log_server_ref = json_result[JSON_DATA]['result'][0]['href']

        if DEBUG:
            print("Using log server '%s' ref %s" %
                  (json_result[JSON_DATA]['result'][0]['name'], log_server_ref))

        json_data = json.loads(self.element_template)
        json_data['log_server_ref'] = log_server_ref
        json_data['name'] = self.name
        json_data['nodes'][0]['firewall_node']['name'] = self.name + " node 1"
        iface = self.add_physical_interface(self.control_ip, 0)
        self.modify_interface_property(iface, "primary_mgt", True)
        for phys_iface in self.physical_interfaces:
            json_data['physicalInterfaces'].append(phys_iface)

        if DEBUG:
            print json.dumps(json_data, sort_keys=False,
                             indent=2, separators=(',', ': '))
        self.json_element = json_data
        self.smc_api_connection.post_element(self.element_type, self.to_json())
        self.fetch_element_id()

def create_L3FW(name, manage_ip, out_going_ip=None):

    smc_connection = SMCAPIConnection(cfg.CONF.NGFW.smc_url,
                                      cfg.CONF.NGFW.smc_api_version,
                                      cfg.CONF.NGFW.smc_api_auth_key)
    smc_connection.login()
    l3fw = SMCAPIElementL3FWSingle(name,
                                   smc_connection, manage_ip)
    iface_ip = '0.0.0.0/24'
    if out_going_ip:
        iface_ip = out_going_ip

    iface = l3fw.add_physical_interface(iface_ip, 1)
    l3fw.modify_interface_property(iface, "auth_request_source", True)
    l3fw.modify_interface_property(iface, "outgoing", True)
    l3fw.modify_interface_property(iface, "auth_request", True)
    #l3fw.add_physical_interface(ip2, 2)
        #l3fw.keyboard = "Finnish"
    l3fw.keyboard = "US English"
    l3fw.timezone = "UTC"
    l3fw.create()
    contact = l3fw.get_initial_contact_data()
    #f = open("/tmp/engine.cfg", "w")
    #f.write(str(contact))
    smc_connection.logout()
    return str(contact)
 
if __name__ == "__main__":
    create_L3FW()
    exit(0)
    try:
        if len(sys.argv) < 4:
            usage("Need correct amount of arguments")
        if sys.argv[1] != "L3FW" and sys.argv[1] != "L2FW":
            usage("incorrect element type %s" % (os.argv[1]))
    except Exception, e:
        usage("Could not resolve element name")

    smc_connection = SMCAPIConnection(HOST_URL, "5.7", SMC_API_AUTH_KEY)
    smc_connection.login()

    if sys.argv[1] == "L3FW":
        l3fw = SMCAPIElementL3FWSingle(sys.argv[2],
                                       smc_connection, sys.argv[3])
        iface = l3fw.add_physical_interface("1.1.1.1/24", 1)
        l3fw.modify_interface_property(iface, "auth_request_source", True)
        l3fw.modify_interface_property(iface, "outgoing", True)
        l3fw.modify_interface_property(iface, "auth_request", True)
        l3fw.add_physical_interface("1.1.3.1/24", 2)
        #l3fw.keyboard = "Finnish"
        l3fw.keyboard = "US English"
        l3fw.timezone = "UTC"
        l3fw.create()
        print l3fw.get_initial_contact_data()
    elif sys.argv[1] == "L2FW":
        if DEBUG:
            print("l2fw")
        l2fw = SMCAPIElementL2FWSingle(sys.argv[2],
                                       smc_connection, sys.argv[3])
        l2fw.create()
        print l2fw.get_initial_contact_data()
    exit(0)
