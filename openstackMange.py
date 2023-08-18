from keystoneauth1 import identity
from keystoneauth1 import session
from neutronclient.v2_0 import client
from xenadmin.settings import OpenStack_username, OpenStack_password, OpenStack_project_name, \
    OpenStack_project_domain_id, OpenStack_user_domain_id, OpenStack_auth_url
import hashlib
from novaclient import client as noclient
import openstack
import traceback
import logging


class OpenStackMange(object):
    def __init__(self, neutron=None, conn=None, secrity_groups_id=None):
        self.sess = self.get_client()
        self.neutron = neutron or self.get_neutron()
        self.conn = conn or self.get_conn()
        self.nova_client = noclient.Client('2', session=self.sess)
        self.secrity_groups_id = secrity_groups_id or self.get_secrity_groups()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return self

    def get_client(self):
        username = OpenStack_username
        password = OpenStack_password
        project_name = OpenStack_project_name
        project_domain_id = OpenStack_project_domain_id
        user_domain_id = OpenStack_user_domain_id
        auth_url = OpenStack_auth_url
        auth = identity.Password(auth_url=auth_url,

                                 username=username,

                                 password=password,

                                 project_name=project_name,

                                 project_domain_id=project_domain_id,

                                 user_domain_id=user_domain_id)

        sess = session.Session(auth=auth)
        return sess

    def get_neutron(self):
        neutron = client.Client(session=self.sess)
        return neutron

    def get_conn(self):
        conn = openstack.connect(cloud='test_cloud')
        return conn

    def get_secrity_groups(self):
        secrity_groups = self.neutron.list_security_groups()
        id = None
        try:
            id = secrity_groups['security_groups'][0]['id']
        except Exception:
            traceback.print_exc()
        logging.error(id)
        return [id]

    def network_list(self):
        network_id, subnet_id = None, None
        try:
            # list all networks

            networks = self.neutron.list_networks()
            logging.error("networks: %s" % networks)
            # create a network
            filters = {}
            filters["id"] = network_id
            logging.error(network_id, subnet_id)
            networks = self.neutron.list_networks(**filters)
            logging.error("-----networks: %s" % networks)
        except Exception:
            traceback.print_exc()

    def network_api(self, network_name='mynetwork-test', network_ip='192.0.0.0/8', gateway_ip='192.0.0.2'):
        network_id, subnet_id = None, None
        try:
            # list all networks

            # networks = self.neutron.list_networks()
            # logging.error("networks: %s" % networks)
            # create a network
            network = {'name': network_name, 'admin_state_up': True, 'region_name': 'RegionOne',
                       'ipam_vpc_prefix': network_ip}
            new_network = self.neutron.create_network({'network': network})
            logging.error("network: %s" % new_network)
            net_dict = new_network['network']
            network_id = net_dict['id']
            logging.error("network_id: %s" % network_id)
            # create a subnet
            subnet_body = {
                'subnets': [{'cidr': network_ip, 'ip_version': 4, 'network_id': network_id, 'gateway_ip': gateway_ip,
                             "ipam_site_name": "mg"}]}
            new_subnet = self.neutron.create_subnet(subnet_body)
            subnet_id = new_subnet['subnets'][0]['id']
            logging.error("subnet: %s" % new_subnet)
        except Exception:
            traceback.print_exc()
        return network_id, subnet_id

    def delete_network(self, network_id=None):
        logging.error("Delete Network:")
        status = False
        if not network_id:
            return status
        try:
            # networks = self.neutron.list_networks()
            # port list
            port_list_del = []
            network_port = {}
            network_port["network_id"] = network_id
            list_ports = self.neutron.list_ports(**network_port)
            logging.error('------- list_ports : {}'.format(list_ports))
            for port in list_ports.get('ports', []):
                if not port.get('device_id', ''):
                    self.delete_port(port.get('id', ''))
                else:
                    port_list_del.append(port.get('id', ''))
            if len(port_list_del) == 1:
                if self.check_port_vm(port_list_del[0]):
                    self.delete_port(port_list_del[0])
                    port_list_del = []
            if port_list_del:
                return False
            filters = {}
            filters["id"] = network_id
            networks = self.neutron.list_networks(**filters)
            logging.error("-----networks: %s" % networks)
            logging.error('*******************************')
            # subnets = self.neutron.list_subnets()
            # logging.error("subnets: %s" % subnets)
            for network_item in networks['networks']:
                if network_id == network_item.get('id', ''):
                    subnet_ids = network_item.get('subnets', [])
                    logging.error('*******************************')
                    for example_subnet in subnet_ids:
                        self.neutron.delete_subnet(example_subnet)
                    self.neutron.delete_network(network_item['id'])
                    networks = self.neutron.list_networks(**filters)
                    logging.error("-----networks: %s" % networks)
                    logging.error('*******************************')
            status = True

        except Exception:
            traceback.print_exc()
        return status

    def get_list_ports(self, id=None):
        logging.error("List Ports:")
        if id:
            filters = {}
            filters["id"] = id
            list_ports = self.neutron.list_ports(**filters)
            logging.error('------- list_ports : {}'.format(list_ports))
        else:
            list_ports = self.conn.list_ports()
            for port in list_ports:
                logging.error(port)
        return list_ports

    def create_port(self, name="Specified-test-IP", network_id=None, subnet_id=None, ip_address=None):
        port_id = ''
        try:
            # alloc ip address by user Specified
            port_body = {"port": {"name": name, "network_id": network_id, "security_groups": self.secrity_groups_id,
                                  "fixed_ips": [{"subnet_id":  subnet_id, "ip_address": ip_address}]}}
            new_port = self.neutron.create_port(port_body)
            port_id = new_port.get('port', {}).get('id', '')
            mac_address = new_port.get('port', {}).get('mac_address', '')
            fixed_ips = new_port.get('port', {}).get('fixed_ips', [])
            ip_addr = ''
            if fixed_ips:
                ip_addr = fixed_ips[0].get('ip_address')
            logging.error('id {} , ip :{} , mac_address : {}'.format(port_id, ip_addr, mac_address))
            #if not mac_address:
            #    self.delete_port(port_id)
            #    port_id = ''
        except Exception:
            traceback.print_exc()
        return mac_address, port_id

    def range_create_port(self, name="Specified-test-IP", network_id=None):
        port_id = ''
        ip_addr = ''
        mac_address = ''
        try:
            port_body = {"port": {"name": name, "network_id": network_id}}
            new_port = self.neutron.create_port(port_body)
            port_id = new_port.get('port', {}).get('id', '')
            mac_address = new_port.get('port', {}).get('mac_address', '')
            fixed_ips = new_port.get('port', {}).get('fixed_ips', [])
            ip_addr = ''
            if fixed_ips:
                ip_addr = fixed_ips[0].get('ip_address')
            logging.error('id {} , ip :{} , mac_address : {}'.format(port_id, ip_addr, mac_address))
            if not mac_address:
                self.delete_port(port_id)
                port_id = ''
                ip_addr = ''
                mac_address = ''
        except Exception:
            traceback.print_exc()
        return port_id, ip_addr, mac_address

    def delete_port(self, id=None):
        try:
            if not id:
                return
            port_list = []
            filters = {}
            filters["id"] = id
            new_port = self.neutron.list_ports()
            logging.error('*****-port delete {}'.format(new_port))
            new_port = self.neutron.list_ports(**filters)
            logging.error('--port delete {}'.format(new_port))
            if new_port:
                port_list = new_port['ports']
            for port_item in port_list:
                self.neutron.delete_port(port_item['id'])
            new_port = self.neutron.list_ports(**filters)
            logging.error('--port delete {}'.format(new_port))
        except Exception:
            traceback.print_exc()

    def list_image(self):
        try:
            logging.error("List Images:")
            for image in self.conn.image.images():
                logging.error(image)
        except Exception:
            traceback.print_exc()

    def get_id_by_name(self, image_id_or_name=None):
        image = None
        try:
            image = self.conn.image.find_image(image_id_or_name)
            logging.error('image === {}'.format(list))

        except Exception:
            traceback.print_exc()
        return image

    def upload_image_from_file(self, name='analysis-test1', file_name='/root/analysis.qcow2',
                               container_format="bare", disk_format="qcow2"):
        image_id = None
        try:
            logging.error("Upload Image:")
            # Load fake image data for the example.
            # data = '/root/zy/CentOS-7-x86_64-GenericCloud.qcow2'
            # Build the image attributes and upload the image.
            # image_attrs = {
            #    'name': "test-upload-image-1",
            #    'data': data,
            #    'disk_format': 'qcow2',
            #    'container_format': 'bare',
            #    'visibility': 'public',
            # }
            # conn.image.upload_image(**image_attrs)
            # name = 'hanyuyang-test1'
            # file_name = '/root/analysis.qcow2'

            image = self.conn.image.create_image(name=name, filename=file_name,
                                                container_format=container_format,
                                                 disk_format=disk_format, wait=True, timeout=7200)

            logging.error(image.id)
            image_id = image.id
        except Exception:
            traceback.print_exc()
        return image_id

    def download_image_stream(self, image_id, file_name):
        # download_image_stream("6d127c72-6a39-46b1-84a2-eb652b186ee1",
        #                       "./6d127c72-6a39-46b1-84a2-eb652b186ee1.image.qcow2")
        logging.error("Download Image via streaming:")
        # Find the image you would like to download.
        image = self.conn.image.find_image(image_id)

        # As the actual download now takes place outside of the library
        # and in your own code, you are now responsible for checking
        # the integrity of the data. Create an MD5 has to be computed
        # after all of the data has been consumed.
        md5 = hashlib.md5()
        with open(file_name, "wb") as local_image:
            response = self.conn.image.download_image(image, stream=True)
            # Read only 1024 bytes of memory at a time until
            # all of the image data has been consumed.
            for chunk in response.iter_content(chunk_size=1024):
                # With each chunk, add it to the hash to be computed.
                md5.update(chunk)
                local_image.write(chunk)
            # Now that you've consumed all of the data the response gave you,
            # ensure that the checksums of what the server offered and
            # what you downloaded are the same.
            if response.headers["Content-MD5"] != md5.hexdigest():
                raise Exception("Checksum mismatch in downloaded content")

    def download_image(self, name="myimage"):
        logging.error("Download Image:")
        # Find the image you would like to download.
        image = self.conn.image.find_image(name)
        with open("{}.qcow2".format(name), "w") as local_image:
            response = self.conn.image.download_image(image)
            # Response will contain the entire contents of the Image.
            local_image.write(response)

    def delete_image(self, id='50e74765-784a-4b9d-873c-625bdf55f70b'):
        status = False
        logging.error("delete Image: {}".format(id))
        try:
            # Find the image you would like to download.
            # example_image = self.conn.image.find_image(id)
            example_image = self.get_id_by_name(id)
            self.conn.image.delete_image(example_image, ignore_missing=False)
            status = True
        except Exception:
            traceback.print_exc()
        return status

    def find_flavor(self, flavor_id=None):
        try:
            logging.error("Find Flavor:")
            flavor = self.conn.compute.find_flavor(flavor_id)
            logging.error(flavor)
            return flavor
        except Exception:
            traceback.print_exc()

    def create_flavor(self, name="test-flavor-2", ram=2048, vcpus=1, disk=10):
        flavor_id = None
        try:
            logging.error("Create Flavor:")
            flavor = self.conn.compute.create_flavor(name=name, ram=ram, vcpus=vcpus, disk=disk)
            flavor_id = flavor.id
        except Exception:
            traceback.print_exc()
        return flavor_id

    def delete_flavor(self, id):
        try:
            logging.error("delete Flavor:")
            flavor = self.find_flavor(id)
            self.conn.compute.delete_flavor(flavor)
            flavor = self.find_flavor(id)
            status = True
        except Exception:
            traceback.print_exc()
            status = False
        return status

    def kvm_status(self, instance_id):
        server = self.conn.compute.get_server(instance_id)
        return server.status

    def start_kvm(self, instance_id):
        server = self.conn.compute.start_server(instance_id)
        return server

    def stop_kvm(self, instance_id):
        server = self.conn.compute.stop_server(instance_id)
        return server

    def create_kvm(self, name, image_id, flavor_id, metadata, nics):
        nova_client = self.nova_client
        instance = nova_client.servers.create(name, image=image_id,
                meta=metadata,
                flavor=flavor_id,
                nics=nics)

        return instance.id

    def delete_kvm(self, instance_id):
        server = self.conn.compute.delete_server(instance_id)
        return server

    def update_kvm(self, instance_id, name):
        nova_client = self.nova_client
        try:
            server = nova_client.servers.update(instance_id, name)
        except Exception:
            traceback.print_exc()
        return server

    def get_kvm_list(self, image_id=None):
        try:
            servers = self.nova_client.servers.list()
            # image_id = "8c9bd0b7-5b3a-42a3-9b41-501dfdc4b837"
            for k in servers:
                logging.error(k.image.get('id'))
                if k.image.get('id') == image_id:
                    return False
        except Exception:
            traceback.print_exc()
            return False
        return True

    def get_kvm_name(self, name='InternalManagerVM-'):
        try:
            servers = self.nova_client.servers.list()
            # image_id = "8c9bd0b7-5b3a-42a3-9b41-501dfdc4b837"
            for k in servers:
                if name in k.name:
                    logging.error(k.__dict__)
                    return k.id
        except Exception:
            return ''

    def set_managervm(self, network_id=None):
        port_id, ip_addr, mac_address = '', '', ''
        try:
            import uuid
            name = uuid.uuid1()
            port_id, ip_addr, mac_address = self.range_create_port(name=name, network_id=network_id)
            if not port_id:
                return False, '', '', ''
            server_id = self.get_kvm_name()
            if not server_id:
                return False, '', '', ''
            new_server = self.nova_client.servers.get(server_id)
            logging.error("server: %s =&gt; %s" % (new_server.id, new_server.status))
            if new_server.status != "ACTIVE":
                logging.error("server is not active: %s" % new_server)
            res = self.nova_client.servers.interface_attach(server=server_id, port_id=port_id,
                                                            net_id=None, fixed_ip=None)
            status = True
            logging.error(res)
        except Exception:
            status = False
            traceback.print_exc()
        return status, port_id, ip_addr, mac_address

    def delete_network_subnet_port(self, network_id=None):
        logging.error("Delete Network:")
        status = False
        try:
            # networks = self.neutron.list_networks()
            # port list
            # port_list_del = []
            network_port = {}
            network_port["network_id"] = network_id
            list_ports = self.neutron.list_ports(**network_port)
            logging.error('------- list_ports : {}'.format(list_ports))
            for port in list_ports.get('ports', []):
                self.delete_port(port.get('id', ''))
            filters = {}
            filters["id"] = network_id
            networks = self.neutron.list_networks(**filters)
            logging.error("-----networks: %s" % networks)
            logging.error('*******************************')
            # subnets = self.neutron.list_subnets()
            # logging.error("subnets: %s" % subnets)
            for network_item in networks['networks']:
                if network_id == network_item.get('id', ''):
                    subnet_ids = network_item.get('subnets', [])
                    logging.error('*******************************')
                    for example_subnet in subnet_ids:
                        self.neutron.delete_subnet(example_subnet)
                    self.neutron.delete_network(network_item['id'])
                    networks = self.neutron.list_networks(**filters)
                    logging.error("-----networks: %s" % networks)
                    logging.error('*******************************')
            status = True

        except Exception:
            traceback.print_exc()
        return status

    def check_port_vm(self, id):
        status = False
        try:
            posts = self.get_list_ports(id)
            kvm_id = self.get_kvm_name()
            post_device_id = posts.get('ports', [])[0].get('device_id', '') if posts.get('ports', []) else ''
            if kvm_id == post_device_id:
                status = True
        except Exception:
            traceback.print_exc()
        return status


def main():
    # Initialize and turn on debug logging

    openstack.enable_logging(debug=False)
    # Cloud configs are read with openstack.config
    try:
        with OpenStackMange() as c:
            import socket
            a = socket.gethostname()
            logging.error(a)
            # import sys
            # logging.error(sys.argv[0])
            # import os
            # logging.error(os.getcwd())
            # c.network_list()
            # c.list_image()
            # c.get_id_by_name()
            # c.find_flavor()
            # c.get_list_ports()
            # c.network_api()
            # c.get_kvm_list()
            # c.create_port(name="delete--1", network_id='039896b3-9756-4918-b973-492bf8d123c4',
            #               subnet_id='38c35cea-bbe9-4fc3-aeca-1960703558bf', ip_address='117.0.0.0')
            # c.range_create_port(name="hanyuyang--0888", network_id='039896b3-9756-4918-b973-492bf8d123c4')
            # c.upload_image_from_file()
            # c.create_flavor()
            # c.delete_image()
            # c.delete_port(id='15f5af16-f8f4-4deb-a7b7-29ad5e729611')
            # c.delete_network(network_id='cdf5863e-d403-4195-a2e2-f75721180795')
            # c.delete_flavor('c84a8e6b-42bd-4a63-8140-02eeb36ff0da')
            c.set_managervm(network_id='039896b3-9756-4918-b973-492bf8d123c4')
            # c.get_kvm_name()

    except Exception:
        raise


if __name__ == "__main__":
    main()