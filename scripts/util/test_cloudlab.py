#!/usr/bin/env python

import cloudlab_util as cl
from geni.rspec import pg as rspec
from geni.util import loadContext

def see_slice():
    c = loadContext("/tmp/context.json", key_passphrase='TeFxy^FVv8Z5')
    print(c.cf.listProjects(c))
    cl.do_release(c, 'testing138', ['cl-utah'])
    #cl.release(experiment_name='testing136',
    #            cloudlab_user='giridhn',
    #            cloudlab_password='TeFxy^FVv8Z5',
    #            cloudlab_project='Consensus',
    ##            cloudlab_cert_path='cloudlab.pem',
    #            cloudlab_key_path='~/.ssh/id_ed25519.pub')
    print("Available slices: {}".format(c.cf.listSlices(c).keys()))

def setup():
    node = rspec.RawPC("node")
    #img = "urn:publicid:IDN+apt.emulab.net+image+schedock-PG0:docker-ubuntu16:0"
    #node.disk_image = img
    node.hardware_type = 'm400'
    iface1 = node.addInterface("if1")

    # Specify the component id and the IPv4 address
    iface1.component_id = "eth1"
    iface1.addAddress(rspec.IPv4Address("192.168.1.1", "255.255.255.0"))
    link = rspec.LAN("lan")
    link.addInterface(iface1)

    r = rspec.Request()
    r.addResource(node)

    request = {}
    request['cl-utah'] = r
    m = cl.request(experiment_name='testing138',
                requests=request,
                expiration=960,
                timeout=15,
                cloudlab_user='giridhn',
                cloudlab_password='TeFxy^FVv8Z5',
                cloudlab_project='Consensus',
                cloudlab_cert_path='cloudlab.pem',
                cloudlab_key_path='~/.ssh/id_ed25519.pub')

    # read info in manifests to introspect allocation
    print(m['cl-utah'].nodes)
    for node in m['cl-utah'].nodes:
        print("Node")
        print(node)
        print(node.component_id)
        for iface in node.interfaces:
            print("Interface")
            print(iface)
            print(node.hostipv4)
            print(iface.address_info)
            print(iface.sliver_id)

    # run your experiment...

    # once done with experiment, release resources
    #m = cl.request(experiment_name='myexp',
    #               cloudlab_user='myuser',
    #               cloudlab_password='mypassword',
    #               cloudlab_project='myproject',
    #               cloudlab_cert_path='/path/to/cloudlab.pem',
    #               cloudlab_pubkey_path='/path/to/cloudlab_rsa.pub')




#cl.print_slivers(experiment_name = 'testing131', cloudlab_user='giridhn',
#                  cloudlab_password='TeFxy^FVv8Z5', cloudlab_project='Consensus',
#                  cloudlab_cert_path='/Users/neilgiridharan/Downloads/cloudlab.pem', cloudlab_key_path='/Users/neilgiridharan/.ssh/id_ed25519.pub')
#setup()
see_slice()