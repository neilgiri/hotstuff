"""This is a trivial example of a gitrepo-based profile; The profile source code and other software, documentation, etc. are stored in in a publicly accessible GIT repository (say, github.com). When you instantiate this profile, the repository is cloned to all of the nodes in your experiment, to `/local/repository`. 
This particular profile is a simple example of using a single raw PC. It can be instantiated on any cluster; the node will boot the default operating system, which is typically a recent version of Ubuntu.
Instructions:
Wait for the profile instance to start, then click on the node in the topology and choose the `shell` menu item. 
"""

# Import the Portal object.
import geni.portal as portal
# Import the ProtoGENI library.
import geni.rspec.pg as rspec

# Create a portal context.
pc = portal.Context()

# Create a Request object to start building the RSpec.
request = pc.makeRequestRSpec()

num_nodes = 10
lan = request.LAN()

for i in range(num_nodes):
    node = request.RawPC("node" + str(i))
    node.hardware_type = "m510"
    iface = node.addInterface("if" + str(i))
    iface.component_id = "eth" + str(i + 1)
    iface.addAddress(rspec.IPv4Address("192.168.1." + str(i + 1), "255.255.255.0"))
    lan.addInterface(iface)
    node.addService(rspec.Install(url="https://github.com/neilgiri/hotstuff/archive/master.tar.gz", path="/users/giridhn"))
    node.addService(rspec.Execute(shell="bash", command="sudo tar -C /users/giridhn -xvzf /users/giridhn/hotstuff-master.tar.gz ; sudo apt-get update ; sudo apt-get install --yes golang-go"))


# Print the RSpec to the enclosing page.
pc.printRequestRSpec(request)
