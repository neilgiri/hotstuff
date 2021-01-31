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

num_nodes = 4
lan = request.LAN()

for i in range(num_nodes):
    node = request.RawPC("node" + str(i))
    iface = node.addInterface("if" + str(i))
    iface.addAddress(rspec.IPv4Address("192.168.1." + str(i + 1), "255.255.255.0"))
    lan.addInterface(iface)
    node.addService(rspec.Install(url="https://golang.org/dl/go1.15.7.linux-amd64.tar.gz", path="/local"))
    node.addService(rspec.Execute(shell="bash", command="/local/hotstuff/scripts/install_go.sh"))


# Print the RSpec to the enclosing page.
pc.printRequestRSpec(request)