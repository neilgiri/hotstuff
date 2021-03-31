# Natacha Crooks - ncrooks@cs.utexas.edu - 2017
# This example script relies on the private IPs of EC2 instances and therefore
# should be run within EC2.
# Before running this script, make sure to update your AWS_KEY
# in setup-machine.sh and to replace the ami id of the client/server
# to which ever ami you choose to run the code on
# All experiments should follow a similar pattern, replacing test.json
# by whichever parameter they choose to leverage
# In its current form, there can only be one experiment run per availability# region (TODO: fix this)

import wendyExperiment
import cloudlab_util

#cloudlab_util.default_context()

#wendyExperiment.cleanupCloudlab('config/test.json')
#wendyExperiment.setupCloudlab('config/test.json')
#localPath = wendyExperiment.setup('config/test.json')
wendyExperiment.create_config('config/test.json')
wendyExperiment.run('config/test.json')
wendyExperiment.calculateParallel('config/test.json', None)
localPath = "/Users/neilgiridharan/Documents/VMware/WendyCode/hotstuff/experiments/testExperiment12"
dataFile = localPath + "/hotstuff.dat"
outputDataFile = localPath + "/result.pdf"
data = list()
data.append((dataFile,"HotStuff BatchSize 100"))
data.append((localPath + "/fastwendy.dat", "Fast Wendy BatchSize 100"))
data.append((localPath + "/wendy.dat", "Wendy BatchSize 100"))
wendyExperiment.plotThroughputLatency(data, outputDataFile)
