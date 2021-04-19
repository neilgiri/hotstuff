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

#wendyExperiment.cleanupCloudlab('config/test1.json')
#wendyExperiment.setupCloudlab('config/test1.json')
#localPath = wendyExperiment.setup('config/test1.json')
#wendyExperiment.create_config('config/test1.json')
#wendyExperiment.run('config/test1.json')
#wendyExperiment.calculateParallel('config/test1.json', None)
localPath = "/Users/neilgiridharan/Documents/VMware/WendyCode/hotstuff/experiments/testExperiment8"
dataFile = localPath + "/hotstuff-5ms.dat"
outputDataFile = localPath + "/result.pdf"
data = list()
data.append((dataFile,"HS-400"))

data.append((localPath + "/wendy-5ms.dat", "W-400"))
data.append((localPath + "/fastwendy-5ms.dat", "FW-400"))
wendyExperiment.plotThroughputF(data, outputDataFile)


#data.append((localPath + "/hotstuff400.dat", "HS-400"))
#data.append((localPath + "/wendy400.dat", "W-400"))
#data.append((localPath + "/fastwendy400.dat", "FW-400"))

#data.append((localPath + "/hotstuff800.dat", "HS-800"))
#data.append((localPath + "/wendy800.dat", "W-800"))
#data.append((localPath + "/fastwendy800.dat", "FW-800"))

#data.append((localPath + "/aggsigmicrobenchvd.dat", "WendySig"))
#data.append((localPath + "/aggsigmicrobenchvd-bgls.dat", "BGLS03"))

#wendyExperiment.plotAggSigBenchVd(data, outputDataFile)
