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

#wendyExperiment.cleanupCloudlab('config/test.json')
#wendyExperiment.setupCloudlab('config/test.json')
localPath = wendyExperiment.setup('config/test.json')
# shieldExperiment.run('config/test.json')
# shieldExperiment.cleanup('config/test.json')
#shieldExperiment.calculateParallel('config/test.json', localPath)
#dataFile = localPath + "/results.dat"
#outputDataFile = localPath + "/result.pdf"
#data = list()
# data.append((dataFile,"Shield"))
# print outputDataFile
#shieldExperiment.plotThroughputLatency(data, outputDataFile)
