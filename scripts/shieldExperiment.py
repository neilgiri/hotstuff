# Natacha Crooks ncrooks@cs.utexas.edu 2017
# Main script for running SHIELD experiments
# Each sript contains five parts:
# EC2 setup (optional)
# Setup
# Run
# Collect Data
# EC2 teardown (optional)

# TODO remove redundant pieces of code (some duplication) +
# This code has not been tested by someone other than me
from graph_util import *
from math_util import *
from prop_util import *
from compile_util import *
import boto.ec2
from cloudlab_util import *
from ec2_util import *
from ssh_util import *
import os
import os.path
import sys
import datetime
import time
import random
import multiprocessing
import boto.dynamodb
sys.path.append("util/")

# To add a new experiment, create a JSON file from
# the three default json files in the config/ folder
# one for the experimental setup, one for the
# node configuration, and one for the actual
# experiments (ex: concatenate default_ycsb.json,
# default_node.json, and default_exp.json) # and write the following code # shieldExperiment.setupEc2("ec2.json")
# shieldExperiment.setupConfigForEC2(ec2File, propFile)
# shieldExperiment.setup("test.json")
# shieldExperiment.run("test.json")
# shieldExperiment.cleanup("test.json")
# shieldExperiment.cleanupEc2("test.json")

proxyKeyword = "proxy"
storageKeyword = "storage"
clientKeyword = "client"
nbRepetitions = 3


def setupConfigForEc2(propFile, ec2File):
    ec2Properties = loadPropertyFile(ec2File)
    properties = loadPropertyFile(propFile)
    #properties['proxy_ip_address'] =  ec2Properties['proxy_ip_address']
    #properties['remote_store_ip_address'] = ec2Properties['remote_store_ip_address']
    properties['clients'] = ec2Properties['clients']
    # Upgrade property file
    print("Updating Property File " + str(propFile))
    with open(propFile, 'w') as fp:
        json.dump(properties, fp, indent=2, sort_keys=True)


# Sets up client machines and proxy machines as
# Amazon EC2 VMs, and updates the property file
# with ther (private) ip address
def setupEc2(ecFile):
    ecProperties = loadPropertyFile(ecFile)
    if not ecProperties:
        print("Empty property file, failing")
        return
    #proxyAmi = ecProperties['ec2']['proxy_ami']
    #clientAmi = ecProperties['ec2']['client_ami']
    #storageAmi = ecProperties['ec2']['storage_ami']
    nbClients = int(ecProperties['client_machines'])
    #proxyInstType = ecProperties['ec2']['proxy_inst_type']
    clientInstType = ecProperties['ec2']['client_inst_type']
    #storageInstType = ecProperties['ec2']['storage_inst_type']
    #proxyRegion = ecProperties['ec2']['proxy_region']
    clientRegion = ecProperties['ec2']['client_region']
    #storageRegion = ecProperties['ec2']['storage_region']
    #proxyAvailability = ecProperties['ec2']['proxy_availability']
    clientAvailability = ecProperties['ec2']['client_availability']
    #storageAvailability= ecProperties['ec2']['storage_availability']
    clientKeyName = ecProperties['ec2']['keyname'] + clientRegion
    #proxyKeyName = ecProperties['ec2']['keyname'] + proxyRegion
    #storageKeyName = ecProperties['ec2']['keyname'] + storageRegion
    clientSec = ecProperties['ec2']['client_sec']
    #proxySec = ecProperties['ec2']['proxy_sec']
    #storageSec = ecProperties['ec2']['storage_sec']
    #proxyConn = startConnection(proxyRegion)
    #proxyKey = getOrCreateKey(proxyConn, proxyKeyName)
    # print proxyKey
    clientConn = startConnection(clientRegion)
    clientKey = getOrCreateKey(clientConn, clientKeyName)
    #storageConn = startConnection(storageRegion)
    #storageKey = getOrCreateKey(storageConn, storageKeyName)
    experimentName = ecProperties['name']
    #useProxy = toBool(ecProperties['useproxy'])
    #useStorage = toBool(ecProperties['usestorage'])
    #useLoader = toBool(ecProperties['useloader'])
    #useSpot = toBool(ecProperties['ec2']['usespot'])

    # Start Proxy
    # if (useProxy):
    #tag = experimentName + proxyKeyword
    # startEc2Instance(proxyConn, proxyAmi, proxyKey,
    # proxyInstType, [proxySec], proxyAvailability, tag, spot=useSpot)
    # print "Waiting for machine to initialise"
    # Wait until finished initialising
    #ips = list()
    # while (len(ips)!=1):
    # waitUntilInitialised(proxyConn,tag,1)
    # Update the IP addresses
    #ips = getEc2InstancesPrivateIp(proxyConn, 'Name', {'tag:Name':tag}, True)
    # print len(ips)
    # print "Finished Initialising Proxy"
    #ecProperties['proxy_ip_address'] = ips[0][1]
    # print ecProperties['proxy_ip_address']

    # Start Storage Manager (if not using amazonDB)

    # if (useStorage):
    #tag = experimentName + storageKeyword
    # Start Storage Manager
    # startEc2Instance(storageConn, storageAmi, storageKey,
    # storageInstType, [storageSec], storageAvailability, tag, spot=useSpot)
    # Wait until finished initialising
    # print "Waiting for machine to initialise"
    #ips = list()
    # while (len(ips)!=1):
    # waitUntilInitialised(storageConn,tag,1)
    # print "Finished Initialising Storage"
    # Update the IP addresses
    #ips = getEc2InstancesPrivateIp(storageConn, 'Name', {'tag:Name':tag}, True)
    # print ips
    # print len(ips)
    #ecProperties['remote_store_ip_address'] = ips[0][1]

    print("Creating VMs for nb of client machines")

    tag = experimentName + clientKeyword
    for i in range(0, nbClients):
        print("Creating Client Machine " + str(i))
        startEc2Instance(clientConn, clientAmi, clientKey,
                         clientInstType, [clientSec], clientAvailability, tag, spot=useSpot)
    ips = list()
    while (len(ips) != nbClients):
        waitUntilInitialised(clientConn, tag, nbClients)
        ips = getEc2InstancesPrivateIp(
            clientConn, 'Name', {'tag:Name': tag}, True)
        print(len(ips))
    ecProperties["clients"] = [x[1] for x in ips]
    # Upgrade property file
    print("Property File " + str(ecFile))
    with open(ecFile, 'w') as fp:
        json.dump(ecProperties, fp, indent=2, sort_keys=True)

# if method called, terminate VMs


def cleanupEc2(ecFile):

    ecProperties = loadPropertyFile(ecFile)

    if not ecProperties:
        print "Empty property file, failing"
        return

    proxyAmi = ecProperties['ec2']['proxy_ami']
    clientAmi = ecProperties['ec2']['client_ami']
    storageAmi = ecProperties['ec2']['storage_ami']
    nbClients = int(ecProperties['client_machines'])
    proxyInstType = ecProperties['ec2']['proxy_inst_type']
    clientInstType = ecProperties['ec2']['client_inst_type']
    storageInstType = ecProperties['ec2']['storage_inst_type']
    proxyRegion = ecProperties['ec2']['proxy_region']
    clientRegion = ecProperties['ec2']['client_region']
    storageRegion = ecProperties['ec2']['storage_region']
    clientKeyName = ecProperties['ec2']['keyname'] + clientRegion
    proxyKeyName = ecProperties['ec2']['keyname'] + proxyRegion
    storageKeyName = ecProperties['ec2']['keyname'] + storageRegion
    clientSec = ecProperties['ec2']['client_sec']
    proxySec = ecProperties['ec2']['proxy_sec']
    storageSec = ecProperties['ec2']['storage_sec']
    proxyConn = startConnection(proxyRegion)
    proxyKey = getOrCreateKey(proxyConn, proxyKeyName)
    clientConn = startConnection(clientRegion)
    clientKey = getOrCreateKey(clientConn, clientKeyName)
    storageConn = startConnection(storageRegion)
    storageKey = getOrCreateKey(storageConn, storageKeyName)
    experimentName = ecProperties['name']

    # Terminate proxy
    tag = experimentName + proxyKeyword
    proxyId = getEc2InstancesId(
        proxyConn, 'Name', {'tag:Name': tag}, True)
    print proxyId
    terminateEc2Instances(proxyConn, proxyId)
    # Terminate clients
    tag = experimentName + clientKeyword
    clientId = getEc2InstancesId(
        clientConn, 'Name', {'tag:Name': tag}, True)
    terminateEc2Instances(clientConn, clientId)
    print clientId
    tag = experimentName + storageKeyword
    storageId = getEc2InstancesId(
        storageConn, 'Name', {'tag:Name': tag}, True)
    terminateEc2Instances(storageConn, storageId)
    print storageId


def loadOptionalKey(properties, key):
    try:
        prop = properties[key]
        return prop
    except:
        return null

# Function that setups up appropriate folders on the
# correct machines, and sends the jars. It assumes
# that the appropriate VMs/machines have already started


def setup(propertyFile, ec2File="ec2.json"):
    print("Setup")

    properties = loadPropertyFile(propertyFile)
    ecProperties = loadPropertyFile(ec2File)
    if not properties or not ecProperties:
        print("Empty property file, failing")
        return

    ##### LOADING PROPERTIES FILE ####
    user = properties['username']
    password = properties['password']
    project = properties['project']
    experimentName = properties['experimentname']
    certificatePath = properties['certificatepath']
    publicKeyPath = properties['publickeypath']
    localProjectDir = properties['localprojectdir']
    remoteProjectDir = properties['remoteprojectdir']
    localSrcDir = properties['localsrcdir']
    #mavenDir = localSrcDir + "/target"
    expFolder = '/results/' + experimentName
    expDir = expFolder + "/" + datetime.datetime.now().strftime("%Y:%m:%d:%H:%M") + "/"
    properties['experiment_dir'] = expDir
    #proxyRegion = ecProperties['ec2']['proxy_region']
    #clientRegion = ecProperties['ec2']['client_region']
    #storageRegion = ecProperties['ec2']['storage_region']
    #clientKeyName = ecProperties['ec2']['keyname'] + clientRegion + ".pem"
    #proxyKeyName = ecProperties['ec2']['keyname'] + proxyRegion + ".pem"
    #storageKeyName = ecProperties['ec2']['keyname'] + storageRegion + ".pem"

    #proxy = ecProperties['proxy_ip_address']
    #storage = ecProperties['remote_store_ip_address']
    localPath = localProjectDir + '/' + expDir + "/"
    remotePath = remoteProjectDir + '/' + expDir + "/"

    #useProxy = toBool(ecProperties['useproxy'])
    #useStorage = toBool(ecProperties['usestorage'])
    #useLoader = toBool(ecProperties['useloader'])

###### UPDATE DB DIRECTORY #####
    #properties['db_file_path'] = remoteProjectDir + \
    #    '/' + expFolder + "/" + properties['db_file_name']
    # properties['db_file_path'] =  properties['db_file_name']

#### LOADING/GENERATING JAR FILES ####

    #jarName = properties['jar']
    #clientMainClass = properties['clientmain']
    #proxyMainClass = loadOptionalKey(properties, 'proxymain')
    #storageMainClass = loadOptionalKey(properties, 'storagemain')
    #loaderMainClass = loadOptionalKey(properties, 'loadermain')

    #print "Using Proxy " + str(useProxy)
    #print "Using Storage " + str(useStorage)
    #print "Using Loader " + str(useLoader)

    # Compile Go Executables
    print("Setup: Compiling Executables")

    currentDir = os.getcwd()
    executeCommand(" cd " + localSrcDir)
    executeCommand("cd " + localSrcDir + " ; mvn install")
    executeCommand("cd " + localSrcDir + " ; mvn package")

    print mavenDir + "/" + jarName

    fileExists = os.path.isfile(mavenDir + "/" + jarName)
    if (not fileExists):
        print "Error: Incorrect Jar Name"
        exit()

#### GENERATING EXP DIRECTORY ON ALL MACHINES ####

    print "Creating Experiment directory"
    clientIpList = list()
    for c in properties['clients']:
        clientIpList.append(c)
    for c in clientIpList:
        print c
        mkdirRemote(c, remotePath, clientKeyName)
    if (useProxy):
        print proxy
        mkdirRemote(proxy, remotePath, proxyKeyName)
    if (useStorage):
        print "Reached here"
        mkdirRemote(storage, remotePath, storageKeyName)
    executeCommand("mkdir -p " + localPath)

#### SENDING JARS TO ALL MACHINES ####

    # Send Jars
    print "Sending Jars to all Machines"
    j = mavenDir + "/" + jarName
    print remotePath
    print clientIpList
    print useProxy
    print useStorage
    sendFileHosts(j, clientIpList, remotePath, clientKeyName)
    if (useProxy):
        sendFileHosts(j, [proxy], remotePath, proxyKeyName)
    if (useStorage):
        sendFileHosts(j, [storage], remotePath, storageKeyName)
    executeCommand("cp " + j + " " + localPath)
    # Create file with git hash
    executeCommand("cp " + propertyFile + " " + localPath)
    gitHash = getGitHash(localSrcDir)
    print "Saving Git Hash " + gitHash
    executeCommand("touch " + localPath + "/git.txt")
    with open(localPath + "/git.txt", 'ab') as f:
        f.write(gitHash)
    # Write back the updated property file
    with open(propertyFile, 'w') as fp:
        json.dump(properties, fp, indent=2, sort_keys=True)
    executeCommand("cp " + propertyFile + " " + localPath)
    return localPath


# Runs the actual experiment
def run(propertyFile, deleteTable=False, ecFile="ec2.json"):

    print "Run"
    properties = loadPropertyFile(propertyFile)
    ecProperties = loadPropertyFile(ecFile)
    if not properties or not ecProperties:
        print "Empty property file, failing"
        return

    useStorage = toBool(properties['usestorage'])
    useProxy = toBool(properties['useproxy'])
    useLoader = toBool(properties['useloader'])
    jarName = properties['jar']
    clientMainClass = properties['clientmain']
    if (useProxy):
        proxyMainClass = properties['proxymain']
    if (useLoader):
        loaderMainClass = properties['loadermain']
    if (useStorage):
        storageMainClass = properties['storagemain']
    proxyRegion = ecProperties['ec2']['proxy_region']
    clientRegion = ecProperties['ec2']['client_region']
    storageRegion = ecProperties['ec2']['storage_region']
    clientKeyName = ecProperties['ec2']['keyname'] + clientRegion + ".pem"
    proxyKeyName = ecProperties['ec2']['keyname'] + proxyRegion + ".pem"
    storageKeyName = ecProperties['ec2']['keyname'] + storageRegion + ".pem"
    experimentName = properties['experimentname']
    localProjectDir = properties['localprojectdir']
    remoteProjectDir = properties['remoteprojectdir']
    javaCommandClient = properties['javacommandclient']
    javaCommandServer = properties['javacommandserver']

    try:
        javaCommandStorage = properties['javacommandstorage']
    except:
        javaCommandStorage = javaCommandServer

    try:
        noKillStorage = properties['no_kill_storage']
    except:
        noKillStorage = False

    try:
        simulateLatency = int(properties['simulate_latency'])
    except:
        simulateLatency = 0

    expDir = properties['experiment_dir']
    remoteExpDir = remoteProjectDir + "/" + expDir
    localExpDir = localProjectDir + "/" + expDir
    nbRounds = len(properties['nbclients'])
    logFolders = properties['log_folder']
    # TODO(natacha): cleanup
    try:
        reuseData = toBool(properties['reuse_data'])
        print "Reusing Data " + str(reuseData)
    except:
        reuseData = False

    # Create connections for everyone
    clientConn = startConnection(clientRegion)
    clientKey = getOrCreateKey(clientConn, clientKeyName)
    clientIpList = list()
    for c in properties['clients']:
        clientIpList.append(c)
    proxy = properties['proxy_ip_address']
    proxyConn = startConnection(proxyRegion)
    proxyKey = getOrCreateKey(proxyConn, proxyKeyName)
    storage = properties['remote_store_ip_address']
    storageConn = startConnection(storageRegion)
    storageKey = getOrCreateKey(storageConn, storageKeyName)

    #properties = updateDynamoTables(properties, experimentName)

    # Setup latency on appropriate hosts if
    # simulated
    print "WARNING: THIS IS HACKY AND WILL NOT WORK WHEN CONFIGURING MYSQL"
    if (simulateLatency):
        print "Simulating a " + str(simulateLatency) + " ms"
        if (useProxy):
            setupTC(proxy, simulateLatency, [storage], proxyKey)
            if (useStorage):
                setupTC(storage, simulateLatency, [proxy], storageKey)
        else:
            # Hacky if condition for our oram tests without proxy
            # Because now latency has to be between multiple hostsu
            if (useStorage):
                for c in clientIpList:
                    setupTC(c, simulateLatency, [storage], clientKey)
                setupTC(storage, simulateLatency, clientIpList, storageKey)
            else:
                raise Exception("TODO MYSQL")
    first = True
    dataLoaded = False
    for i in range(0, nbRounds):
        time.sleep(10)
        for it in range(0, nbRepetitions):
            time.sleep(10)
            try:
                print "Running Round: " + str(i) + " Iter " + str(it)
                nbClients = int(properties['nbclients'][i])
                print "Number of clients " + str(nbClients)
                localRoundFolder = localExpDir + "/" + \
                    str(nbClients) + "_" + str(it)
                remoteRoundFolder = remoteExpDir + \
                    "/" + str(nbClients) + "_" + str(it)
                print "Round Folder : " + str(localRoundFolder)
                localPath = localRoundFolder
                remotePath = remoteRoundFolder
                print "Remote Path :" + str(remotePath)
                executeCommand("mkdir -p " + localPath)
                logFolder = remotePath + "/" + logFolders
                properties['log_folder'] = logFolder
                localProp = localPath + "/properties"
                remoteProp = remotePath + "/properties"
                properties['exp_dir'] = remotePath

                # Create folders on appropriate hosts
                for c in clientIpList:
                    mkdirRemote(c, remotePath, clientKey)
                    mkdirRemote(c, logFolder, clientKey)
                if (useProxy):
                    mkdirRemote(proxy, remotePath, proxyKey)
                    mkdirRemote(proxy, logFolder, proxyKey)
                if (useStorage):
                    mkdirRemote(storage, remotePath, storageKey)
                    mkdirRemote(storage, logFolder, storageKey)

                properties['proxy_listening_port'] = str(
                    random.randint(20000, 30000))

                if (first or (not noKillStorage)):
                    properties['remote_store_listening_port'] = str(
                        random.randint(30000, 40000))

                localProp = localPath + "/properties"
                remoteProp = remotePath + "/properties"

                # start storage
                print "Start Storage (Having Storage " + str(useStorage) + ")"
                if (useStorage and (first or (not noKillStorage))):
                    first = False
                    print "Starting Storage again"
                    sid = nbClients + 2
                    properties['node_uid'] = str(sid)
                    properties['node_ip_address'] = storage
                    properties['node_listening_port'] = properties['remote_store_listening_port']
                    localProp_ = localProp + "_storage.json"
                    remoteProp_ = remoteProp + "_storage.json"
                    with open(localProp_, 'w') as fp:
                        json.dump(properties, fp, indent=2, sort_keys=True)
                    print "Sending Property File and Starting Server"
                    sendFile(localProp_, storage, remotePath, storageKey)
                    cmd = "cd " + remoteExpDir + " ;  " + javaCommandStorage + " -cp " + jarName + " " + storageMainClass + " " + remoteProp_ + " 1>" + \
                        remotePath + "/storage" + \
                        str(sid) + ".log 2>" + remotePath + \
                        "/storage_err" + str(sid) + ".log"
                    t = executeNonBlockingRemoteCommand(
                        storage, cmd, storageKey)
                    t.start()
                else:
                    print "Storage already started"

                time.sleep(30)
                # start proxy
                print "Start Proxy (Having Proxy " + str(useProxy) + ")"
                if (useProxy):
                    sid = nbClients + 1
                    properties['node_uid'] = str(sid)
                    properties['node_ip_address'] = proxy
                    properties['node_listening_port'] = properties['proxy_listening_port']
                    localProp_ = localProp + "_proxy.json"
                    remoteProp_ = remoteProp + "_proxy.json"
                    with open(localProp_, 'w') as fp:
                        json.dump(properties, fp, indent=2, sort_keys=True)
                    print "Sending Property File and Starting Server"
                    sendFile(localProp_, proxy, remotePath, proxyKey)
                    cmd = "cd " + remoteExpDir + " ; " + javaCommandServer + " -cp " + jarName + " " + proxyMainClass + " " + remoteProp_ + " 1>" + \
                        remotePath + "/proxy" + \
                        str(sid) + ".log 2>" + remotePath + \
                        "/proxy_err" + str(sid) + ".log"
                    print cmd
                    t = executeNonBlockingRemoteCommand(
                        proxy, cmd, proxyKeyName)
                    t.start()

                time.sleep(30)

                oldDataSet = None
                ## Load Data ##
                print "Start Loader (Having Loader " + str(useLoader) + ")"
                if (useLoader and ((not dataLoaded) or (not reuseData))):
                    dataLoaded = True
                    localProp_ = localProp + "_loader.json"
                    remoteProp_ = remoteProp + "_loader.json"
                    ip = clientIpList[0]
                    properties['node_uid'] = str(nbClients + 3)
                    properties['node_ip_address'] = ip
                    properties.pop('node_listening_port', None)

                    oldDataSet = properties['key_file_name']
                    dataset_remloc = remotePath + "/" + \
                        properties['key_file_name']
                    dataset_localoc = localPath + "/" + \
                        properties['key_file_name']
                    properties['key_file_name'] = dataset_remloc
                    with open(localProp_, 'w') as fp:
                        json.dump(properties, fp, indent=2, sort_keys=True)
                    sendFile(
                        localProp_, clientIpList[0], remotePath, clientKeyName)
                    cmd = "cd " + remoteExpDir + "; " + javaCommandClient + " -cp " + jarName + " " + loaderMainClass + \
                        " " + remoteProp_ + " 1>" + remotePath + \
                        "/loader.log 2>" + remotePath + "/loader_err.log"

                    # Generate data set via executing the loader
                    executeRemoteCommand(clientIpList[0], cmd, clientKeyName)
                    getFile(dataset_remloc, [
                            clientIpList[0]], dataset_localoc, clientKey)
                    # Once dataset has been executed, send it out to all clients
                    sendFileHosts(dataset_localoc, clientIpList,
                                  dataset_remloc, clientKey)

                ## Start clients ##
                nbMachines = len(clientIpList)
                client_list = list()
                for cid in range(nbClients, 0, -1):
                    ip = clientIpList[cid % nbMachines]
                    properties['node_uid'] = str(cid)
                    properties['node_ip_address'] = ip
                    properties.pop('node_listening_port', None)
                    localProp_ = localProp + "client" + str(cid) + ".json"
                    oldRunName = properties['run_name']
                    remoteProp_ = remoteProp + "client" + str(cid) + ".json"
                    properties['run_name'] = remotePath + "/" + \
                        str(cid) + "_" + properties['run_name']
                    with open(localProp_, 'w') as fp:
                        json.dump(properties, fp, indent=2, sort_keys=True)
                    sendFile(localProp_, ip, remoteProp_, clientKeyName)
                    cmd = "cd " + remoteExpDir + " ; " + javaCommandClient + " -cp " + clientMainClass + " " + jarName + " " + remoteProp_ + " 1>" + remotePath + "/client_" + ip + "_" + \
                        str(cid) + ".log 2>" + remotePath + \
                        "/client_" + ip + "_" + str(cid) + "_err.log"
                    cmd = "cd " + remoteExpDir + "; " + javaCommandClient + " -cp " + jarName + " " + clientMainClass + " " + remoteProp_ + " 1>" + remotePath + "/client_" + ip + "_" + \
                        str(cid) + ".log 2>" + remotePath + \
                        "/client_" + ip + "_" + str(cid) + "_err.log"
                    t = executeNonBlockingRemoteCommand(ip, cmd, clientKeyName)
                    client_list.append(t)
                    properties['run_name'] = oldRunName

                print "Start clients"
                time.sleep(30)
                for t in client_list:
                    t.start()
                for t in client_list:
                    t.join(9600)
                collectData(propertyFile, ecFile, localPath, remotePath)
                time.sleep(60)
                print "Finished Round"
                print "---------------"
                if oldDataSet is not None:
                    properties['key_file_name'] = oldDataSet

                for c in clientIpList:
                    try:
                        executeRemoteCommandNoCheck(
                            c, "ps -ef | grep java | grep -v grep | grep -v bash | awk '{print \$2}' | xargs -r kill -9", clientKeyName)
                    except Exception as e:
                        print " "
                if (useProxy):
                    try:
                        print "Killing Proxy" + str(proxy)
                        executeRemoteCommandNoCheck(
                            proxy, "ps -ef | grep java | grep -v grep | grep -v bash | awk '{print \$2}' | xargs -r kill -9", proxyKeyName)
                    except Exception as e:
                        print " "

                if (useStorage and not noKillStorage):
                    try:
                        print "Killing Storage" + str(storage)
                        executeRemoteCommandNoCheck(
                            storage, "ps -ef | grep java | grep -v grep | awk '{print \$2}' | xargs -r kill -9", storageKeyName)
                    except Exception as e:
                        print " "
                else:
                    print "No Kill Storage"
                if (deleteTable):
                    deleteDynamoTables(properties)

            except Exception as e:
                print " "
            except subprocess.CalledProcessError, e:
                print str(e.returncode)

    # Tear down TC rules
    if (simulateLatency):
        if (useProxy):
            deleteTC(proxy, storage, proxyKey)
        if (useStorage):
            deleteTC(storage, proxy, storageKey)

    return expDir

# Cleanup: kills ongoing processes and removes old data
# directory


def cleanup(propertyFile, ecFile="ec2.json"):
    properties = loadPropertyFile(propertyFile)
    ecProperties = loadPropertyFile(ecFile)
    if not properties or not ecProperties:
        print "Empty property file, failing"
        return
    proxyRegion = ecProperties['ec2']['proxy_region']
    clientRegion = ecProperties['ec2']['client_region']
    storageRegion = ecProperties['ec2']['storage_region']
    clientKeyName = ecProperties['ec2']['keyname'] + clientRegion + ".pem"
    proxyKeyName = ecProperties['ec2']['keyname'] + proxyRegion + ".pem"
    storageKeyName = ecProperties['ec2']['keyname'] + storageRegion + ".pem"
    experimentName = properties['experimentname']
    user = properties['username']

    useStorage = toBool(properties['usestorage'])
    useProxy = toBool(properties['useproxy'])

    print "Killing processes"
    clientIpList = list()
    for c in properties['clients']:
        clientIpList.append(c)
    proxy = properties['proxy_ip_address']
    storage = properties['remote_store_ip_address']

    for c in clientIpList:
        try:
            print "Killing " + str(c)
            executeRemoteCommandNoCheck(
                c, "ps -ef | grep java | grep -v grep | grep -v bash | awk '{print \$2}' | xargs -r kill -9", clientKeyName)
        except Exception as e:
            print " "

    if (useProxy):
        try:
            print "Killing Proxy" + str(proxy)
            executeRemoteCommandNoCheck(
                proxy, "ps -ef | grep java | grep -v grep | grep -v bash | awk '{print \$2}' | xargs -r kill -9", proxyKeyName)
        except Exception as e:
            print " "

    if (useStorage):
        try:
            print "Killing Storage" + str(storage)
            executeRemoteCommandNoCheck(
                storage, "ps -ef | grep java | grep -v grep | awk '{print \$2}' | xargs -r kill -9", storageKeyName)
        except Exception as e:
            print " "

    print "Removing old experiments"
    remoteFolder = properties['experiment_dir'] + '/' + experimentName
    for c in clientIpList:
        rmdirRemoteIfExists(c, remoteFolder, clientKeyName)
    if (useProxy):
        rmdirRemoteIfExists(proxy, remoteFolder, proxyKeyName)
    if (useStorage):
        rmdirRemoteIfExists(storage, remoteFolder, storageKeyName)

    #if (deleteTable): deleteDynamoTables(propertyFile)


# Collects the data for the experiment
def collectData(propertyFile, ecFile, localFolder, remoteFolder):
    print "Collect Data"

    properties = loadPropertyFile(propertyFile)
    ecProperties = loadPropertyFile(ecFile)
    if not properties or not ecProperties:
        print "Empty property file, failing"
        return
    proxyRegion = ecProperties['ec2']['proxy_region']
    clientRegion = ecProperties['ec2']['client_region']
    storageRegion = ecProperties['ec2']['storage_region']
    clientKeyName = ecProperties['ec2']['keyname'] + clientRegion + ".pem"
    proxyKeyName = ecProperties['ec2']['keyname'] + proxyRegion + ".pem"
    storageKeyName = ecProperties['ec2']['keyname'] + storageRegion + ".pem"
    useStorage = toBool(properties['usestorage'])
    useProxy = toBool(properties['useproxy'])

    clientIpList = list()

    for c in properties['clients']:
        clientIpList.append(c)
    proxy = properties['proxy_ip_address']
    storage = properties['remote_store_ip_address']
    print "Getting Data "
    print clientIpList
    getDirectory(localFolder, clientIpList, remoteFolder, clientKeyName)
    if (useProxy):
        getDirectory(localFolder, [proxy], remoteFolder, proxyKeyName)
    if (useStorage):
        getDirectory(localFolder, [storage], remoteFolder,
                     storageKeyName)


def calculateParallel(propertyFile, localExpDir):
    properties = loadPropertyFile(propertyFile)
    if not properties:
        print "Empty property file, failing"
        return
    nbRounds = len(properties['nbclients'])
    experimentName = properties['experimentname']
    if (not localExpDir):
        localProjectDir = properties['localprojectdir']
        expDir = properties['experiment_dir']
        localExpDir = localProjectDir + "/" + expDir
    threads = list()
    fileHandler = open(localExpDir + "/results.dat", "w+")
    for it in range(0, nbRepetitions):
        time = int(properties['exp_length'])
        manager = multiprocessing.Manager()
        results = manager.dict()
        for i in range(0, nbRounds):
            try:
                nbClients = int(properties['nbclients'][i])
                folderName = localExpDir + "/" + \
                    str(nbClients) + "_" + str(it) + "/" + \
                    str(nbClients) + "_" + str(it)
                print folderName
                executeCommand("rm -f " + folderName + "/clients.dat")
                fileList = dirList(folderName, False, 'dat')
                folderName = folderName + "/clients"
                combineFiles(fileList, folderName + ".dat")
                t = multiprocessing.Process(target=generateData, args=(
                    results, folderName + ".dat", nbClients, time))
                threads.append(t)
            except:
                print "No File " + folderName

        executingThreads = list()
        while (len(threads) > 0):
            for c in range(0, 2):
                try:
                    t = threads.pop(0)
                except:
                    break
                print "Remaining Tasks " + str(len(threads))
                executingThreads.append(t)
            for t in executingThreads:
                t.start()
            for t in executingThreads:
                t.join()
            print "Finished Processing Batch"
            executingThreads = list()
        sortedKeys = sorted(results.keys())
        for key in sortedKeys:
            fileHandler.write(results[key])
        fileHandler.flush()
    fileHandler.close()


def generateData(results, folderName, clients, time):
    print "Generating Data for " + folderName
    result = str(clients) + " "
    result += str(computeMean(folderName, 2)) + " "
    result += str(computeMin(folderName, 2)) + " "
    result += str(computeMax(folderName, 2)) + " "
    result += str(computeVar(folderName, 2)) + " "
    result += str(computeStd(folderName, 2)) + " "
    result += str(computePercentile(folderName, 2, 50)) + " "
    result += str(computePercentile(folderName, 2, 75)) + " "
    result += str(computePercentile(folderName, 2, 90)) + " "
    result += str(computePercentile(folderName, 2, 95)) + " "
    result += str(computePercentile(folderName, 2, 99)) + " "
    result += str(computeThroughput(folderName, 2, time)) + " \n"
    results[clients] = result


# Plots a throughput-latency graph. This graph assumes the
# data format in calculate() function
# Pass in as argument: a list of tuple (dataName, label)
# and the output to which this should be generated
def plotThroughputLatency(dataFileNames, outputFileName, title=None):
    x_axis = "Throughput(Trx/s)"
    y_axis = "Latency(ms)"
    if (not title):
        title = "Throughput-Latency Graph"
    data = list()
    for x in dataFileNames:
        data.append((x[0], x[1], 11, 1))
    plotLine(title, x_axis, y_axis, outputFileName,
             data, False, xrightlim=200000, yrightlim=5)


# Plots a throughput. This graph assumes the
# data format in calculate() function
# Pass in as argument: a list of tuple (dataName, label)
# and the output to which this should be generated
def plotThroughput(dataFileNames, outputFileName, title=None):
    x_axis = "Clients"
    y_axis = "Throughput (trx/s)"
    if (not title):
        title = "ThroughputGraph"
    data = list()
    for x in dataFileNames:
        data.append((x[0], x[1], 0, 11))
    plotLine(title, x_axis, y_axis, outputFileName, data,
             False, xrightlim=300, yrightlim=200000)

# Plots a throughput. This graph assumes the
# data format in calculate() function
# Pass in as argument: a list of tuple (dataName, label)
# and the output to which this should be generated


def plotLatency(dataFileNames, outputFileName, title=None):
    x_axis = "Clients"
    y_axis = "Latency(ms)"
    if (not title):
        title = "LatencyGraph"
    data = list()
    for x in dataFileNames:
        data.append((x[0], x[1], 0, 1))
    plotLine(title, x_axis, y_axis, outputFileName,
             data, False, xrightlim=300, yrightlim=5)


def updateDynamoTables(properties, experimentName):
    properties['aws_trx_table_name'] = experimentName + \
        properties['aws_trx_table_name']
    properties['aws_trx_images_table_name'] = experimentName + \
        properties['aws_trx_images_table_name']
    properties['aws_base_table_name'] = experimentName + \
        properties['aws_base_table_name']
    return properties


def deleteDynamoTables(properties):
    # TODO(natacha): add aws_acces_point to config files
    print "Deleting Dynamo Tables"
    region = "us-east-2"
    conn = boto.dynamodb.connect_to_region(region)
    print "Deleting " + properties['aws_trx_table_name']
    try:
        table = conn.get_table(properties['aws_trx_table_name'])
        conn.delete_table(table)
    except Exception as e:
        print "Failed to delete "
    try:
        print "Deleting " + properties['aws_trx_images_table_name']
        table = conn.get_table(properties['aws_trx_images_table_name'])
        conn.delete_table(table)
    except Exception as e:
        print "Failed to delete"
    try:
        print "Deleting " + properties['aws_base_table_name']
        table = conn.get_table(properties['aws_base_table_name'])
        conn.delete_table(table)
    except Exception as e:
        print "Failed to delete"
