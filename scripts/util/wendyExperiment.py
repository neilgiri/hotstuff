# Natacha Crooks ncrooks@cs.utexas.edu 2017
# Main script for running SHIELD experiments
# cloudlab setup (optional)
# Setup
# Run
# cloudlab teardown (optional)

# TODO remove redundant pieces of code (some duplication) +
# This code has not been tested by someone other than me
from graph_util import *
from math_util import *
from prop_util import *
from compile_util import *
from ssh_util import *
import cloudlab_util as cl
import os
import os.path
import sys
import datetime
import time
import random
import multiprocessing
import subprocess
import toml

sys.path.append("util/")

# To add a new experiment, create a JSON file from
# the three default json files in the config/ folder
# one for the experimental setup, one for the
# node configuration, and one for the actual
# shieldExperiment.setupConfigForcloudlab(cloudlabFile, propFile)
# shieldExperiment.setup("test.json")
# shieldExperiment.run("test.json")
# shieldExperiment.cleanupcloudlab("test.json")

proxyKeyword = "proxy"
storageKeyword = "storage"
clientKeyword = "client"
nbRepetitions = 1


def setupConfigForCloudlab(propFile, cloudlabFile):
    cloudlabProperties = loadPropertyFile(cloudlabFile)
    properties = loadPropertyFile(propFile)
    #properties['remote_store_ip_address'] = cloudlabProperties['remote_store_ip_address']
    properties['clients'] = cloudlabProperties['clients']
    # Upgrade property file
    print("Updating Property File " + str(propFile))
    with open(propFile, 'w') as fp:
        json.dump(properties, fp, indent=2, sort_keys=True)


# Sets up client machines and replica machines as
# Cloudlab machines, and updates the property file
# with ther (private) ip address
def setupCloudlab(cloudlabFile):
    clProperties = loadPropertyFile(cloudlabFile)
    if not clProperties:
        print("Empty property file, failing")
        return
    user = clProperties['username']
    replicaDiskImg = clProperties['cloudlab']['replica_disk_img']
    clientDiskImg = clProperties['cloudlab']['client_disk_img']
    #storageAmi = ecProperties['ec2']['storage_ami']
    nbClients = int(clProperties['client_machines'])
    nbReplicas = int(clProperties['replica_machines'])

    replicaInstType = clProperties['cloudlab']['replica_inst_type']
    clientInstType = clProperties['cloudlab']['client_inst_type']
    #storageInstType = ecProperties['ec2']['storage_inst_type']
    replicaRegion = clProperties['cloudlab']['replica_region']
    clientRegion = clProperties['cloudlab']['client_region']
    #storageRegion = ecProperties['ec2']['storage_region']
    replicaAvailability = clProperties['cloudlab']['replica_availability']
    clientAvailability = clProperties['cloudlab']['client_availability']
    #storageAvailability= ecProperties['ec2']['storage_availability']
    clientKeyName = clProperties['cloudlab']['keyname'] + clientRegion
    replicaKeyName = clProperties['cloudlab']['keyname'] + replicaRegion
    #storageKeyName = ecProperties['ec2']['keyname'] + storageRegion
    clientSec = clProperties['cloudlab']['client_sec']
    replicaSec = clProperties['cloudlab']['replica_sec']
    #storageSec = ecProperties['ec2']['storage_sec']
    #replicaConn = startConnection(replicaRegion)
    #replicaKey = getOrCreateKey(replicaConn, replicaKeyName)
    # print proxyKey
    #clientConn = startConnection(clientRegion)
    #clientKey = getOrCreateKey(clientConn, clientKeyName)
    #storageConn = startConnection(storageRegion)
    #storageKey = getOrCreateKey(storageConn, storageKeyName)
    experimentName = clProperties['name']
    expire = int(clProperties['expiration'])
    time = int(clProperties['timeout'])
    #useProxy = toBool(ecProperties['useproxy'])
    #useStorage = toBool(ecProperties['usestorage'])
    #useLoader = toBool(ecProperties['useloader'])
    #useSpot = toBool(ecProperties['ec2']['usespot'])

    # Start Proxy
    # if (useProxy):
    #tag = experimentName + proxyKeyword
    #startEc2Instance(proxyConn, proxyAmi, proxyKey, proxyInstType, [proxySec], proxyAvailability, tag, spot=useSpot)
    
    request = {}
    r, link = cl.startInstance(nbClients, clientDiskImg, clientInstType, 0)
    
    print("Added client machines to request")
    # Wait until finished initialising

    print("Creating VMs for nb of replica machines")
    if replicaRegion == clientRegion:
        r, link = cl.startInstance(nbReplicas, replicaDiskImg, replicaInstType, nbClients, r, link)
        request[replicaRegion] = r
    else:
        r1, link = cl.startInstance(nbReplicas, replicaDiskImg, replicaInstType, nbClients)
        request[replicaRegion] = r1
        request[clientRegion] = r

    m = cl.request(experiment_name=experimentName,
                   requests=request,
                   expiration=expire,
                   timeout=time,
                   cloudlab_user=None,
                   cloudlab_password=None,
                   cloudlab_project=None,
                   cloudlab_cert_path=None,
                   cloudlab_key_path=None)

    ips = list()
    i = 0
    nodes = m[clientRegion].nodes
    while i < nbClients:
        ips.append(nodes[i].hostipv4)
        i += 1
        print(len(ips))
    clProperties["clients"] = ips

    ips = list()
    if clientRegion != replicaRegion:
        nodes = m[replicaRegion].nodes
        i = 0

    while i < len(nodes):
        ips.append(nodes[i].hostipv4)
        i += 1

        print(len(ips))

    print("Finished Initialising Replicas")
    clProperties['replicas'] = ips
    print(clProperties['replicas'])

    # Upgrade property file
    print("Property File " + str(cloudlabFile))
    with open(cloudlabFile, 'w') as fp:
        json.dump(clProperties, fp, indent=2, sort_keys=True)

    #installPackages([user + "@" + r for r in clProperties['replicas']], ["golang-go"], replicaKeyName)
    #installPackages([user + "@" + c for c in clProperties['clients']], ["golang-go"], clientKeyName)


# if method called, terminate VMs
def cleanupCloudlab(cloudlabFile, contextFile='/tmp/context.json', cred_file='/Users/neilgiridharan/.bssw/geni/emulab-ch2-giridhn-usercred.xml'):
    clProperties = loadPropertyFile(cloudlabFile)

    if not clProperties:
        print("Empty property file, failing")
        return

    #storageAmi = ecProperties['cloudlab']['storage_ami']
    #storageSec = ecProperties['cloudlab']['storage_sec']
    #proxyConn = startConnection(proxyRegion)
    #proxyKey = getOrCreateKey(proxyConn, proxyKeyName)
    #clientConn = startConnection(clientRegion)
    #clientKey = getOrCreateKey(clientConn, clientKeyName)
    #storageConn = startConnection(storageRegion)
    #storageKey = getOrCreateKey(storageConn, storageKeyName)
    #executeCommand("rm " + cred_file)
    experimentName = clProperties['name']
    replicaRegion = clProperties['cloudlab']['replica_region']
    clientRegion = clProperties['cloudlab']['client_region']

    cloudlab_password = None
    cloudlab_password = cl.check_var(cloudlab_password, 'CLOUDLAB_PASSWORD')
    c = cl.loadContext(contextFile, key_passphrase=cloudlab_password)
    cl.do_release(c, experimentName, [clientRegion, replicaRegion])
    #cl.default_context()

    # Terminate proxy
    # proxyId = getcloudlabInstancesId(
    #    proxyConn, 'Name', {'tag:Name': tag}, True)
    #terminatecloudlabInstances(proxyConn, proxyId)
    # Terminate clients
    # clientId = getcloudlabInstancesId(
    #terminatecloudlabInstances(clientConn, clientId)
    # print(clientId)
    # storageId = getcloudlabInstancesId(
    #terminatecloudlabInstances(storageConn, storageId)
    # print(storageId)


def loadOptionalKey(properties, key):
    try:
        prop = properties[key]
        return prop
    except:
        return None

# Function that setups up appropriate folders on the
# correct machines, and sends the jars. It assumes
# that the appropriate VMs/machines have already started


def setup(propertyFile):
    print("Setup")

    properties = loadPropertyFile(propertyFile)
    #clProperties = loadPropertyFile(cloudlabFile)
    if not properties:
        print("Empty property file, failing")
        return

    ##### LOADING PROPERTIES FILE ####
    user = properties['username']
    #password = properties['password']
    #project = properties['project']
    experimentName = properties['experimentname']
    #certificatePath = properties['certificatepath']
    #publicKeyPath = properties['publickeypath']
    localProjectDir = properties['localprojectdir']
    remoteProjectDir = properties['remoteprojectdir']
    localSrcDir = properties['localsrcdir']
    clientCmdDir = localSrcDir + "/cmd/hotstuffclient"
    replicaCmdDir = localSrcDir + "/cmd/hotstuffserver"
    keygen = localSrcDir + "/" + properties['gokeygen']
    expFolder = 'results/' + experimentName
    expDir = expFolder + "/" + datetime.datetime.now().strftime("%Y:%m:%d:%H:%M") + "/"
    #storageKeyName = ecProperties['cloudlab']['keyname'] + storageRegion + ".pem"

    clientKeyName = properties['cloudlab']['client_keyname']
    replicaKeyName = properties['cloudlab']['replica_keyname']


    replica_ip_addresses = properties['replicas']
    #storage = ecProperties['remote_store_ip_address']
    localPath = localProjectDir + '/' + expDir
    remotePath = remoteProjectDir + '/' + expFolder

    #useProxy = toBool(ecProperties['useproxy'])
    #useStorage = toBool(ecProperties['usestorage'])
    #useLoader = toBool(ecProperties['useloader'])

###### UPDATE DB DIRECTORY #####
    # properties['db_file_path'] = remoteProjectDir + \
    #    '/' + expFolder + "/" + properties['db_file_name']
    # properties['db_file_path'] =  properties['db_file_name']

#### LOADING/GENERATING JAR FILES ####

    #jarName = properties['jar']
    clientMainClass = properties['clientmain']
    replicaMainClass = properties['replicamain']
    #storageMainClass = loadOptionalKey(properties, 'storagemain')
    #loaderMainClass = loadOptionalKey(properties, 'loadermain')

    # print "Using Proxy " + str(useProxy)
    # print "Using Storage " + str(useStorage)
    # print "Using Loader " + str(useLoader)
    #sendDirectoryHosts(localProjectDir, [user + "@" + r for r in replica_ip_addresses], properties['remotedirprefix'])
    #sendDirectoryHosts(localProjectDir, [user + "@" + c for c in properties['clients']], properties['remotedirprefix'])


    # Compile Go Executables
    print("Setup: Compiling Executables")
    


    currentDir = os.getcwd()
    #executeCommand(" cd " + localSrcDir)
    #executeCommand("cd " + localSrcDir + " ; mvn install")
    #executeCommand("cd " + localSrcDir + " ; mvn package")
    executeParallelBlockingRemoteCommand([user + "@" + r for r in replica_ip_addresses], "cd " + remoteProjectDir + " ; make all")
    time.sleep(40)
    executeParallelBlockingRemoteCommand([user + "@" + c for c in properties['clients']], "cd " + remoteProjectDir + " ; make all")
    time.sleep(40)
    print(remoteProjectDir + "/" + replicaMainClass)

    #fileExists = os.path.isfile(clientCmdDir + "/" + clientMainClass)
    #if (not fileExists):
    #    print("Error: Incorrect Client executable")
    #    exit()

    #fileExists = os.path.isfile(replicaCmdDir + "/" + replicaMainClass)
    #if (not fileExists):
    #    print("Error: Incorrect Replica executable")
    #    exit()
    print("Generating the keys")
    replicaHostIps = ""
    #print(properties['replicas'])
    for r in properties['replicas']:
        #print(r)
        replicaHostIps = replicaHostIps + r + ","
    replicaHostIps = replicaHostIps[:-1]
    executeCommand(keygen + " -p 'r*' -n " + str(len(properties['replicas'])) + " --hosts " + replicaHostIps + " --tls " + localSrcDir + "/keys")
    sendDirectoryHosts(localSrcDir + "/keys", [user + "@" + r for r in properties['replicas']], remoteProjectDir)
    sendDirectoryHosts(localSrcDir + "/keys", [user + "@" + c for c in properties['clients']], remoteProjectDir)


#### GENERATING EXP DIRECTORY ON ALL MACHINES ####

    print("Creating Experiment directory")
    clientIpList = list()
    for c in properties['clients']:
        clientIpList.append(c)
    for c in clientIpList:
        print(c)
        mkdirRemote(user + "@" + c, remotePath, clientKeyName)

    replicaIpList = list()
    for r in properties['replicas']:
        replicaIpList.append(r)
    for r in replicaIpList:
        print(r)
        mkdirRemote(user + "@" + r, remotePath, replicaKeyName)
    # if (useProxy):
        # print(proxy)
        #mkdirRemote(proxy, remotePath, proxyKeyName)
    # if (useStorage):
        #print("Reached here")
        #mkdirRemote(storage, remotePath, storageKeyName)
    executeCommand("mkdir -p " + localPath)

#### SENDING executables TO ALL MACHINES ####

    # Send Jars
    print("Sending executables to all Machines")
    #j = mavenDir + "/" + jarName
    clientExec = clientCmdDir + "/" + clientMainClass
    replicaExec = replicaCmdDir + "/" + replicaMainClass
    print(remotePath)
    print(clientIpList)
    print(replicaIpList)
    # print(useStorage)
    #sendFileHosts(j, clientIpList, remotePath, clientKeyName)
    #sendFileHosts(clientExec, [user + "@" + c for c in clientIpList], remotePath, clientKeyName)
    #sendFileHosts(replicaExec, [user + "@" + r for r in replicaIpList], remotePath, replicaKeyName)
    # if (useProxy):
    #sendFileHosts(j, [proxy], remotePath, proxyKeyName)
    # if (useStorage):
    #sendFileHosts(j, [storage], remotePath, storageKeyName)
    #executeCommand("cp " + clientExec + " " + localPath)
    #executeCommand("cp " + replicaExec + " " + localPath)

    # Create file with git hash
    #executeParallelBlockingRemoteCommand([user + "@" + r for r in replica_ip_addresses], "cp " + propertyFile + " " + remotePath)
    #executeParallelBlockingRemoteCommand([user + "@" + c for c in properties['clients']], "cp " + propertyFile + " " + remotePath)

    executeCommand("cp " + propertyFile + " " + localPath)
    gitHash = getGitHash(localSrcDir).decode("utf-8")
    print("Saving Git Hash " + gitHash)
    executeCommand("touch " + localPath + "/git.txt")
    with open(localPath + "/git.txt", 'ab') as f:
        f.write(str.encode(gitHash))
    # Write back the updated property file
    with open(propertyFile, 'w') as fp:
        json.dump(properties, fp, indent=2, sort_keys=True)
    executeCommand("cp " + propertyFile + " " + localPath)
    return localPath

def create_config(propertyFile):
    properties = loadPropertyFile(propertyFile)
    #clProperties = loadPropertyFile(cloudlabFile)
    if not properties:
        print("Empty property file, failing")
        return
    replicas = properties['replicas']
    clients = properties['clients']
    username = properties['username']
    data_dict = {"pacemaker": "round-robin", "leader-id": 1, "view-change": 100, "leader-schedule": [1, 2, 3, 4]}
    id = 1
    replicas_dict = []
    for r in replicas:
        r_dict = {"id": str(id), "peer-address": r + ":13371", "client-address": r + ":23371", "pubkey": "keys/r" + str(id) + ".key.pub", "cert": "keys/r" + str(id) + ".crt"}
        replicas_dict.append(r_dict)
        id += 1
    data_dict['replicas'] = replicas_dict
    output_file_name = "hotstuff.toml"
    with open(output_file_name, "w") as toml_file:
        toml.dump(data_dict, toml_file)
    
    sendFileHosts(output_file_name, [username + "@" + r for r in replicas], properties['remoteprojectdir'], properties['cloudlab']['replica_keyname'])
    sendFileHosts(output_file_name, [username + "@" + c for c in clients], properties['remoteprojectdir'], properties['cloudlab']['client_keyname'])



def run(propertyFile, cloudlabFile="cloudlab.json"):

    print("Run")
    properties = loadPropertyFile(propertyFile)
    #clProperties = loadPropertyFile(cloudlabFile)
    if not properties:
        print("Empty property file, failing")
        return

    #useStorage = toBool(properties['usestorage'])
    #useProxy = toBool(properties['useproxy'])
    #useLoader = toBool(properties['useloader'])
    #jarName = properties['jar']
    #clientMainClass = properties['clientmain']
    #replicaMainClass = properties['replicamain']
    # if (useProxy):
    #    proxyMainClass = properties['proxymain']
    # if (useLoader):
    #    loaderMainClass = properties['loadermain']
    # if (useStorage):
    #storageKeyName = ecProperties['cloudlab']['keyname'] + storageRegion + ".pem"
    experimentName = properties['experimentname']
    localProjectDir = properties['localprojectdir']
    remoteProjectDir = properties['remoteprojectdir']
    goCommandClient = properties['gocommandclient']
    goCommandReplica = properties['gocommandreplica']

    # try:
    #    javaCommandStorage = properties['javacommandstorage']
    # except:
    #    javaCommandStorage = javaCommandServer

    # try:
    #    noKillStorage = properties['no_kill_storage']
    # except:
    #    noKillStorage = False

    try:
        simulateLatency = int(properties['simulate_latency'])
    except:
        simulateLatency = 0

    username = properties["username"]
    expDir = properties['experiment_dir']
    remoteExpDir = remoteProjectDir + "/" + expDir + "/results/" + experimentName 
    localExpDir = localProjectDir + "/" + expDir
    nbRounds = len(properties['nbclients'])
    logFolders = properties['log_folder']
    # TODO(natacha): cleanup
    try:
        reuseData = toBool(properties['reuse_data'])
        print("Reusing Data " + str(reuseData))
    except:
        reuseData = False

    # Create connections for everyone
    #clientConn = startConnection(clientRegion)
    #clientKey = getOrCreateKey(clientConn, clientKeyName)
    clientIpList = list()
    for c in properties['clients']:
        clientIpList.append(c)

    replicaIpList = list()
    for r in properties['replicas']:
        replicaIpList.append(r)

    #proxy = properties['proxy_ip_address']
    #proxyConn = startConnection(proxyRegion)
    #replicaKey = getOrCreateKey(proxyConn, replicaKeyName)
    #storage = properties['remote_store_ip_address']
    #storageConn = startConnection(storageRegion)
    #storageKey = getOrCreateKey(storageConn, storageKeyName)

    #properties = updateDynamoTables(properties, experimentName)

    # Setup latency on appropriate hosts if
    # simulated
    clientKey = properties['cloudlab']['client_keyname']
    replicaKey = properties['cloudlab']['replica_keyname']

    clientKeyName = clientKey
    replicaKeyName = replicaKey

    print("WARNING: THIS IS HACKY AND WILL NOT WORK WHEN CONFIGURING MYSQL")
    if (simulateLatency):
        print("Simulating a " + str(simulateLatency) + " ms")
        for replica in replicaIpList:
            setupTC(replica, simulateLatency, replicaKey)
        # if (useProxy):
            #setupTC(proxy, simulateLatency, [storage], proxyKey)
            # if (useStorage):
            #setupTC(storage, simulateLatency, [proxy], storageKey)
        # else:
            # Hacky if condition for our oram tests without proxy
            # Because now latency has to be between multiple hostsu
            # if (useStorage):
        for c in clientIpList:
            setupTC(c, simulateLatency, replicaIpList, clientKey)

    first = True
    dataLoaded = False
    #nbRounds = 1
    for i in range(0, nbRounds):
        time.sleep(10)
        for it in range(0, nbRepetitions):
            time.sleep(10)
            try:
                print("Running Round: " + str(i) + " Iter " + str(it))
                nbClients = int(properties['nbclients'][i])
                print("Number of clients " + str(nbClients))
                localRoundFolder = localExpDir + "/" + \
                    str(nbClients) + "_" + str(it)
                remoteRoundFolder = remoteExpDir + \
                    "/" + str(nbClients) + "_" + str(it)
                print("Round Folder : " + str(localRoundFolder))
                localPath = localRoundFolder
                remotePath = remoteRoundFolder
                print("Remote Path :" + str(remotePath))
                executeCommand("mkdir -p " + localPath)
                logFolder = remotePath + "/" + logFolders
                properties['log_folder'] = logFolder
                localProp = localPath + "/properties"
                remoteProp = remotePath + "/properties"
                properties['exp_dir'] = remotePath

                # Create folders on appropriate hosts
                for c in clientIpList:
                    mkdirRemote(username + "@" + c, remotePath, clientKey)
                    mkdirRemote(username + "@" + c, logFolder, clientKey)
                for r in replicaIpList:
                    mkdirRemote(username + "@" + r, remotePath, replicaKey)
                    mkdirRemote(username + "@" + r, logFolder, replicaKey)

                # if (useProxy):
                    #mkdirRemote(proxy, remotePath, proxyKey)
                    #mkdirRemote(proxy, logFolder, proxyKey)
                # if (useStorage):
                    #mkdirRemote(storage, remotePath, storageKey)
                    #mkdirRemote(storage, logFolder, storageKey)

                properties['replica_listening_port'] = str(
                    random.randint(20000, 30000))

                # if (first or (not noKillStorage)):
                # properties['remote_store_listening_port'] = str(
                # random.randint(30000, 40000))

                localProp = localPath + "/properties"
                remoteProp = remotePath + "/properties"

                # start storage
                #print("Start Storage (Having Storage " + str(useStorage) + ")")
                # if (useStorage and (first or (not noKillStorage))):
                #first = False
                ##print("Starting Storage again")
                #sid = nbClients + 2
                #properties['node_uid'] = str(sid)
                #properties['node_ip_address'] = storage
                #properties['node_listening_port'] = properties['remote_store_listening_port']
                #localProp_ = localProp + "_storage.json"
                #remoteProp_ = remoteProp + "_storage.json"
                # with open(localProp_, 'w') as fp:
                #json.dump(properties, fp, indent=2, sort_keys=True)
                #print("Sending Property File and Starting Server")
                #sendFile(localProp_, storage, remotePath, storageKey)
                # cmd = "cd " + remoteExpDir + " ;  " + javaCommandStorage + " -cp " + jarName + " " + storageMainClass + " " + remoteProp_ + " 1>" + \
                # remotePath + "/storage" + \
                # str(sid) + ".log 2>" + remotePath + \
                #"/storage_err" + str(sid) + ".log"
                # t = executeNonBlockingRemoteCommand(
                # storage, cmd, storageKey)
                # t.start()
                # else:
                #print("Storage already started")

                time.sleep(30)
                # start replicas
                print("Start Replicas")
                # if (useProxy):
                sid = nbClients + 1
                #properties['node_uid'] = str(sid)
                #properties['node_ip_address'] = proxy
                properties['replicas'] = replicaIpList
                #properties['node_listening_port'] = properties['proxy_listening_port']
                localProp_ = localProp + "_replicas.json"
                remoteProp_ = remoteProp + "_replicas.json"
                with open(localProp_, 'w') as fp:
                    json.dump(properties, fp, indent=2, sort_keys=True)
                print("Sending Property File and Starting Server")
                for replica in replicaIpList:
                    sendFile(localProp_, username + "@" + replica, remotePath, replicaKey)
                    # cmd = "cd " + remoteExpDir + " ; " + javaCommandServer + " -cp " + jarName + " " + proxyMainClass + " " + remoteProp_ + " 1>" + \
                    #    remotePath + "/proxy" l+ \
                    #    str(sid) + ".log 2>" + remotePath + \
                    #    "/proxy_err" + str(sid) + ".og"

                    id = sid - nbClients
                    cmd = "cd " + remoteProjectDir + " ; " + goCommandReplica + " --self-id " + str(id) + " --privkey keys/r" + str(id) + ".key --batch-size 800 --cpuprofile cpuprofile.out 1> " + \
                        remotePath + "/replica_" + replica + "_" + \
                        str(sid) + ".log"
                    sid += 1

                    print(cmd)
                    t = executeNonBlockingRemoteCommand(username + "@" +
                        replica, cmd, replicaKeyName)
                    t.start()

                time.sleep(30)

                oldDataSet = None
                ## Load Data ##
                #print("Start Loader (Having Loader " + str(useLoader) + ")")
                # if (useLoader and ((not dataLoaded) or (not reuseData))):
                #    dataLoaded = True
                #    localProp_ = localProp + "_loader.json"
                #    remoteProp_ = remoteProp + "_loader.json"
                #    ip = clientIpList[0]
                ##    properties['node_uid'] = str(nbClients + 3)
                #    properties['node_ip_address'] = ip
                #    properties.pop('node_listening_port', None)

                #    oldDataSet = properties['key_file_name']
                #    dataset_remloc = remotePath + "/" + \
                #        properties['key_file_name']
                #    dataset_localoc = localPath + "/" + \
                #        properties['key_file_name']
                #    properties['key_file_name'] = dataset_remloc
                #    with open(localProp_, 'w') as fp:
                #        json.dump(properties, fp, indent=2, sort_keys=True)
                #    sendFile(
                #        localProp_, clientIpList[0], remotePath, clientKeyName)
                # cmd = "cd " + remoteExpDir + "; " + javaCommandClient + " -cp " + jarName + " " + loaderMainClass + \
                #    " " + remoteProp_ + " 1>" + remotePath + \
                #    "/loader.log 2>" + remotePath + "/loader_err.log"

                # Generate data set via executing the loader
                #    executeRemoteCommand(clientIpList[0], cmd, clientKeyName)
                #    getFile(dataset_remloc, [
                #            clientIpList[0]], dataset_localoc, clientKey)
                # Once dataset has been executed, send it out to all clients
                #    sendFileHosts(dataset_localoc, clientIpList,
                #                  dataset_remloc, clientKey)

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
                    sendFile(localProp_, username + "@" + ip, remoteProp_, clientKeyName)
                    # cmd = "cd " + remoteExpDir + " ; " + javaCommandClient + " -cp " + clientMainClass + " " + jarName + " " + remoteProp_ + " 1>" + remotePath + "/client_" + ip + "_" + \
                    #    str(cid) + ".log 2>" + remotePath + \
                    #    "/client_" + ip + "_" + str(cid) + "_err.log"
                    # cmd = "cd " + remoteExpDir + "; " + javaCommandClient + " -cp " + jarName + " " + clientMainClass + " " + remoteProp_ + " 1>" + remotePath + "/client_" + ip + "_" + \
                    #    str(cid) + ".log 2>" + remotePath + \
                    #    "/client_" + ip + "_" + str(cid) + "_err.log"
                    cmd = "cd " + remoteProjectDir + " ; " + goCommandClient + " --self-id " + str(cid) + " --max-inflight 1000 --payload-size 0 --exit-after " + properties['exp_length'] + " 1>" + \
                        remotePath + "/client_" + ip + "_" + \
                        str(cid) + ".log"
                    t = executeNonBlockingRemoteCommand(username + "@" + ip, cmd, clientKeyName)
                    client_list.append(t)
                    properties['run_name'] = oldRunName

                print("Start clients")
                time.sleep(30)
                for t in client_list:
                    t.start()
                for t in client_list:
                    t.join(9600)
                collectData(propertyFile, cloudlabFile, localPath, remotePath)
                time.sleep(60)
                print("Finished Round")
                print("---------------")
                if oldDataSet is not None:
                    properties['key_file_name'] = oldDataSet

                for c in clientIpList:
                    try:
                        executeRemoteCommandNoCheck(
                            username + "@" + c, "ps -ef | grep wendyecclient | grep -v grep | grep -v bash | awk '{print \$2}' | xargs -r kill -9", clientKeyName)
                        executeRemoteCommandNoCheck(
                            username + "@" + c, "ps -ef | grep fastwendyecclient | grep -v grep | grep -v bash | awk '{print \$2}' | xargs -r kill -9", clientKeyName)
                        executeRemoteCommandNoCheck(
                            username + "@" + c, "ps -ef | grep hotstuffclient | grep -v grep | grep -v bash | awk '{print \$2}' | xargs -r kill -9", clientKeyName)
                    except Exception as e:
                        print(" ")

                for r in replicaIpList:
                    try:
                        executeRemoteCommandNoCheck(
                            username + "@" + r, "ps -ef | grep wendyecserver | grep -v grep | grep -v bash | awk '{print \$2}' | xargs -r kill -9", replicaKeyName)
                        executeRemoteCommandNoCheck(
                            username + "@" + r, "ps -ef | grep fastwendyecserver | grep -v grep | grep -v bash | awk '{print \$2}' | xargs -r kill -9", replicaKeyName)
                        executeRemoteCommandNoCheck(
                            username + "@" + r, "ps -ef | grep hotstuffserver | grep -v grep | grep -v bash | awk '{print \$2}' | xargs -r kill -9", replicaKeyName)
                    except Exception as e:
                        print(" ")

                # if (useProxy):
                #    try:
                #        print("Killing Proxy" + str(proxy))
                #        executeRemoteCommandNoCheck(
                #            proxy, "ps -ef | grep java | grep -v grep | grep -v bash | awk '{print \$2}' | xargs -r kill -9", proxyKeyName)
                #    except Exception as e:
                #        print(" ")

                # if (useStorage and not noKillStorage):
                #    try:
                #        print("Killing Storage" + str(storage))
                #        executeRemoteCommandNoCheck(
                #            storage, "ps -ef | grep java | grep -v grep | awk '{print \$2}' | xargs -r kill -9", storageKeyName)
                #    except Exception as e:
                #        print(" ")
                # else:
                #    print("No Kill Storage")
                # if (deleteTable):
                #    deleteDynamoTables(properties)

            except Exception as e:
                print(" ")
            except subprocess.CalledProcessError as e:
                print(str(e.returncode))

    # Tear down TC rules
    # if (simulateLatency):
        # if (useProxy):
        #    deleteTC(proxy, storage, proxyKey)
        # if (useStorage):
        #    deleteTC(storage, proxy, storageKey)

    return expDir

# Cleanup: kills ongoing processes and removes old data
# directory


def cleanup(propertyFile, cloudlabFile="cloudlab.json"):
    properties = loadPropertyFile(propertyFile)
    clProperties = loadPropertyFile(cloudlabFile)
    if not properties or not clProperties:
        print("Empty property file, failing")
    #storageKeyName = ecProperties['cloudlab']['keyname'] + storageRegion + ".pem"
    experimentName = properties['experimentname']
    user = properties['username']

    clientKeyName = properties['cloudlab']['client_keyname']
    replicaKeyName = properties['cloudlab']['replica_keyname']

    #useStorage = toBool(properties['usestorage'])
    #useProxy = toBool(properties['useproxy'])

    print("Killing processes")
    clientIpList = list()
    replicas = list()

    for c in properties['clients']:
        clientIpList.append(c)
    for r in properties['replicas']:
        replicas.append(r)

    #proxy = properties['proxy_ip_address']
    #storage = properties['remote_store_ip_address']

    for c in clientIpList:
        try:
            print("Killing " + str(c))
            executeRemoteCommandNoCheck(
                c, "ps -ef | grep wendyecclient | awk '{print \$2}' | xargs -r kill -9", clientKeyName)
        except Exception as e:
            print(" ")

    for r in replicas:
        try:
            print("Killing " + str(c))
            executeRemoteCommandNoCheck(
                c, "ps -ef | grep wendyecserver | awk '{print \$2}' | xargs -r kill -9", replicaKeyName)
        except Exception as e:
            print(" ")

    # if (useProxy):
    #    try:
    #        print("Killing Proxy" + str(proxy))
    #        executeRemoteCommandNoCheck(
    #            proxy, "ps -ef | grep java | grep -v grep | grep -v bash | awk '{print \$2}' | xargs -r kill -9", proxyKeyName)
    #    except Exception as e:
    #        print(" ")

    # if (useStorage):
    #    try:
    #        print("Killing Storage" + str(storage))
    #        executeRemoteCommandNoCheck(
    #            storage, "ps -ef | grep java | grep -v grep | awk '{print \$2}' | xargs -r kill -9", storageKeyName)
    #    except Exception as e:
    #        print(" ")

    print("Removing old experiments")
    remoteFolder = properties['experiment_dir'] + '/' + experimentName
    for c in clientIpList:
        rmdirRemoteIfExists(c, remoteFolder, clientKeyName)
    for r in replicas:
        rmdirRemoteIfExists(c, remoteFolder, replicaKeyName)

    # if (useProxy):
    #    rmdirRemoteIfExists(proxy, remoteFolder, proxyKeyName)
    # if (useStorage):
    #    rmdirRemoteIfExists(storage, remoteFolder, storageKeyName)

    #if (deleteTable): deleteDynamoTables(propertyFile)


# Collects the data for the experiment
def collectData(propertyFile, cloudlabFile, localFolder, remoteFolder):
    print("Collect Data")

    properties = loadPropertyFile(propertyFile)
    #clProperties = loadPropertyFile(cloudlabFile)
    if not properties:
        print("Empty property file, failing")
    #storageKeyName = ecProperties['cloudlab']['keyname'] + storageRegion + ".pem"
    #useStorage = toBool(properties['usestorage'])
    #useProxy = toBool(properties['useproxy'])
    user = properties['username']

    clientIpList = list()
    replicas = list()

    for c in properties['clients']:
        clientIpList.append(user + "@" + c)

    for r in properties['replicas']:
        replicas.append(user + "@" + r)
    #proxy = properties['proxy_ip_address']
    #storage = properties['remote_store_ip_address']
    print("Getting Data ")
    print(clientIpList)
    print(replicas)

    clientKeyName = properties['cloudlab']['client_keyname']
    replicaKeyName = properties['cloudlab']['replica_keyname']

    getDirectory(localFolder, clientIpList, remoteFolder, clientKeyName)
    getDirectory(localFolder, replicas, remoteFolder, replicaKeyName)

    # if (useProxy):
    #    getDirectory(localFolder, [proxy], remoteFolder, proxyKeyName)
    # if (useStorage):
    #    getDirectory(localFolder, [storage], remoteFolder,
    #                 storageKeyName)


def calculateParallel(propertyFile, localExpDir):
    properties = loadPropertyFile(propertyFile)
    if not properties:
        print("Empty property file, failing")
        return
    
    nbRounds = len(properties['nbclients'])
    experimentName = properties['experimentname']
    remoteExpDir = properties['remoteprojectdir'] + "/" + properties["experiment_dir"] + "/results/" + experimentName
    host = properties['username'] + "@" + properties['clients'][0]
    
    rsyncDir = ""
    if (not localExpDir):
        localProjectDir = properties['localprojectdir']
        expDir = properties['experiment_dir']
        localExpDir = localProjectDir + "/" + expDir + "/" + experimentName
        rsyncDir = localProjectDir + "/" + expDir
    
    getDirectoryRsync(rsyncDir, [properties['username'] + "@" + c for c in properties['clients']], remoteExpDir)
    #threads = list()
    fileHandler = open(localExpDir + "/results.dat", "w+")
    for it in range(0, nbRepetitions):
        time = int(properties['exp_length'])
        #manager = multiprocessing.Manager()
        #results = manager.dict()
        results = {}
        for i in range(0, nbRounds):
            try:
                nbClients = int(properties['nbclients'][i])
                folderName = localExpDir + "/" + \
                    str(nbClients) + "_" + str(it) + "/"
                print(folderName)
                #executeCommand("rm -f " + folderName + "/clients.dat")
                fileList = dirList(folderName, False, 'log')
                print(fileList)
                #folderName = folderName + "client_" + properties['clients'][0] + "_" + str(nbClients)
                combineFiles(fileList, folderName + "client.dat")
                #t = multiprocessing.Process(target=generateData, args=(
                #    results, folderName + ".log", nbClients, time))
                #threads.append(t)
                generateData(results, folderName + "client.dat", nbClients, time)
            except:
                print("No File " + folderName)

        #executingThreads = list()
        #while (len(threads) > 0):
        #    for c in range(0, 2):
        #        try:
        #            t = threads.pop(0)
        #        except:
        #            break
        #        print("Remaining Tasks " + str(len(threads)))
        #        executingThreads.append(t)
        #    if __name__ == 'main':
        #        for t in executingThreads:
        #            t.start()
        #        for t in executingThreads:
        #            t.join()
        #    print("Finished Processing Batch")
        #    executingThreads = list()
        sortedKeys = sorted(results.keys())
        for key in sortedKeys:
            fileHandler.write(results[key])
        fileHandler.flush()
    fileHandler.close()


def generateData(results, folderName, clients, time):
    print("Generating Data for " + folderName)
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
    x_axis = "Throughput(cmds/s)"
    y_axis = "Latency(ms)"
    if (not title):
        title = "Throughput-Latency Graph"
    data = list()
    for x in dataFileNames:
        data.append((x[0], x[1], 11, 1))
    plotLine(title, x_axis, y_axis, outputFileName,
             data, False, xleftlim=0, xrightlim=250000, yrightlim=20)


# Plots a throughput. This graph assumes the
# data format in calculate() function
# Pass in as argument: a list of tuple (dataName, label)
# and the output to which this should be generated
def plotThroughput(dataFileNames, outputFileName, title=None):
    x_axis = "Clients"
    y_axis = "Throughput (cmds/s)"
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
