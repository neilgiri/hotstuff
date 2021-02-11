import os
import sys
import datetime
import time
import socket

sys.path.append("../../../scripts")
import ssh_util
import ec2_util as ec2
import boto.ec2
import compile_util as comp
import prop_util as prop

# Experimental Setup Parameters
name_tag = "Name"
bin_name = "ping"
user = "ubuntu"
delay = 1
security_group = "launch-wizard"
ami = {"us-west-1":"ami-916432f1","us-west-2":"ami-9550fbf5","us-east-1":"ami-2ef48339", "us-east-2":"ami-85a0fae0","ca-central-1":"ami-60308204","eu-west-1":"ami-701b3c03", "eu-west-2": "ami-28efe54c", "eu-central-1":"ami-1ff83970", "ap-northeast-1":"ami-f2e88795", "ap-northeast-2":"ami-c278afac","ap-southeast-1": "ami-11d47b72", "ap-southeast-2":"ami-7a9da519", "ap-south-1":"ami-9680f7f9","sa-east-1":"ami-39de4655"}
instance = "t2.nano"
defaultkey = "default"
remote_path = "/home/ubuntu/"
exp_folder = "results/" + datetime.datetime.now().strftime("%Y:%m:%d:%H:%M") + "/"
remote_exp_folder = remote_path + "/" + exp_folder
tag = "ping"

# Global Variables
keys  = {}

def log(host,cmd):
    print "[" + host + "]:" + cmd

def get_instances_per_region(regions):
    ip_to_region = {}
    for re in regions:
        conn = ec2.startConnection(re)
        try:
            ips = ec2.getEc2InstancesPublicIp(conn,name_tag)
            for (name,ip) in ips:
                ip_to_region[ip] = re
        except Exception as e:
            print "Failed to get Ips in " + c.region.name + " " + str(e)
    return ip_to_region

# Computes the list of all publicip addresses running in all
# regions
def get_all_instances(regions,filters=None):
    all_ips = []
    connections = [ec2.startConnection(re) for re in regions]
    for c in connections:
        try:
            ips = ec2.getEc2InstancesPublicIp(c, name_tag,filters)
            all_ips.extend(ips)
        except Exception as e:
            print "Failed to get Ips in " + c.region.name + " " +  str(e)
    return all_ips

# Creates two compute instance, with ami type and instance
# type specified in global array ami and field instance
def create_instances(regions):
    print "Creating instances"
    connections = [ec2.startConnection(re) for re in regions]
    for c in connections:
        try:
            key = keys[c.region.name]
            reservation = c.run_instances(ami[c.region.name],key_name=key,instance_type=instance,security_groups=[security_group])
            reservation.instances[0].add_tag('Name', 'ping')
            reservation = c.run_instances(ami[c.region.name],key_name=key,instance_type=instance,security_groups=[security_group])
            reservation.instances[0].add_tag('Name', 'ping')
        except Exception as e:
            print e
            print "Failed to create instance in " + c.region.name

#Terminates all currently running ping instances
def cancel_instances(regions):
    connections = [ec2.startConnection(re) for re in regions]
    for c in connections:
        try:
            ids = ec2.getEc2InstancesId(c,name_tag,filters={"tag:Name":"ping"})
            print "IDs to terminate for region " + c.region.name + " are"
            print ids
            if (len(ids)>0):
                ec2.terminateEc2Instances(c,ids)
        except Exception as e:
            print e
            print "failed to terminate instance"


def load_keys(keyname,regions):
    for r in regions:
        conn = ec2.startConnection(r)
        key = keyname + "-" + r
        keys[r] = ec2.getOrCreateKey(conn,key)


def start(key):
  # First, setup EC2 instances #
  # This code uses public IP address
   print "Starting ... "
   regions = ec2.ec2_regions
   if (key == None):
     key = defaultkey
   # Update binary
   comp.compileFromMake(targets=[""]);
   ssh_util.executeCommand("mkdir -p " + exp_folder)
   git_hash = prop.getGitHash(".")
   fi_name = exp_folder + "/hash.txt"
   with open(fi_name,'w') as f:
       f.write(git_hash)
   load_keys(key,regions)
   ips = get_all_instances(regions)
   this_host = socket.gethostbyname(socket.gethostname())
   print "This host is " + this_host
   print "ips before start:"
   print ips
   # Creates an instance in every region. Make sure to specify key if not running from Amazon
   create_instances(regions)
   # This list includes terminated VMs
   all_ips = get_all_instances(regions,{'tag:Name':'ping'})
   # Remove terminated VMs
   terminated_ips = get_all_instances(regions,{'tag:instance-state-code':'48'})
   ips = [x for x in all_ips if x not in terminated_ips]
   # Populates ip_to_region
   ip_to_region = get_instances_per_region(regions)
   print "ips after start:"
   print ip_to_region
   # Wait until have initialised
   time.sleep(120)
   # Dirty hack to prevent textfile busy
   counter = 0
   for (name,host) in ips:
        for (to_name,to_host) in ips:
         print "(" + name + "," + host + "," + to_name + "," + to_host + ")"
         if ((host!=to_host) & (host!=this_host) & (to_host!=this_host)):
          try:
           log(host,"Creating experiment directory " +  remote_exp_folder)
           re_from = ip_to_region[host]
           re_to = ip_to_region[to_host]
           key = keys[re_from] + ".pem"
           initialised = False
           # Retry until call is successful
           while initialised!=True:
               try:
                   #Create Exp Dir
                   ssh_util.mkdirRemote(host,remote_exp_folder,key)
                   ssh_util.executeCommand("cp build/ping build/ping" + str(counter))
                   #Send Binary file
                   ssh_util.sendFile("build/ping" + str(counter),host,".",key)
                   initialised=True
               except Exception as e:
                   print "Retrying " + str(e)
                   initialised=False
           ping_file = re_from + "_" + re_to + "_" + host + "_" + to_host
           err_file = remote_exp_folder + "/" + ping_file + "_err.log"
           ping_file = remote_exp_folder + "/" + ping_file + "_data.log"
           cmd = "sudo ./" + bin_name + str(counter) + " " + str(counter) + " " + to_host + " " + str(delay) + " " + ping_file + " 0 2> " + err_file
           log(host,cmd)
           ssh_util.executeNonBlockingRemoteCommand(host,cmd,key).start()
           counter = counter + 1
           time.sleep(1)
          except Exception as e:
            print "Failed to start exp on host " + str(host) + " " + str(e)

def stop(key):
   if (key == None):
     key = defaultkey
   regions = ec2.ec2_regions
   load_keys(key,regions)
   all_ips = get_all_instances(regions,{'tag:Name':'ping'})
    # Remove terminated VMs
   terminated_ips = get_all_instances(regions,{'tag:instance-state-code':'48'})
   ips = [x for x in all_ips if x not in terminated_ips]
   this_host = socket.gethostbyname(socket.gethostname())
   ip_to_region = get_instances_per_region(regions)
   for (name,ip) in ips:
       try:
         if (ip != this_host):
            print "Reached here " + str(ip)
            re = ip_to_region[ip]
            key = keys[re] + ".pem"
            ssh_util.killRemoteProcess(ip,bin_name,user,key)
       except Exception as e:
        print e
        print "Failed to kill process on " + str(ip) + " " + str(e)


def collect(key,folder):
   regions = ec2.ec2_regions
   if (key == None):
     key = defaultkey
   load_keys(key,regions)
   all_ips = get_all_instances(regions,{'tag:Name':'ping'})
    # Remove terminated VMs
   terminated_ips = get_all_instances(regions,{'tag:instance-state-code':'48'})
   ips = [x for x in all_ips if x not in terminated_ips]
   # Populates ip_to_region
   this_host = socket.gethostbyname(socket.gethostname())
   ip_to_region = get_instances_per_region(regions)
   exp_folder = "results/" + folder + "/"
   os.system("mkdir -p " + exp_folder)
   remote_exp_folder = remote_path + "/" + exp_folder
   for (name,host) in ips:
       print name
       print host
       for (to_name, to_host) in ips:
         print to_name
         print to_host
         print "(" + name + "," + host + "," + to_name + "," + to_host + ")"
         if ((host!=to_host) & (host!=this_host) & (to_host!=this_host)):
          try:
           re_from = ip_to_region[host]
           re_to = ip_to_region[to_host]
           key = keys[re_from] + ".pem"
           ping_file = re_from + "_" + re_to + "_" + host + "_" + to_host
           err_file = remote_exp_folder + "/" + ping_file + "_err.log"
           ping_file = remote_exp_folder + "/" + ping_file + "_data.log"
           ssh_util.getFile(exp_folder,[host],ping_file,key)
           ssh_util.getFile(exp_folder,[host],err_file,key)
          except Exception as e:
           print "Failed to collect data from " + str(host) + " " + str(e) + " for file " + ping_file
           exit()

def cleanup():
    regions = ec2.ec2_regions
    print regions
    cancel_instances(regions)

def main():
    if (len(sys.argv) <2):
        print "Error: incorrect number of arguments. Expected at least MODE: START/STOP/COLLECT/STOPCOLLECT/CLEANUP"
        exit()
    mode = sys.argv[1]
    if (len(sys.argv)>2):
        folder  = sys.argv[2]
    key = None
    if (mode == "START"):
        start(key)
        print "Started ... "
    elif (mode == "STOP"):
        stop(key)
    elif (mode == "COLLECT"):
        collect(key,folder)
    elif (mode == "STOPCOLLECT"):
        stop(key)
        collect(key)
    elif (mode == "CLEANUP"):
        cleanup()
    else:
        print "Incorrect Mode Option"
        exit(-1)

if __name__ == "__main__":
    main()


