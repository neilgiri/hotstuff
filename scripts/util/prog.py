### Natacha Crooks - 2014
### Contails utility function related to SSH
############################################


import subprocess

## Executes a command, call is blocking
## Throws a CalledProcessError if
## doesn't

def executeCommand(command):
  print("Calling " + command)
  subprocess.check_call(command, shell=True)

## Call is asynchronous, output
## is piped
## Args are supplied as a list of args
def startProcess(args):
  return subprocess.Popen(args, stdout=PIPE, stderr=PIPE)

## Kills Process that matches string (using grep)
## Throws CalledProcessError for exception
def killProcess(host, process):
    cmd = "ssh " + host + "`kill $(ps -ef | grep \"" + process +"\" | awk \'{print $2}\')"
    executeCommand(cmd)

## Creates Directory on Remote Directory
def mkdirRemote(host, directory):
    cmd = "ssh " + host + "`mkdir " + directory + " '"
    executeCommand(cmd)

## Updates repository
def gitPull(directory):
    cwd = os.cwd()
    os.chdir(directory)
    cmd = "git pull --rebase"
    executeCommand(cmd)

## Pulls Directory
def getDirectory(local_dir, hosts, remote_dir):
    for h in hosts:
        cmd = "scp -R " + h + ":" + remote_dir +  " " + local_dir
        executeCommand(cmd)


## Sends file to remote directory
def sendFile(local_file, hosts, remote_dir):
   for h in hosts:
        cmd = "scp  " + local_file + " " +  h + ":" + remote_dir
        executeCommand(cmd)

## Executes, in sequence, specified command
## on each of the hosts in the list
## If returns an error throws an exception
def executeSequenceBlockingRemoteCommand(hosts, command):
   for h in hosts:
       cmd = "ssh " + h + "'" + command + "'"
       check_call(cmd)

## Executes, in parallel, specified command
## on each of the hosts in the list
## If returns an error throws an exception

def executeParallelBlockingRemoteCommand(hosts, command):
    thread_list = list()
    for h in hosts:
        cmd = "ssh " + h + "'" + command + "'"
        t =Thread(target=executeCommand,args=(cmd,))
        thread_list.append(t)
        for t in thread_list:
            t.start()
    for t in thread_list:
      t.join()
