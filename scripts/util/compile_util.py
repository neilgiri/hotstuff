# Natacha Crooks - 2014
# Contains utility functions related to compiling
# Java jars

import sys
import os
import subprocess

##
# Generates Jar File
# Takes the source folder
# a list of .jar dependencies
# the main class
# the name of the output jar (which will be generated in the
# directory in which this script is called
##


def generateJar(src, dependencies, mainclass, jar):
    cwd = os.getcwd()
    main = mainclass
    jarname = jar

    os.chdir(src)
    manif = ""
    i = 0
    deps = ""
    for x in dependencies:
        i = i + 1
        deps += x
        manif += x + " "
        if (x != len(dependencies)):
            deps += ":"
    files = "find " + src + " -name \"*.java\" > allSource.log"
    os.system(files)
    compiles = "javac -classpath " + deps + " @allSource.log"
    os.system(compiles)
    manifest = open('manifest.txt', 'w')
    manifest.write('Main-Class: ' + main + '\n')
    manifest.write('Class-Path: ' + manif + '\n\n')
    manifest.close()
    classes = "find . -name \"*.class\" > allClass.log"
    os.system(classes)
    jar = "jar -cvfm " + jarname + " " + "manifest.txt " + "@allClass.log"
    os.system(jar)
    print(jar)
    move = "mv " + jarname + " " + cwd
    os.system(move)
    os.chdir(cwd)

# Compiles program from make file, in specified folder
# and with specified target
def compileFromMake(folder=".", targets=["all"]):
    cwd = os.getcwd()
    clean = "make clean"
    make = "make "
    os.chdir(folder)
    try:
        subprocess.check_call(clean, shell=True)
        for target in targets:
            subprocess.check_call(make + " " + target, shell=True)
    except Exception as e:
        print("Error: " + str(e))
    os.chdir(cwd)
