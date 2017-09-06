#!/usr/bin/env python
from __future__ import print_function

#
# UNICORE server installation script
#
# Reads configuration parameters from a file configure.properties, and
# adapts several config files
#
# usage: configure.py [hostname]
#

import os
import sys
import socket
import shutil
try:
    import ConfigParser
except ImportError as e:
    import configparser as ConfigParser


#
# substitute variable values
#
def substituteVars(input, parameters):
    result=input
    for param in parameters:
        key= "${"+param+"}"
        val= config.get("parameters",param)
        if(val=="hostname"):
            val=hostname
        if(val=="currentdir"):
            val=installdir
        result=result.replace(key,val)
        result=result.replace("${FILE_SEPARATOR}", "/")
    return result

    
installdir=os.getcwd()
    
try:
    hostname=sys.argv[1]
except:
    hostname="localhost"

#read configuration file
config = ConfigParser.ConfigParser()
#make the parser case-sensitive
config.optionxform=str
config.read(['configure.properties'])

if(config.get("parameters","INSTALL_PATH")=="currentdir"):
    installdir=os.getcwd()
else:
    installdir=config.get("parameters","INSTALL_PATH")


print ("Configuring the installation in directory %s, on machine %s" %(installdir,hostname))

#current directory
basedir=os.getcwd()


#
#list of config files to process (paths relative to this script)
#

workflowServerFiles=[
       "workflow/conf/startup.properties",
       "workflow/conf/wsrflite.xml",
       "workflow/conf/uas.config",
]

servorchFiles=[
       "servorch/conf/startup.properties",
       "servorch/conf/wsrflite.xml",
       "servorch/conf/uas.config",
]

#make full filelist depending on which components we're configuring 
files = ["start-workflow.sh","stop-workflow.sh"]

if(config.get("parameters","workflow")=="true"):
   files = files + workflowServerFiles
if(config.get("parameters","servorch")=="true"):
   files = files + servorchFiles

#
#loop over list of config files and do the substitution
#

parameters=config.options("parameters")

for f in files:
    filename=basedir+"/"+f
    print ("... processing %s" % filename)

    #if not exists, make a copy of the original config file
    if not os.path.isfile(filename+"_origin"):
        print ("    making backup %s" % filename+"_origin")
        shutil.copy(filename,filename+"_origin")	
	
    file = open(filename+"_origin")
    lines=file.readlines()
    file.close()
    
    file = open(filename, 'w')

    for line in lines:
        line=substituteVars(line,parameters)
        #do it again to allow values containing variables
        line=substituteVars(line,parameters)
        file.write(line)
    file.close()




print ("Done configuring!")

