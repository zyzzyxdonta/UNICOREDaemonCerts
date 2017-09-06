#!/usr/bin/env python
from __future__ import print_function

#
# UNICORE server installation script
#
# copies files into target directory
# 
# usage:
#     1) edit configure.properties
#     2) execute ./configure.py [hostname]
#     3) execute ./install.py
#

try:
    import ConfigParser
except ImportError as e:
    import configparser as ConfigParser

from shutil import copy,copytree
import glob
from sys import exc_info
import fnmatch
import os

#helper function, taken from python 2.6 shutil.py
def ignore_patterns(patterns):
    def _ignore_patterns(path, names):
        ignored_names = []
        for pattern in patterns:
            ignored_names.extend(fnmatch.filter(names, pattern))
        return set(ignored_names)
    return _ignore_patterns


#read configuration file
config = ConfigParser.ConfigParser()
#make the parser case-sensitive
config.optionxform=str
config.read(['configure.properties'])

pwd=os.getcwd()

# do we need to copy any files
copyfiles=True

if(config.get("parameters","INSTALL_PATH")=="currentdir"):
    installdir=os.getcwd()
    copyfiles=False
else:
    installdir=config.get("parameters","INSTALL_PATH")

if not copyfiles:
    print("Nothing to do (installation directory is the current directory).")
    exit()

print("Installing files to directory %s" %(installdir))



ignoreFiles=('*_origin', 'wrapper.conf*','docs*')

components=["workflow", "servorch"]


for component in components:
    if(config.get("parameters",component)=="true"):
        copytree(component,installdir+"/"+component,ignore=ignore_patterns(ignoreFiles))

# documentation
docdir=installdir+"/docs"
if os.path.isdir(docdir):
    copyfiles = glob.glob("docs/*")
    for sfile in copyfiles:
        copy(sfile,docdir) 
else:
    copytree("docs",docdir,ignore=ignore_patterns(ignoreFiles))

        
# copy files in root directory
files = ["start-workflow.sh", "stop-workflow.sh"]

if config.get("parameters","installdemocerts")=="true":
    # copy certs directory
    copytree("certs",installdir+"/certs",ignore=ignore_patterns(ignoreFiles))

try:
    for f in files:
        filename=installdir+"/"+f
        copy(pwd+"/"+f,filename)	
except:
    print("Error copying %s to %s" % (pwd+"/"+f, filename))
    print(exc_info())

print("Done.")


