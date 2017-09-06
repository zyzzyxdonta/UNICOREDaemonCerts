#!/bin/sh

echo "Stopping servers..."

#
# cd to base directory
#
INST=`dirname $0`
cd $INST

if [ -e unicorex ] 
then
  echo "Stopping UNICORE/X execution server process "
  cd unicorex
  bin/stop.sh
  cd ..
fi

if [ -e registry ] 
then
  echo "Stopping UNICORE/X registry server process "
  cd registry
  bin/stop.sh
  cd ..
fi

if [ -e gateway ] 
then
  echo "Stopping Gateway process "
  cd gateway
  bin/stop.sh
  cd ..
fi

if [ -e servorch ] 
then
  echo "Stopping Service Orchestrator server process "
  cd servorch
  bin/stop.sh
  cd ..
fi

if [ -e workflow ] 
then
  echo "Stopping Workflow server process "
  cd workflow
  bin/stop.sh
  cd ..
fi

if [ -e xuudb ] 
then
  echo "Stopping XUUDB server process "
  cd xuudb
  bin/stop.sh
  cd ..
fi

if [ -e unity ] 
then
  echo "Stopping Unity server process "
  cd unity
  bin/unity-idm-server-stop
  cd ..
fi

