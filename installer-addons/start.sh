#!/bin/sh

echo "******************************"
echo "*"
echo "* UNICORE startup..."
echo "*"
echo "******************************"
echo

#
# components to be started
#
start_tsi="true"
start_unity="true"
start_xuudb="false"
start_gateway="true"
start_unicorex="true"
start_registry="true"
start_workflow="true"
start_servorch="true"

#
# cd to base directory
#
INST=`dirname $0`
cd $INST

if [ -e unity ] 
then if [ "${start_unity}" = "true" ] 
then 
  cd unity
  echo "Starting Unity..."
  ./bin/unity-idm-server-start
  echo "Sleeping for 15 seconds."
  sleep 15
  cd ..
fi
fi

if [ -e xuudb ] 
then if [ "${start_xuudb}" = "true" ] 
then 
  cd xuudb
  echo "Starting XUUDB..."
  ./bin/start.sh
  echo "Sleeping for 3 seconds."
  sleep 3
  cd ..
fi
fi

#this should run only once (dealt with in the adduser.sh script)
if [ -e adduser.sh ]; then 
  ./adduser.sh 
fi

if [ -e gateway ] 
then if [ "${start_gateway}" = "true" ]
then
  cd gateway
  echo "Starting Gateway..."
  ./bin/start.sh
  echo "Sleeping for 3 seconds."
  sleep 3
  cd ..
fi
fi

if [ -e registry ] 
then if [ "${start_registry}" = "true" ]
then
  cd registry
  echo "Starting shared registry UNICORE/X server..."
  bin/start.sh 
  echo "Sleeping for 3 seconds."
  sleep 3
  cd ..
fi
fi

if [ -e unicorex ] 
then if [ "${start_unicorex}" = "true" ]
then
  cd unicorex
  echo "Starting UNICORE/X server..."
  bin/start.sh 
  cd ..
fi
fi

if [ -e workflow ] 
then if [ "${start_workflow}" = "true" ]
then
  cd workflow
  echo "Starting Workflow server..."
  bin/start.sh 
  cd ..
fi
fi

if [ -e servorch ] 
then if [ "${start_servorch}" = "true" ]
then
  cd servorch
  echo "Starting Service Orchestrator server..."
  bin/start.sh 
  cd ..
fi
fi
