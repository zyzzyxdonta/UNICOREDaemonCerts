#!/bin/sh

echo "Stopping servers..."

#
# cd to base directory
#
INST=`dirname $0`
cd $INST

if [ -d unicorex/bin ]
then
  echo "Stopping UNICORE/X execution server process "
  cd unicorex
  bin/stop.sh
  cd ..
fi

if [ -d registry/bin ]
then
  echo "Stopping UNICORE/X registry server process "
  cd registry
  bin/stop.sh
  cd ..
fi

if [ -d gateway/bin ]
then
  echo "Stopping Gateway process "
  cd gateway
  bin/stop.sh
  cd ..
fi

if [ -d servorch/bin ]
then
  echo "Stopping Service Orchestrator server process "
  cd servorch
  bin/stop.sh
  cd ..
fi

if [ -d workflow/bin ]
then
  echo "Stopping Workflow server process "
  cd workflow
  bin/stop.sh
  cd ..
fi

if [ -d xuudb/bin ]
then
  echo "Stopping XUUDB server process "
  cd xuudb
  bin/stop.sh
  cd ..
fi

if [ -d unity/bin ]
then
  echo "Stopping Unity server process "
  cd unity
  bin/unity-idm-server-stop
  cd ..
fi

