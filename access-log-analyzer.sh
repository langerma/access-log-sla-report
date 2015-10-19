#!/bin/sh
#
# Helper script to parse an access.log and create a HTML SLA report
#
# The script expects a list of access.logs and creates a summary report based on JAMon

#!/bin/sh

if [ "$SERVER_HOME" = "" ] ; then
  COMMAND=$0
  SERVER_HOME=`dirname ${COMMAND}`/.
fi

# pick up libraries in ./lib
for i in ${SERVER_HOME}/lib/* ; do
  if [ "$LOCALCLASSPATH" != "" ]; then
    LOCALCLASSPATH=${LOCALCLASSPATH}:$i
  else
    LOCALCLASSPATH=$i
  fi
done

jrunscript -cp $LOCALCLASSPATH ./src/main/js/access-log-sla-report.js "$@"