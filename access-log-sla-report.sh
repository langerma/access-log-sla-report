#!/bin/sh
#
# Helper script to parse an access.log and create a HTML SLA report
#
# The script expects a list of access.logs and creates a summary report based on JAMon

#!/bin/sh

if [ "$APP_HOME" = "" ] ; then
  COMMAND=$0
  APP_HOME=`dirname ${COMMAND}`
fi

# detect environment and set the class path separator
if [[ "$(uname -s)" == CYGWIN* ]]; then
	CP_SEPARATOR=";"
else
	CP_SEPARATOR=":"
fi

# pick up libraries in ./lib
for i in ${APP_HOME}/lib/* ; do
  if [ "$LOCALCLASSPATH" != "" ]; then
    LOCALCLASSPATH=${LOCALCLASSPATH}${CP_SEPARATOR}$i
  else
    LOCALCLASSPATH=$i
  fi
done

${JAVA_HOME}/bin/jrunscript -cp $LOCALCLASSPATH $APP_HOME/src/main/js/access-log-sla-report.js "$@"
