#!/bin/sh

./access-log-sla-report.bat -p combined-apache -o ./target/report/combined-access.html ./src/test/data/apache/combined-access.log 
./access-log-sla-report.bat -p httpd-sit-geapi -o ./target/report/http-sit-geapi.html ./src/test/data/sit/httpd-access.log 
./access-log-sla-report.bat -p catalina-sit-geapi -o ./target/report/catalina-sit-geapi.html ./src/test/data/sit/catalina-access.log
./access-log-sla-report.bat -p haproxy-sit-geapi -o ./target/report/haproxy-sit-geapi.html ./src/test/data/sit/haproxy.log 