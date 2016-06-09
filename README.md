# 1. Introduction

This project contains a blue-print for parsing HTTP access logs and generating a SLA (Service Level Agreement) report. It is intended as blue-print project because
 
 * The format of access log files is highly configurable
 * Generation of the SLA report requires a collapsed URL (removing various ids found in the URL)
 * You might have custom requirements of skipping certain lines
 
Why would you need such a project - actually there should not be any need for such a tool
 
 * The production system is performance-tested so there are by definitions no excessive response times
 * A six-figure performance monitoring tool with 24x7 operation team is around which would spot any performance issues before they even happen
 * No customer has yet complained about slow response times so there can't be any performance issues

Having said that I sometimes like to question those assumptions

 * Analyzing access logs is low-tech since those files are always generated 
 * With a little bit of luck you can convince someone to copy a production access log
 * Adopting the RegExp is not trivial but can be done within an hour 

   
# 2. Design Consideration

## 2.1 Javascript versus Java

The actual program consists of a Javascript file executed by Rhino/Nashorn using some Java libraries. 

Why not creating an all-in-one Java application
 
 * When you have gigabytes of access logs it is easier to move the script to the production server than the access logs to your computer
 * When you work on a remote server you only have SSH and some console-based editors
 * When you modify the script on the remote server you don't need a development infrastructure (IDE, Maven, ...)

## 2.2 Supporting Multiple Access Log Formats

Configuration of access logs are wildly different - there is no configuration to rule them all

Therefor the script supports multiple access logs formats 

| Name  							| Description																			   	|
|-----------------------------------|-------------------------------------------------------------------------------------------|
| catalina-sit					    | Tomcat access log using sIT conventions													|
| catalina-sit-geapi   		        | Tomcat access log using sIT conventions with George API exclude filters					|
| catalina-sit-geimp        	    | Tomcat access log using sIT conventions for George Importer								| 
| httpd-sit					        | Apache HTTPD log using sIT conventions													|
| httpd-sit-geapi       		    | Apache HTTPD log using sIT conventions with George-specififc exclude filters				|
| custom                		    | Custom format to play around interactively    											|
   
   
# 3. Usage

```
george-access-log-sla-report> ./access-log-sla-report.sh -h
usage: access-log-sla-report
 -h,--help           print this message
 -o,--output <arg>   output file for report
 -p,--parser <arg>   parser for access log
```

Execute the following command line parses some Apache HTTPD access logs

```
george-access-log-sla-report> ./access-log-sla-report.sh ./src/test/data/httpd-access.log 
[INFO] Parsing the following number of file(s) : 1
[INFO] Parsing '/Volumes/data/work/beeone/george/george-tools/george-access-log-sla-report/./src/test/data/httpd-access.log' containing 13 lines took 187 ms
[INFO] The following number of lines were ignored : 1
```

The application also supports compressed access logs, e.g.

```
access-log-sla-report> ./access-log-sla-report.sh ./src/test/data/httpd-access.log.bz2 
[INFO] Parsing the following number of file(s) : 1
[INFO] Parsing '/Volumes/data/work/github/sgoeschl/access-log-sla-report/./src/test/data/httpd-access.log.bz2' containing 11 lines took 167 ms
```

A more complex invocation

```
george-access-log-sla-report> ./access-log-sla-report.sh -p catalina-sit-geapi -o report.html ./src/test/data/catalina-access-log.txt 
[INFO] Parsing the following number of file(s) : 1
[INFO] Parsing '/Volumes/data/work/beeone/george/george-tools/george-access-log-sla-report/./src/test/data/catalina-access-log.txt' containing 24 lines took 154 ms
[INFO] The following number of lines were ignored : 1
```

A few sample invocations

> ./access-log-sla-report.sh -p catalina-sit-geapi -o ./target/catalina-access-log.txt.html ./src/test/data/catalina-access-log.txt
> ./access-log-sla-report.sh -p httpd-sit-geapi -o ./target/httpd-access-log.html ./src/test/data/httpd-access.log
> ./access-log-sla-report.sh -p httpd-sit-geapi -o ./target/httpd-access-log.bz2.html ./src/test/data/httpd-access.log.bz2
> ./access-log-sla-report.sh -p httpd-sit-geapi -o ./target/httpd-access-log.gz.html ./src/test/data/httpd-access.log.gz

# 4. Building

Execute the following command line

```
access-log-sla-report> mvn clean install
```

It generates a 

 * access-log-sla-report-1.0.0-SNAPSHOT-dist.zip
 * access-log-sla-report-1.0.0-SNAPSHOT-dist.tar.gz
 
which can be unpacked at the remote server 

The integration test also creates a "./target/access-log-sla-report.html"

# 5. Understanding the HTML Report

![Figure-1 Access Log SLA Report](./src/site/images/access-log-sla-report.png "Access Log SLA Report")

Looking at the HTML report reveals the following information

* There were 11 HTTP requests captured 
* Some HTTP requests are shown in red color indicating that at least one error was detected
* The "Page Details Table" shows the response time sorted in various buckets
   * ''restapi/api/protected/transactions # GET'' has 3 invocations whereas 2 invocations are in the bucket "80-160 ms" and the average response time of these requests is 97,5 milliseconds
   
   
# 6. Under The Hood
            
 * The Javascript is executed by Rhino (JDK 1.7) or Nashorn (JDK 1.8)
 * The script reads the access logs line by line and each line is split into individual parts using regular expressions
 * The individual parts are further processed to create "LogEntry" instances
 * A "LogEntry" instance contains a collapsed URL, a HTTP result code, a timestamp and a duration
 * This information is feed to [jmeter-sla-report](https://github.com/sgoeschl/jmeter-sla-report) which delegates the work to [JAMon](http://jamonapi.sourceforge.net)
 * After feeding all "LogEntry" instances to JAMon a HTML report is created
      

# 7. Software Requirements

## 7.1 Build

The following tools are required to build the project

* JDK 1.8
* Apache Maven 3.2.3 or better

## 7.2 Execution

The following tools are required to run the project

* JDK 1.8

# 8. sIT Access Log Format

## 8.1 Apache HTTPD Access Log

```
Consolidated log format (Apache access log):

-- common (combined default)
%h              Remote hostname/IP [string]
%v              Canonical server name (vhost) [string]
%u              Remote user (if authenticated) [string]
%t              Request reception time [18/Sep/2011:19:18:28 -0400]
%r              First line of request [string]
%>s             Final request status [number]
%b              Response bytes excluding headers [string]
%{Referer}i     Incoming Referer header [string]
%{User-Agent}i  Incoming UA header [string]

-- extension (process)
pid             Process and thread ID of the request serving child [number/number]
uid             Unique request ID [string{24}]

-- extension (connection)
con             Local connection info [IP/port]
cbs             Connection bytes received and sent, including headers [bytes/bytes]
ckr             Connection keep-alive requests [number]
cst             Connection status when response is completed [char: "X"(aborted before completed),
                                                                    "+"(keep alive after response),
                                                                    "-"(close after response)]
-- extension (response)
rtm             Response time [s/us]
rhd             Response handler [string: e.g. "proxy-server"/"weblogic-handler"(upstream server),
                                               "-"(local content)]
rcs             Response cache status [string: "cache-hit"(served from cache),
                                               "cache-revalidate"(revalidated and served from cache),
                                               "cache-miss"(served from upstream),
                                               "cache-invalidate"(invalidated by request method)]
-- extension (compression)
cmp             Compression ratio (string)

-- extension (header)
hct             Content-Type sent to the client [string]
hco             Cookies sent from/to the client [string/string]
hac             Accept* headers sent from the client [string]
hxa             X-* headers sent from/to the client [string/string]

-- extension (balancer)
brn             Balancer routing cookie or request parameter name [string]
bsr             Balancer session route received from client [string]
bwr             Balancer session route for the chosen worker [string]
brc             Whether the balancer route has changed or was not provided [char]

-- extension (SSL)
ssl             Whether HTTPS is being used [string]
sve             SSL protocol version in use [string: SSLv3, TLSv1, TLSv1.1, TLSv1.2]
sci             SSL cipher specification name [string]
sck             SSL cipher key size actually used and possible [string/string]
sid             SSL session ID [string]
sre             Whether the SSL session is initial or resumed [string: "Initial", "Resumed"]
sni             SNI TLS extension content [string]
srp             SRP user name [string]
scc             SSL client certificate subject/issuer CN [string/string]
scv             SSL client verification status [string: "NONE", "SUCCESS", "GENEROUS", "FAILED:reason"]
sar             Whether access was denied due to SSL restrictions [char]
```
   
## 8.2 Tomcat Access log

```
-- common (combined default)
%h              Remote host name (or IP address if enableLookups for the connector is false) [string]
%v              Local server name [string]
%u              Remote user that was authenticated (if any), else '-' [string]
%t              Request reception time in Common Log Format
%r              First line of the request (method and request URI) [string]
%s              HTTP status code of the response [number]
%b              Bytes sent, excluding HTTP headers, or '-' if zero [string]
%{Referer}i     Incoming Referer header [string]
%{User-Agent}i  Incoming UA header [string]

-- extension (process)
tid             Current request thread name [string]
uid             Unique request ID from 'X-REQUEST-ID' as UUID [string{36}]

-- extension (connection)
con             Local connection info [IP/port]

-- extension (response)
rtm             Response time [s/ms]

-- extension (header)
hct             Content-Type sent to the client [string]
hac             The Accept headers sent from the client [string]

-- extension (servlet engine)
sid             Session identifier [string]

-- extension (application)
-- These custom values can be extracted from cookie or header and need to go to a context.xml
x-user-id       Custom user id calling server [string]
x-client-id     Custom client id calling server, e.g. "george-go" [string]
x-client-info   Custom other data [string]    
```

 


