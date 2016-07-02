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
./access-log-sla-report.sh -p httpd-sit-geapi ./src/test/data/httpd-access.log 
[INFO] Parsing the following number of file(s) : 1
[INFO] Parsing '/Volumes/data/work/beeone/george/george-tools/george-access-log-sla-report/./src/test/data/httpd-access.log' containing 13 lines took 187 ms
[INFO] The following number of lines were ignored : 1
```

Execute the following command line parses some Apache Tomcat access logs

```
./access-log-sla-report.sh -p catalina-sit-geapi ./src/test/data/catalina-access-log.txt
[INFO] Parsing the following number of file(s) : 1
[INFO] Parsing '/Users/sgoeschl/work/github/sgoeschl/access-log-sla-report/./src/test/data/catalina-access-log.txt' containing 24 lines took 160 ms
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
* The section "Error Messages" keeps track of the HTTP requests causing errors 
   
   
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

