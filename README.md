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
 
The actual program consists of a Javascript file executed by Rhino/Nashorn using some Java libraries. 

Why not creating an all-in-one Java application
 
 * When you have gigabytes of access logs it is easier to move the script to the production server than the access logs to your computer
 * When you work on a remote server you only have SSH and some console-based editors
 * When you modify the script on the remote server you don't need a development infrastructure (IDE, Maven, ...)
   
   
# 3. Usage

Execute the following command line

```
access-log-sla-report> ./access-log-sla-report.sh ./src/test/data/access.log 
Parsing the following number of file(s) : 1
Parsing '/Users/sgoeschl/work/playground/access-log-sla-report/./src/test/data/access.log' containing 11 lines took 49 ms
```

The application also supports compressed access logs, e.g.

```
access-log-sla-report> ./access-log-sla-report.sh ./src/test/data/access.log.bz2 
[INFO] Parsing the following number of file(s) : 1
[INFO] Parsing '/Volumes/data/work/github/sgoeschl/access-log-sla-report/./src/test/data/access.log.bz2' containing 11 lines took 167 ms
```

# 4. Building

Execute the following command line

```
access-log-sla-report> mvn clean install
```

It generates a 

 * access-log-sla-report-1.0.0-SNAPSHOT-dist.zip
 * access-log-sla-report-1.0.0-SNAPSHOT-dist.tar.gz
 
which can be unpacked at the remote server 

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
      
   
   



 


