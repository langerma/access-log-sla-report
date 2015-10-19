# 1. Introduction

This project contains a blue-print for parsing HTTP access logs and generating a SLA (Service Level Agreement) report. It is intended as blue-print project because
 
 * The format of the access log file is highly configurable
 * Generation of the SLA report requires a collapsed URL (removing various ids found in the URL)
 * You might have custom requirements of skipping certain lines
 
Why would you need such a project - actually there should not be any need for such a tool
 
 * The production system is performance-tested so there are by definitions no lengthy response times
 * A six-figure production system monitoring with 24x7 operation team is around which would spot any performance issues
 * No customer has yet complained about slow response times so it has to be fast 

Having said that I sometimes like to double-check all of this wishful thinking 

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
access-log-sla-report> ./access-log-analyzer.sh ./src/test/data/access.log 
Parsing the following number of file(s) : 1
Parsing '/Users/sgoeschl/work/playground/access-log-sla-report/./src/test/data/access.log' containing 11 lines took 49 ms
```

# 4. Building

Execute the following command line

```
access-log-sla-report> ./access-log-analyzer.sh ./src/test/data/access.log 
Parsing the following number of file(s) : 1
Parsing '/Users/sgoeschl/work/playground/access-log-sla-report/./src/test/data/access.log' containing 11 lines took 49 ms
```

# 4. Understanding the HTML Report

![alt text](./src/site/images/access-log-sla-report.png "HTML Report")

Looking at the HTML report reveals the following information

* There were 11 HTTP requests captured 
* Some HTTP requests are red indicating that at least on error was detected
* The "Page Details Table" shows the response time sorted in various buckets
   * ''restapi/api/protected/transactions # GET'' has 3 invocations whereas 2 invocations are in the bucket "80-160 ms" and the average response time of these requests is 97,5 milliseconds



 


