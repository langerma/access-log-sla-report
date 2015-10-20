/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * This JavaScript parses an Apache access log and uses JAMon to generate a response time report.
 *
 * @author <a href="mailto:siegfried.goeschl@gmail.com">Siegfried Goeschl</a>
 */

// Some ad-hoc filtering you can turn on
var LOGENTRY_FILTER_DURATION_MS = 0;
var LOGENTRY_FILTER_INCLUDE_COLLAPSED_URL = "";
var LOGENTRY_FILTER_EXCLUDE_COLLAPSED_URL = "";

var LOG_ENTRY_DATE_PARSER = new java.text.SimpleDateFormat("dd/MMM/yyyy:HH:mm:ss Z", java.util.Locale.ENGLISH);

// Regular expression applied to each line in the access log - change the regexp according to your HTTP server configuration
var LOG_ENTRY_REGEXP_MATCHES_REQUIRED = 16;
var LOG_ENTRY_REGEXP_STRING = "^(\\S+) (\\S+) (\\S+) \\[([\\w:/]+\\s[+\\-]\\d{4})\\] \"(.+?)\" (\\d{3}) (\\S+) \"([^\"]+)\" \"([^\"]+)\" pid:(\\S+) uid:(\\S+) con:(\\S+) cbs:(\\S+) ckr:(\\S+) cst:(\\S+) rtm:\\d+/(\\S+) .*";
var LOG_ENTRY_REGEXP = java.util.regex.Pattern.compile(LOG_ENTRY_REGEXP_STRING);

// Regular expression to detect a resource id within an URL to create a collapsed URL
var RESOURCE_ID_PARAMETER_REGEXP = java.util.regex.Pattern.compile("^([a-z]{1,15}+\\d?)$");

// The underlying JAMon report model
var JAMON_REPORT_MODEL = new org.apache.jmeter.extra.report.sla.JMeterReportModel();

function main(arguments) {

    if (arguments.length == 0) {
        println("Usage : jrunscript -cp lib/jamon-2.81.jar:lib/jmeter-sla-report-1.0.0.jar ./src/main/js/access-log-sla-report.js file[s]");
        return 1;
    }

    parseLogfiles(arguments);
    writeHtmlReport("access-log-report.html", "Apache Access Log Report", "Server");
    return 0;
}

function parseLogfiles(fileNames) {

    println("[INFO] Parsing the following number of file(s) : " + fileNames.length);

    for (var i = 0; i < fileNames.length; i++) {

        var fileName = fileNames[i];
        var logFile = new java.io.File(fileName);
        var reader = null;

        try
        {
            reader = createReader(logFile);
            parseLogfile(logFile, reader);
        }
        finally {
            if(reader != null) {
                reader.close();
            }
        }
    }
}

function isCompressedFile(logFile) {
    var name = logFile.getName();
    return name.endsWith(".zip") || name.endsWith(".gz") || name.endsWith("gzip") || name.endsWith(".bzip2") || name.endsWith("bz2");
}

function createReader(logFile) {
    if(isCompressedFile(logFile)) {
        var fileInputStream = new java.io.FileInputStream(logFile);
        var bufferedInputStream = new java.io.BufferedInputStream(fileInputStream);
        var compressedInputStream = new org.apache.commons.compress.compressors.CompressorStreamFactory().createCompressorInputStream(bufferedInputStream);
        var inputStreamReader = new java.io.InputStreamReader(compressedInputStream);
        var bufferedReader = new java.io.BufferedReader(inputStreamReader);
        return bufferedReader;
    }
    else {
        return new java.io.BufferedReader(new java.io.FileReader(logFile));
    }
}

function parseLogfile(logFile, reader) {

    try {

        var startTime = java.lang.System.currentTimeMillis();
        var lineNumber = 0;
        var errorCount = 0;
        var ignoredCount = 0;
        var logEntry = null;

        while ((line = reader.readLine()) != null) {

            lineNumber++;
            logEntry = parseLine(logFile, lineNumber, line);

            if (logEntry != null) {

                if (accept(logEntry)) {
                    process(logEntry);
                }
                else {
                    ignoredCount = ignoredCount + 1;
                }
            }
            else {
                errorCount = errorCount + 1;
            }
        }

        var endTime = java.lang.System.currentTimeMillis();

        println("[INFO] Parsing '" + logFile.getAbsolutePath() + "' containing " + lineNumber + " lines took " + (endTime - startTime) + " ms");

        if (ignoredCount > 0) {
            println("[INFO] The following number of lines were ignored : " + ignoredCount);
        }

        if (errorCount > 0) {
            println("[INFO] Found the following number of lines we could not parse : " + errorCount);
        }
    }
    catch (e) {
        println("[ERROR] Parsing '" + logFile.getAbsolutePath() + "' failed : " + e);
    }
}

/**
 * Filter the log entries we are interested in, e.g. based on HTTP status code or response time.
 *
 * @param logEntry current log entry
 * @return boolean if the current log entry shall be skipped
 */
function accept(logEntry) {

    if (logEntry == null) {
        return false;
    }

    if (logEntry.timeTaken < LOGENTRY_FILTER_DURATION_MS) {
        return false;
    }

    if (LOGENTRY_FILTER_INCLUDE_COLLAPSED_URL != null && LOGENTRY_FILTER_INCLUDE_COLLAPSED_URL.length > 0 && !logEntry.collapsedUrl.contains(LOGENTRY_FILTER_INCLUDE_COLLAPSED_URL)) {
        return false;
    }

    if (LOGENTRY_FILTER_EXCLUDE_COLLAPSED_URL != null && LOGENTRY_FILTER_EXCLUDE_COLLAPSED_URL.length > 0 && logEntry.collapsedUrl.contains(LOGENTRY_FILTER_EXCLUDE_COLLAPSED_URL)) {
        return false;
    }

    return true;
}

/**
 * Parse a single line of the HTTPD access log and add it to the report model.
 *
 * @param logFile the currently processed log file
 * @para  lineCount the currently processing line number
 * @param line current line of the logfile
 * @return null if the line was not parsable or the processes line
 */
function parseLine(logFile, lineNumber, line) {

    try {

        // cleanup stuff which would break regexp later on

        preProccessedLine = preProcessLine(line);

        // split the line of the access log into tokens using a regexp

        var matcher = LOG_ENTRY_REGEXP.matcher(preProccessedLine);

        // check that the complete regexp matches

        if (!matcher.matches() || LOG_ENTRY_REGEXP_MATCHES_REQUIRED != matcher.groupCount()) {
            println("[ERROR] Bad log entry (or problem with RE?) : " + preProccessedLine);
            return null;
        }

        var ipAddress = matcher.group(1);
        var dateString = matcher.group(4);
        var requestLine = matcher.group(5);
        var responseCode = parseInt(matcher.group(6));
        var bytesSent = parseInt(matcher.group(7));
        var referer = matcher.group(8);
        var userAgent = matcher.group(9);
        var durationMicro = matcher.group(16);

        // split something like "GET /iad/kaufen-und-verkaufen/foto-tv-video-audio/lautsprecher-boxen-verstaerker?page=27 HTTP/1.1" 
        // into its individual components

        var requestLineParts = requestLine.split(" ");
        var requestHttpMethod = requestLineParts[0];
        var requestURLLine = requestLineParts[1];
        var questionMarkIndex = requestURLLine.indexOf('?');
        var requestUrl = ( questionMarkIndex > 0 ? requestURLLine.substring(0, questionMarkIndex) : requestURLLine);
        var requestParams = ( questionMarkIndex > 0 ? requestURLLine.substring(questionMarkIndex+1) : "");
        var requestHttpProtocol = requestLineParts[2];

        // convert raw parameters

        var timestamp = LOG_ENTRY_DATE_PARSER.parse(dateString);
        var timeTaken = Math.round(parseInt(durationMicro) / 1000);
        var collapsedUrl = createCollapsedUrl(requestUrl);


        // create the LogEntry instance

        return new LogEntry(
            logFile,
            lineNumber,
            line,
            ipAddress,
            timestamp,
            requestUrl,
            collapsedUrl,
            requestHttpMethod,
            responseCode,
            bytesSent,
            referer,
            userAgent,
            requestParams,
            timeTaken);
    }
    catch (e) {
        println("[WARN] Failed to parse the following line : " + line);
        println(e);
        return null;
    }
}

/**
 * Cleanup stuff which would break the regexp later on.
 */
function preProcessLine(line) {

    var result = line;

    // remove a single escaped double-quotes instead of tinkering with the regexp

    result = result.replace("\\\"", "");

    return result;
}

/**
 * Process a single log entry.
 */
function process(logEntry) {
    // println(logEntry.toCsv());
    addToReportModel(logEntry);
}

/**
 * Extract the base url used for the JAMon monitor. We need to strip various
 * ids used for addressing individual resources to avoid millions of "unique"
 * URLs.
 *
 * @param requestURL request URL
 */
function createCollapsedUrl(requestURL) {

    // restapi/api/my/configuration ==> restapi/api/my/configuration
    // restapi/api/my/accounts/XXXXXXXXX/stats ==> restapi/api/my/accounts/*/stats
    // restapi/api/my/accounts/YYYYYYYYY/images/image ==> restapi/api/my/accounts/*/images/image

    var parts = requestURL.split("/");
    var result = new java.lang.StringBuffer();

    for (var i=1; i<parts.length; i++) {
        var part = parts[i];
        if (RESOURCE_ID_PARAMETER_REGEXP.matcher(part).matches()) {
            result.append(part).append("/");
        }
        else {
            result.append("*").append("/")
        }
    }

    result = result.substring(0, result.length() - 1);

    return result;
}

function createMonitorName(logEntry) {
    return logEntry.collapsedUrl + " # " + logEntry.requestMethod;
}

function addToReportModel(logEntry) {

    var timestamp = logEntry.timestamp;
    var monitorName = createMonitorName(logEntry);
    var responseCode = logEntry.responseCode;
    var timeTaken = logEntry.timeTaken;

    if (logEntry.isSuccess()) {
        JAMON_REPORT_MODEL.addSuccess(monitorName,
            timestamp,
            timeTaken);
    }
    else {
        JAMON_REPORT_MODEL.addFailure(
            monitorName,
            timestamp,
            timeTaken,
            responseCode,
            logEntry.getHttpResponseCodeName());
    }
}

/**
 * Write the HTML report to the file system.
 *
 * @param fileName the name of the output file
 * @param title the title of the generated HTML report
 * @param subtitle the subtitle of the generated HTML report
 */
function writeHtmlReport(fileName, title, subtitle) {

    var sortOrder =  "asc";
    var sortColumn = org.apache.jmeter.extra.report.sla.JMeterHtmlReportWriter.DISPLAY_HEADER_LABEL_INDEX;

    // set up the HTML report
    var reportWriter = new org.apache.jmeter.extra.report.sla.JMeterHtmlReportWriter(JAMON_REPORT_MODEL, sortColumn, sortOrder);
    reportWriter.setReportTitle(title);
    reportWriter.setReportSubtitle(subtitle);

    // create the directory of the output file if it does not already exists
    var outputFile = new java.io.File(fileName);
    if (outputFile.getParentFile() != null) {
        outputFile.getParentFile().mkdirs();
    }

    // write the HTML report to the file system
    var writer = new java.io.BufferedWriter(new java.io.FileWriter(fileName));
    writer.write(reportWriter.createReport());
    writer.close();
}

function LogEntry(logFile, lineNumber, line, ipAddress, timestamp, requestUrl, collapsedUrl, requestMethod, responseCode, bytesSent, referer, userAgent, requestParams, timeTaken) {

    if (responseCode < 100 || responseCode > 506) {
        throw "Invalid responseCode : " + responseCode;
    }

    if (bytesSent < 0 || bytesSent > 1024*1024*1024) {
        throw "Invalid bytesSent : " + bytesSent;
    }

    if (timeTaken < 0 || timeTaken > 3600*1000) {
        throw "Invalid timeTaken : " + timeTaken;
    }

    if (requestUrl == null || requestUrl.isEmpty()) {
        throw "Empty 'requestUrl' parameter";
    }

    if (collapsedUrl == null || collapsedUrl.isEmpty()) {
        throw "Empty 'collapsedUrl' parameter";
    }

    if (requestMethod == null || requestMethod.isEmpty()) {
        throw "Empty 'requestMethod' parameter";
    }

    /** the corresponding access log */
    this.logFile = logFile;

    /** the corresponding line number */
    this.lineNumber = lineNumber;

    /** the corresponding line from the access log */
    this.line = line;

    /** the source IP address */
    this.ipAddress = ipAddress;

    /** the timestamp as java.util.Date */
    this.timestamp = timestamp;

    /** the request URL without parameters */
    this.requestUrl = requestUrl;

    /** the collapsed URL without any resource ids */
    this.collapsedUrl = collapsedUrl;

    /** the HTTP requestMethod, e.g. "PUT" */
    this.requestMethod = requestMethod;

    /** the HTTP response code */
    this.responseCode = responseCode;

    /** the size of the response message in bytes */
    this.bytesSent = bytesSent;

    /** the referer */
    this.referer = referer;

    /** the user agent string */
    this.userAgent = userAgent;

    /** additional request parameters */
    this.requestParams = requestParams;

    /** the response time in milliseconds */
    this.timeTaken = timeTaken;

    this.toString = function () {
        var buffer = new java.lang.StringBuilder();
        buffer.append("ipAddress=").append(this.ipAddress).append("\n");
        buffer.append("timestamp=").append(this.timestamp).append("\n");
        buffer.append("requestUrl=").append(this.requestUrl).append("\n");
        buffer.append("collapsedUrl=").append(this.collapsedUrl).append("\n");
        buffer.append("requestMethod=").append(this.requestMethod).append("\n");
        buffer.append("responseCode=").append(this.responseCode).append("\n");
        buffer.append("bytesSent=").append(this.bytesSent.toString()).append("\n");
        buffer.append("referer=").append(this.referer).append("\n");
        buffer.append("userAgent=").append(this.userAgent).append("\n");
        buffer.append("requestParams=").append(this.requestParams).append("\n");
        buffer.append("timeTaken=").append(this.timeTaken.toString()).append("\n");
        buffer.append("logFile=").append(this.logFile).append("\n");
        buffer.append("lineNumber=").append(this.lineNumber.toString()).append("\n");
        return buffer.toString();
    };

    this.toCsv = function () {
        var sdf = new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mmZ");
        var buffer = new java.lang.StringBuilder();
        buffer.append(sdf.format(this.timestamp)).append(";");
        buffer.append(this.requestMethod).append(";");
        buffer.append(this.collapsedUrl).append(";");
        buffer.append(this.responseCode.toString()).append(";");
        buffer.append(this.timeTaken.toString()).append(";");
        buffer.append(this.logFile.getAbsolutePath()).append(";");
        buffer.append(this.lineNumber.toString());
        return buffer.toString();
    };

    this.getHttpResponseCodeName = function() {

        if (responseCode == "200") return "Ok";
        if (responseCode == "201") return "Created";
        if (responseCode == "202") return "Accepted";
        if (responseCode == "203") return "Non-Authoritative Information";
        if (responseCode == "204") return "No Content";
        if (responseCode == "205") return "Reset Content";
        if (responseCode == "206") return "Partial Content";
        if (responseCode == "207") return "Multi-Status";
        if (responseCode == "208") return "Already Reported";

        if (responseCode == "100") return "Continue";
        if (responseCode == "101") return "Switching Protocols";
        if (responseCode == "102") return "Processing";

        if (responseCode == "300") return "Multiple Choices";
        if (responseCode == "301") return "Moved Permanently";
        if (responseCode == "302") return "Found";
        if (responseCode == "303") return "See Other";
        if (responseCode == "304") return "Not Modified";
        if (responseCode == "305") return "Use Proxy";
        if (responseCode == "307") return "Temporary Redirect";

        if (responseCode == "400") return "Bad Request";
        if (responseCode == "401") return "Unauthorized";
        if (responseCode == "402") return "Payment Required";
        if (responseCode == "403") return "Forbidden";
        if (responseCode == "404") return "Not Found";
        if (responseCode == "405") return "Method Not Allowed";
        if (responseCode == "406") return "Not Acceptable";
        if (responseCode == "407") return "Proxy Authentication Required";
        if (responseCode == "408") return "Request Timeout";
        if (responseCode == "409") return "Conflict";
        if (responseCode == "410") return "Gone";
        if (responseCode == "411") return "Length Required";
        if (responseCode == "412") return "Precondition Failed";
        if (responseCode == "413") return "Request Entity Too Large";
        if (responseCode == "414") return "Request-URI Too Long";
        if (responseCode == "415") return "Unsupported Media Type";
        if (responseCode == "416") return "Requested Range Not Satisfiable";
        if (responseCode == "417") return "Expectation Failed";

        if (responseCode == "500") return "Internal Error";
        if (responseCode == "501") return "Not Implemented";
        if (responseCode == "502") return "Bad Gateway";
        if (responseCode == "503") return "Service Unavailable";
        if (responseCode == "504") return "Gateway Timeout";
        if (responseCode == "505") return "HTTP Version Not Supported";
        if (responseCode == "506") return "Variant Also Negotiates";
        if (responseCode == "507") return "Insufficient Storage";
        if (responseCode == "508") return "Loop Detected";
        if (responseCode == "509") return "Bandwidth Limit Exceeded";
        if (responseCode == "510") return "Not Extended";

        return "HTTP Code " + responseCode;
    };

    /**
     * Decide if this HTTP response code is considered an success. This method can
     * be customized if you have your own ideas what a successful call look like, e.g.
     * ignoring "404" for certain URLs.
     */
    this.isSuccess = function () {
        if(this.collapsedUrl.contains("/accounts/*/images")) {
            return ((this.responseCode >= 200 && this.responseCode < 300) || this.responseCode == 404);
        }
        else {
            return (this.responseCode >= 200 && this.responseCode < 300);
        }
    }
}

main(arguments);


