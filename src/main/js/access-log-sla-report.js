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

/*
 * This JavaScript parses a sIT Apache & Cataline access logs and uses JAMon
 * to generate a response time report.
 *
 * @author <a href="mailto:siegfried.goeschl@gmail.com">Siegfried Goeschl</a>
 */

var JAMON_REPORT_MODEL = new org.apache.jmeter.extra.report.sla.JMeterReportModel();

var CATALINA_SIT_LOGENTRY_REGEXP_STRING = "^(\\S+) (\\S+) (\\S+) \\[([\\w:/]+\\s[+\\-]\\d{4})\\] \"(.+?)\" (\\d{3}) (\\S+) \"([^\"]+)\" \"([^\"]+)\" tid:(\\S+) uid:\"(\\S+)\" con:(\\S+) rtm:\\d+\\.\\d*/(?<duration>\\d+) hct:\"(\\S+)\" hac:\"(.*)\" sid:\"(.*)\" x-user-id:\"(.*)\" x-client-id:\"(.*)\" x-client-info:\"(.*)\"";
var HTTPD_SIT_LOGENTRY_REGEXP_STRING = "^(\\S+) (\\S+) (\\S+) \\[([\\w:/]+\\s[+\\-]\\d{4})\\] \"(.+?)\" (\\d{3}) (\\S+) \"([^\"]+)\" \"([^\"]+)\" pid:(\\S+) uid:(\\S+) con:(\\S+) cbs:(\\S+) ckr:(\\S+) cst:(\\S+) rtm:\\d+/(?<duration>\\S+) .*";

var CATALINA_SIT_ACCESS_LOG_PARSER = new AccessLogLineParser(
    "catalina-sit",
    CATALINA_SIT_LOGENTRY_REGEXP_STRING,
    19,
    "dd/MMM/yyyy:HH:mm:ss Z",
    "^([a-z]{1,15}+(\\.[a-z]{3,4}|\\d?))$",
    [],
    [],
    1
);

var CATALINA_SIT_GEORGE_API_ACCESS_LOG_PARSER = new AccessLogLineParser(
    "catalina-sit-geapi",
    CATALINA_SIT_LOGENTRY_REGEXP_STRING,
    19,
    "dd/MMM/yyyy:HH:mm:ss Z",
    "^([a-z]{1,15}+(\\.[a-z]{3,4}|\\d?))$",
    [],
    ["X-ADVISOR-ID:", "images/image?variant=", "api/my/images/", "api/my/orders/"],
    1
);

var CATALINA_SIT_GEORGE_IMPORTER_ACCESS_LOG_PARSER = new AccessLogLineParser(
    "catalina-sit-geimp",
    CATALINA_SIT_LOGENTRY_REGEXP_STRING,
    19,
    "dd/MMM/yyyy:HH:mm:ss Z",
    "^([a-z\-])+$",
    [],
    [],
    1
);

var HTTPD_SIT_ACCESS_LOG_PARSER = new AccessLogLineParser(
    "httpd-sit",
    HTTPD_SIT_LOGENTRY_REGEXP_STRING,
    16,
    "dd/MMM/yyyy:HH:mm:ss Z",
    "^([a-z]{1,15}+(\\.[a-z]{3,4}|\\d?))$",
    [],
    [],
    1000
);

var HTTPD_SIT_GEORGE_API_ACCESS_LOG_PARSER = new AccessLogLineParser(
    "httpd-sit-geimp",
    HTTPD_SIT_LOGENTRY_REGEXP_STRING,
    16,
    "dd/MMM/yyyy:HH:mm:ss Z",
    "^([a-z]{1,15}+(\\.[a-z]{3,4}|\\d?))$",
    [],
    ["X-ADVISOR-ID:", "images/image?variant=", "api/my/images/", "api/my/orders/"],
    1000
);

var CUSTOM_ACCESS_LOG_PARSER = new AccessLogLineParser(
    "custom",
    HTTPD_SIT_LOGENTRY_REGEXP_STRING,
    16,
    "dd/MMM/yyyy:HH:mm:ss Z",
    "^([a-z]{1,15}+(\\.[a-z]{3,4}|\\d?))$",
    [],
    [],
    1000
);

var PARSER_MAP = {};
PARSER_MAP[CATALINA_SIT_ACCESS_LOG_PARSER.name] = CATALINA_SIT_ACCESS_LOG_PARSER;
PARSER_MAP[HTTPD_SIT_ACCESS_LOG_PARSER.name] = HTTPD_SIT_ACCESS_LOG_PARSER;
PARSER_MAP[CATALINA_SIT_GEORGE_API_ACCESS_LOG_PARSER.name] = CATALINA_SIT_GEORGE_API_ACCESS_LOG_PARSER;
PARSER_MAP[CATALINA_SIT_GEORGE_IMPORTER_ACCESS_LOG_PARSER.name] = CATALINA_SIT_GEORGE_IMPORTER_ACCESS_LOG_PARSER;
PARSER_MAP[HTTPD_SIT_GEORGE_API_ACCESS_LOG_PARSER.name] = HTTPD_SIT_GEORGE_API_ACCESS_LOG_PARSER;
PARSER_MAP[CUSTOM_ACCESS_LOG_PARSER.name] = CUSTOM_ACCESS_LOG_PARSER;

function main(arguments) {

    var cli = new CLI(HTTPD_SIT_GEORGE_API_ACCESS_LOG_PARSER.name).parse(arguments);

    if (cli.hasErrors) {
        return 1;
    }

    var accessLogLineParserName = cli.accessLogLineParserName;
    var accessLogLineParser = PARSER_MAP[accessLogLineParserName];

    if (accessLogLineParser == null) {
        println("Unable to find the following parser configuration: " + accessLogLineParserName)
        return 1;
    }

    parseLogfiles(accessLogLineParser, cli.files);
    createAccessLogReportProperties(accessLogLineParser);
    writeHtmlReport(cli.outputFileName, "Access Log SLA Report", accessLogLineParser.name);
    return 0;
}

function parseLogfiles(accessLogParser, fileNames) {

    println("[INFO] Parsing the following number of file(s) : " + fileNames.length);

    for (var i = 0; i < fileNames.length; i++) {

        var fileName = fileNames[i];
        var logFile = new java.io.File(fileName);
        var reader = null;

        try {
            reader = createReader(logFile);
            parseLogfile(accessLogParser, logFile, reader);
        }
        finally {
            if (reader != null) {
                reader.close();
            }
        }
    }
}

function createAccessLogReportProperties(accessLogLineParser) {
    java.lang.System.setProperty("jmeter.parser.name", accessLogLineParser.name);
    java.lang.System.setProperty("jmeter.parser.includes", JSON.stringify(accessLogLineParser.logLineIncludeFilters));
    java.lang.System.setProperty("jmeter.parser.excludes", JSON.stringify(accessLogLineParser.logLineExcludeFilters));
}

function isCompressedLogFile(logFile) {
    var name = logFile.getName();
    return name.endsWith(".zip") || name.endsWith(".gz") || name.endsWith("gzip") || name.endsWith(".bzip2") || name.endsWith("bz2");
}

function createReader(logFile) {
    if (isCompressedLogFile(logFile)) {
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

function parseLogfile(accessLogParser, logFile, reader) {

    try {

        var startTime = java.lang.System.currentTimeMillis();
        var lineNumber = 0;
        var errorCount = 0;
        var ignoredCount = 0;
        var logEntry = null;

        while ((line = reader.readLine()) != null) {

            lineNumber++;

            if (accessLogParser.acceptLogLine(line)) {

                logEntry = accessLogParser.parseLine(logFile, lineNumber, line);

                if (logEntry != null) {

                    if (accessLogParser.accceptLogEntry(logEntry)) {
                        process(logEntry);
                    }
                    else {
                        ignoredCount = ignoredCount + 1;
                    }
                }
            }
            else {
                ignoredCount = ignoredCount + 1;
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
        println("[ERROR] " + dump("accessLogParser", accessLogParser));
    }
}


/**
 * Process a single log entry.
 */
function process(logEntry) {
    addToReportModel(logEntry);
}

function createMonitorName(logEntry) {
    return logEntry.collapsedUrl + " # " + logEntry.requestMethod;
}

function addToReportModel(logEntry) {

    var timestamp = logEntry.timestamp;
    var monitorName = createMonitorName(logEntry);
    var responseCode = logEntry.responseCode;
    var timeTaken = logEntry.timeTakenMillis;

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

    var sortOrder = "asc";
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

function dump(name, object) {
    println(name + ": " + JSON.stringify(object, null, 4));
}

// ==========================================================================
// CommandLineParser
// ==========================================================================

function CLI(defaultParser) {

    var OPTION_PARSER = "p";
    var OPTION_OUTPUT = "o";

    this.hasErrors = false;
    this.accessLogLineParserName = defaultParser;
    this.outputFileName = "access-log-report.html";
    this.files = null;

    this.parse = function (args) {

        var helpFormatter = new org.apache.commons.cli.HelpFormatter();

        var options = new org.apache.commons.cli.Options();
        options.addOption("h", "help", false, "print this message");
        options.addOption(OPTION_PARSER, "parser", true, "parser for access log");
        options.addOption(OPTION_OUTPUT, "output", true, "output file for report");

        var cmd = null;
        var parser = new org.apache.commons.cli.BasicParser();

        try {
            cmd = parser.parse(options, args);
        }
        catch (e) {
            println(e.getMessage());
            helpFormatter.printHelp("access-log-sla-report", options);
            this.hasErrors = true;
            return this;
        }

        if (cmd.hasOption(OPTION_PARSER)) {
            this.accessLogLineParserName = cmd.getOptionValue(OPTION_PARSER);
        }

        if (cmd.hasOption(OPTION_OUTPUT)) {
            this.outputFileName = cmd.getOptionValue(OPTION_OUTPUT);
        }

        if (cmd.hasOption("h")) {
            helpFormatter.printHelp("access-log-sla-report", options);
            this.hasErrors = true;
            return this;
        }

        this.files = cmd.getArgs();

        if (this.files.length == 0) {
            helpFormatter.printHelp("access-log-sla-report [options] file(s)", options);
            this.hasErrors = true;
        }

        return this;
    };
}

// ==========================================================================
// AccessLogLineParser
// ==========================================================================

/**
 * Contains pre-canned accessLogLineParserName configuration and mechanics to parse different access log formats
 * line by line.
 *
 * @param name Name of the instance
 * @param logEntryRegExpString RegExp to split the access log line into individual parts
 * @param logEntryNrOfMatches Number of matches to consider the regexp valid
 * @param logEntryDataFormat Date foramt to parse the timestamp
 * @param resourcePathRegExpString RegExp to detect a resource path part in an URL
 * @param logLineIncludeFilters Simple string filter applied to an un-parsed log line
 * @param logLineExcludeFilters Simple string filter applied to an un-parsed log line
 * @param toMillisDivisor the multipler to convert the response time to milli seconds
 */
function AccessLogLineParser(name, logEntryRegExpString, logEntryNrOfMatches, logEntryDataFormat, resourcePathRegExpString, logLineIncludeFilters, logLineExcludeFilters, toMillisDivisor) {

    this.name = name;
    this.logEntryRegExpString = logEntryRegExpString;
    this.logEntryRegExp = java.util.regex.Pattern.compile(logEntryRegExpString);
    this.logEntryNrOfMatches = logEntryNrOfMatches;
    this.logEntryDateParser = new java.text.SimpleDateFormat(logEntryDataFormat, java.util.Locale.ENGLISH);
    this.resourcePathRegExpString = resourcePathRegExpString;
    this.resourcePathRegExp = java.util.regex.Pattern.compile(resourcePathRegExpString);
    this.logLineIncludeFilters = logLineIncludeFilters;
    this.logLineExcludeFilters = logLineExcludeFilters;
    this.toMillisDivisor = toMillisDivisor;

    /**
     * Cleanup stuff which would break the regexp later on.
     */
    this.preProcessLogLine = function (logLine) {
        return logLine.replace("\\\"", "");
    };

    /**
     * Include the un-parsed log line into the report?
     */
    this.acceptLogLine = function (logLine) {

        var i = 0;

        if (this.logLineIncludeFilters.length > 0) {
            for (i = 0; i < this.logLineIncludeFilters.length; i++) {
                var logLineIncludeFilter = this.logLineIncludeFilters[i];
                if (logLine.contains(logLineIncludeFilter)) {
                    return false;
                }
            }
            return false;
        }

        if (this.logLineExcludeFilters.length > 0) {
            for (i = 0; i < this.logLineExcludeFilters.length; i++) {
                var logLineExcludeFilter = this.logLineExcludeFilters[i];
                if (logLine.contains(logLineExcludeFilter)) {
                    return false;
                }
            }
        }

        return true;
    };

    /**
     * Include the parsed log entry into the report?
     */
    this.accceptLogEntry = function (logEntry) {
        return logEntry != null;
    };

    /**
     * Is this a resource id we can collapse? We assume
     * that the first part of a path is never a resource id.
     */
    this.isResourcePathPart = function (part, index) {
        return index > 1 ? this.resourcePathRegExp.matcher(part).matches() : true;
    };

    /**
     * Extract the base url used for the JAMon monitor. We need to strip various
     * ids used for addressing individual resources to avoid millions of "unique"
     * URLs.
     */
    this.createCollapsedUrl = function (requestURL) {

        // restapi/api/my/configuration ==> restapi/api/my/configuration
        // restapi/api/my/accounts/XXXXXXXXX/stats ==> restapi/api/my/accounts/*/stats
        // restapi/api/my/accounts/YYYYYYYYY/images/image ==> restapi/api/my/accounts/*/images/image

        var parts = requestURL.split("/");
        var result = new java.lang.StringBuffer();

        for (var i = 1; i < parts.length; i++) {
            var part = parts[i];
            if (this.isResourcePathPart(part, i)) {
                result.append(part).append("/");
            }
            else {
                result.append("*").append("/")
            }
        }

        result = result.substring(0, result.length() - 1);

        return result;
    };

    /**
     * Parse a single line of the HTTPD access log and add it to the report model.
     *
     * @param logFile the currently processed log file
     * @param lineNumber the currently processing line number
     * @param line current line of the logfile
     * @return null if the line was not parsable or the processes line
     */
    this.parseLine = function (logFile, lineNumber, line) {

        try {

            // cleanup stuff which would break regexp later on

            preProccessedLine = this.preProcessLogLine(line);

            // split the line of the access log into tokens using a regexp

            var matcher = this.logEntryRegExp.matcher(preProccessedLine);

            // check that the complete regexp matches

            if (!matcher.matches()) {
                println("[ERROR] RegExp did not match : " + preProccessedLine);
                return null;
            }

            if (this.logEntryNrOfMatches != matcher.groupCount()) {
                println("[ERROR] RegExp partly matched : groupCount=" + matcher.groupCount());
                return null;
            }

            // access the fields from a combined log format

            var ipAddress = matcher.group(1);
            var dateString = matcher.group(4);
            var requestLine = matcher.group(5);
            var responseCode = parseInt(matcher.group(6));
            var bytesSent = parseInt(matcher.group(7));
            var referer = matcher.group(8);
            var userAgent = matcher.group(9);

            // pick up other data using named mathcing groups
            var duration = matcher.group("duration");

            // split something like "GET /iad/kaufen-und-verkaufen/foto-tv-video-audio/lautsprecher-boxen-verstaerker?page=27 HTTP/1.1"
            // into its individual components

            var requestLineParts = requestLine.split(" ");
            var requestHttpMethod = requestLineParts[0];
            var requestURLLine = requestLineParts[1];
            var questionMarkIndex = requestURLLine.indexOf('?');
            var requestUrl = ( questionMarkIndex > 0 ? requestURLLine.substring(0, questionMarkIndex) : requestURLLine);
            var requestParams = ( questionMarkIndex > 0 ? requestURLLine.substring(questionMarkIndex + 1) : "");
            var requestHttpProtocol = requestLineParts[2];

            // convert raw parameters

            var timestamp = this.logEntryDateParser.parse(dateString);
            var timeTakenMillis = Math.round(parseInt(duration) / this.toMillisDivisor);
            var collapsedUrl = this.createCollapsedUrl(requestUrl);

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
                timeTakenMillis);
        }
        catch (e) {
            println("[WARN] Failed to parse the following line : " + line);
            println(e);
            return null;
        }
    };

}

// ==========================================================================
// LogEntry
// ==========================================================================

/**
 * Encapsulates a successfully parsed line from the access log.
 */
function LogEntry(logFile, lineNumber, line, ipAddress, timestamp, requestUrl, collapsedUrl, requestMethod, responseCode, bytesSent, referer, userAgent, requestParams, timeTakenMillis) {

    if (responseCode < 100 || responseCode > 506) {
        throw "Invalid responseCode : " + responseCode;
    }

    if (bytesSent < 0 || bytesSent > 1024 * 1024 * 1024) {
        throw "Invalid bytesSent : " + bytesSent;
    }

    if (timeTakenMillis < 0 || timeTakenMillis > 3600 * 1000) {
        throw "Invalid timeTakenMillis : " + timeTakenMillis;
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

    /** the corresponding un-parsed line from the access log */
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
    this.timeTakenMillis = timeTakenMillis;

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
        buffer.append("timeTakenMillis=").append(this.timeTakenMillis.toString()).append("\n");
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
        buffer.append(this.timeTakenMillis.toString()).append(";");
        buffer.append(this.logFile.getAbsolutePath()).append(";");
        buffer.append(this.lineNumber.toString());
        return buffer.toString();
    };

    this.getHttpResponseCodeName = function () {

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
        return (this.responseCode >= 200 && this.responseCode < 400);
    }
}

main(arguments);


