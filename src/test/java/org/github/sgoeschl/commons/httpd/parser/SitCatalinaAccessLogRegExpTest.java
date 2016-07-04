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
package org.github.sgoeschl.commons.httpd.parser;

import org.junit.Test;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Tests the attribute extractions of the Tomcat access logs using SIT log format.
 */
public class SitCatalinaAccessLogRegExpTest {

    private static final int REGEXP_MATCHES_REQUIRED = 19;
    private static final String LOG_ENTRY_PATTERN_STRING = "^(\\S+) (\\S+) (\\S+) \\[([\\w:/]+\\s[+\\-]\\d{4})\\] \"(.+?)\" (\\d{3}) (\\S+) \"([^\"]+)\" \"([^\"]+)\" tid:(\\S+) uid:\"(\\S+)\" con:(\\S+) rtm:\\d+\\.\\d*/(?<duration>\\d+) hct:\"(\\S+)\" hac:\"(.*)\" sid:\"(.*)\" x-user-id:\"(.*)\" x-client-id:\"(.*)\" x-client-info:\"(.*)\"";
    private static final Pattern LOG_ENTRY_REGEXP = Pattern.compile(LOG_ENTRY_PATTERN_STRING);

    static {
        Locale.setDefault(Locale.ENGLISH);
    }

    @Test
    public void shouldExtractRequiredAttributesFromGeorgeApiAccessLog() {
        final String line = "127.0.0.1 george.beeone.lan - [13/Apr/2016:11:27:24 +0200] \"GET /frontend-api/api/my/transactions?pageSize=50&id=2903243c23596c33353e17330d0a2867PRE&_=1460539634488 HTTP/1.0\" 200 7261 \"https://george.beeone.lan/index.html?at=c&devMode=true&ts=1460539633954\" \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36\" tid:http-nio-8080-exec-1 uid:\"c1a82852-f483-ed61-c8f2-c54a391434df\" con:127.0.0.1/80 rtm:0.140/140 hct:\"application/json\" hac:\"Accept: application/json; charset=utf-8, Accept-Encoding: gzip, deflate, sdch, Accept-Language: en-US,en;q=0.8,de;q=0.6,cs;q=0.4\" sid:\"-\" x-user-id:\"408732007\" x-client-id:\"-\" x-client-info:\"-\"";
        final Matcher matcher = LOG_ENTRY_REGEXP.matcher(line);

        assertTrue(matcher.matches());
        assertEquals(REGEXP_MATCHES_REQUIRED, matcher.groupCount());

        final String ipAddress = matcher.group(1);
        final String dateString = matcher.group(4);
        final String requestLine = matcher.group(5);
        final String responseCode = matcher.group(6);
        final String bytesSent = matcher.group(7);
        final String referer = matcher.group(8);
        final String userAgent = matcher.group(9);
        final String durationMicro = matcher.group("duration");

        assertEquals("127.0.0.1", ipAddress);
        assertEquals("13/Apr/2016:11:27:24 +0200", dateString);
        assertEquals("GET /frontend-api/api/my/transactions?pageSize=50&id=2903243c23596c33353e17330d0a2867PRE&_=1460539634488 HTTP/1.0", requestLine);
        assertEquals("200", responseCode);
        assertEquals("7261", bytesSent);
        assertEquals("https://george.beeone.lan/index.html?at=c&devMode=true&ts=1460539633954", referer);
        assertEquals("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36", userAgent);
        assertEquals("140", durationMicro);
    }

    @Test
    public void shouldExtractRequiredAttributesFromGeorgeImporterAccessLog() {
        final String line = "10.198.128.80 10.198.128.81 - [14/Apr/2016:00:03:02 +0200] \"POST /importer-api/importer-api/transactions HTTP/1.1\" 200 82 \"-\" \"Java/1.8.0_73\" tid:catalina-exec-128 uid:\"-\" con:10.198.128.81/30001 rtm:0.128/128 hct:\"application/json\" hac:\"Accept: application/json, Accept-Encoding: -, Accept-Language: -\" sid:\"-\" x-user-id:\"-\" x-client-id:\"-\" x-client-info:\"-\"";
        final Matcher matcher = LOG_ENTRY_REGEXP.matcher(line);

        assertTrue(matcher.matches());
        assertEquals(REGEXP_MATCHES_REQUIRED, matcher.groupCount());

        final String ipAddress = matcher.group(1);
        final String dateString = matcher.group(4);
        final String requestLine = matcher.group(5);
        final String responseCode = matcher.group(6);
        final String bytesSent = matcher.group(7);
        final String referer = matcher.group(8);
        final String userAgent = matcher.group(9);
        final String durationMicro = matcher.group("duration");

        assertEquals("10.198.128.80", ipAddress);
        assertEquals("14/Apr/2016:00:03:02 +0200", dateString);
        assertEquals("POST /importer-api/importer-api/transactions HTTP/1.1", requestLine);
        assertEquals("200", responseCode);
        assertEquals("82", bytesSent);
        assertEquals("-", referer);
        assertEquals("Java/1.8.0_73", userAgent);
        assertEquals("128", durationMicro);
    }
}
