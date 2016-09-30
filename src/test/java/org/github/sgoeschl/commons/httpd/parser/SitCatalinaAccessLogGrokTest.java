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

import oi.thekraken.grok.api.Grok;
import oi.thekraken.grok.api.Match;
import org.junit.Test;

import java.util.Locale;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Tests the attribute extractions of the Tomcat access logs using SIT log format.
 */
public class SitCatalinaAccessLogGrokTest implements GrokAttributeNames {

    private static final int GROK_MATCHES_REQUIRED = 28;
    private static final String GROK_PATTERN_PATH = "./patterns/patterns";
    private static final String GROK_EXPRESSION = "%{COMBINEDAPACHELOG} tid:%{HOSTNAME} uid:%{QS} con:%{IPORHOST}/%{POSINT} rtm:%{NUMBER}/%{INT:time_duration}";

    static {
        Locale.setDefault(Locale.ENGLISH);
    }

    @Test
    public void shouldExtractRequiredAttributesFromGeorgeApiAccessLog() throws Exception {

        // "127.0.0.1 george.beeone.lan - [13/Apr/2016:11:27:24 +0200] \"GET /frontend-api/api/my/transactions?pageSize=50&id=2903243c23596c33353e17330d0a2867PRE&_=1460539634488 HTTP/1.0\" 200 7261 \"https://george.beeone.lan/index.html?at=c&devMode=true&ts=1460539633954\" \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36\" tid:http-nio-8080-exec-1 uid:\"c1a82852-f483-ed61-c8f2-c54a391434df\" con:127.0.0.1/80 rtm:0.140/140 hct:\"application/json\" hac:\"Accept: application/json; charset=utf-8, Accept-Encoding: gzip, deflate, sdch, Accept-Language: en-US,en;q=0.8,de;q=0.6,cs;q=0.4\" sid:\"-\" x-user-id:\"408732007\" x-client-id:\"-\" x-client-info:\"-\""

        final String line = "127.0.0.1 " +
                "george.beeone.lan " +
                "- " +
                "[13/Apr/2016:11:27:24 +0200] " +
                "\"GET /frontend-api/api/my/transactions?pageSize=50&id=2903243c23596c33353e17330d0a2867PRE&_=1460539634488 HTTP/1.0\" " +
                "200 " +
                "7261 " +
                "\"https://george.beeone.lan/index.html?at=c&devMode=true&ts=1460539633954\" " +
                "\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36\" " +
                "tid:http-nio-8080-exec-1 " +
                "uid:\"c1a82852-f483-ed61-c8f2-c54a391434df\" " +
                "con:127.0.0.1/80 " +
                "rtm:0.140/140 " +
                "hct:\"application/json\" " +
                "hac:\"Accept: application/json; charset=utf-8, Accept-Encoding: gzip, deflate, sdch, Accept-Language: en-US,en;q=0.8,de;q=0.6,cs;q=0.4\" " +
                "sid:\"-\" " +
                "x-user-id:\"408732007\" " +
                "x-client-id:\"-\" " +
                "x-client-info:\"-\"";

        final Map<String, Object> map = apply(grok(), line);

        assertEquals(GROK_MATCHES_REQUIRED, map.size());
        assertEquals("127.0.0.1", map.get(CLIENT_IP));
        assertEquals("george.beeone.lan", map.get(IDENT));
        assertEquals("-", map.get(AUTHENTICATION));
        assertEquals("13/Apr/2016:11:27:24 +0200", map.get(TIMESTAMP));
        assertEquals("GET", map.get(HTTP_VERB));
        assertEquals("/frontend-api/api/my/transactions?pageSize=50&id=2903243c23596c33353e17330d0a2867PRE&_=1460539634488", map.get(HTTP_REQUEST));
        assertEquals("1.0", map.get(HTTP_VERSION));
        assertEquals("200", map.get(HTTP_STATUS_CODE));
        assertEquals("7261", map.get(BYTES_READ));
        assertEquals("https://george.beeone.lan/index.html?at=c&devMode=true&ts=1460539633954", map.get(REFERRER));
        assertEquals("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36", map.get(HTTP_USER_AGENT));
        assertEquals("http-nio-8080-exec-1", map.get("HOSTNAME"));
        assertEquals("c1a82852-f483-ed61-c8f2-c54a391434df", map.get("QS"));
        assertEquals("127.0.0.1", map.get("IPORHOST"));
        assertEquals("80", map.get("POSINT"));
        assertEquals("140", map.get(TIME_DURATION));
    }

    @Test
    public void shouldExtractRequiredAttributesFromGeorgeApiAccessLog01() throws Exception {

        // 127.0.0.1 george.beeone.lan - [13/Apr/2016:11:13:06 +0200] "GET /frontend-api/api/swagger.json HTTP/1.0" 200 245765 "https://george.beeone.lan/g/frontend-api-docs/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36" tid:http-nio-8080-exec-4 uid:"-" con:127.0.0.1/80 rtm:0.064/64 hct:"application/json" hac:"Accept: application/json;charset=utf-8,*/*, Accept-Encoding: gzip, deflate, sdch, Accept-Language: en-US,en;q=0.8,de;q=0.6,cs;q=0.4" sid:"-" x-user-id:"-" x-client-id:"-" x-client-info:"-"

        final String line = "127.0.0.1 " +
                "george.beeone.lan " +
                "- " +
                "[13/Apr/2016:11:13:06 +0200] " +
                "\"GET /frontend-api/api/swagger.json HTTP/1.0\" " +
                "200 " +
                "245765 " +
                "\"https://george.beeone.lan/g/frontend-api-docs/\" " +
                "\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36\" " +
                "tid:http-nio-8080-exec-4 " +
                "uid:\"-\" " +
                "con:127.0.0.1/80 " +
                "rtm:0.064/64 " +
                "hct:\"application/json\" " +
                "hac:\"Accept: application/json;charset=utf-8,*/*, Accept-Encoding: gzip, deflate, sdch, Accept-Language: en-US,en;q=0.8,de;q=0.6,cs;q=0.4\" " +
                "sid:\"-\" " +
                "x-user-id:\"-\" " +
                "x-client-id:\"-\" " +
                "x-client-info:\"-\"";

        final Map<String, Object> map = apply(grok(), line);

        assertEquals(GROK_MATCHES_REQUIRED, map.size());
        assertEquals("127.0.0.1", map.get(CLIENT_IP));
        assertEquals("george.beeone.lan", map.get(IDENT));
        assertEquals("-", map.get(AUTHENTICATION));
        assertEquals("13/Apr/2016:11:13:06 +0200", map.get(TIMESTAMP));
        assertEquals("GET", map.get(HTTP_VERB));
        assertEquals("/frontend-api/api/swagger.json", map.get(HTTP_REQUEST));
        assertEquals("1.0", map.get(HTTP_VERSION));
        assertEquals("200", map.get(HTTP_STATUS_CODE));
        assertEquals("245765", map.get(BYTES_READ));
        assertEquals("https://george.beeone.lan/g/frontend-api-docs/", map.get(REFERRER));
        assertEquals("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36", map.get(HTTP_USER_AGENT));
        assertEquals("http-nio-8080-exec-4", map.get("HOSTNAME"));
        assertEquals("-", map.get("QS"));
        assertEquals("127.0.0.1", map.get("IPORHOST"));
        assertEquals("80", map.get("POSINT"));
        assertEquals("64", map.get(TIME_DURATION));
    }

    @Test
    public void shouldExtractRequiredAttributesFormGeorgeImporterAccessLog() throws Exception {

        // "10.198.128.80 10.198.128.81 - [14/Apr/2016:00:03:02 +0200] \"POST /importer-api/importer-api/transactions HTTP/1.1\" 200 82 \"-\" \"Java/1.8.0_73\" tid:catalina-exec-128 uid:\"-\" con:10.198.128.81/30001 rtm:0.128/128 hct:\"application/json\" hac:\"Accept: application/json, Accept-Encoding: -, Accept-Language: -\" sid:\"-\" x-user-id:\"-\" x-client-id:\"-\" x-client-info:\"-\""

        final String line = "10.198.128.80 " +
                "10.198.128.81 " +
                "- " +
                "[14/Apr/2016:00:03:02 +0200] " +
                "\"POST /importer-api/importer-api/transactions HTTP/1.1\" " +
                "200 " +
                "82 " +
                "\"-\" " +
                "\"Java/1.8.0_73\" " +
                "tid:catalina-exec-128 " +
                "uid:\"-\" " +
                "con:10.198.128.81/30001 " +
                "rtm:0.128/128 " +
                "hct:\"application/json\" " +
                "hac:\"Accept: application/json, Accept-Encoding: -, Accept-Language: -\" " +
                "sid:\"-\" " +
                "x-user-id:\"-\" " +
                "x-client-id:\"-\" " +
                "x-client-info:\"-\"";

        final Map<String, Object> map = apply(grok(), line);

        assertEquals(GROK_MATCHES_REQUIRED, map.size());
        assertTrue("No attributes are found", !map.isEmpty());
        assertEquals("10.198.128.80", map.get(CLIENT_IP));
        assertEquals("10.198.128.81", map.get(IDENT));
        assertEquals("-", map.get(AUTHENTICATION));
        assertEquals("14/Apr/2016:00:03:02 +0200", map.get(TIMESTAMP));
        assertEquals("POST", map.get(HTTP_VERB));
        assertEquals("/importer-api/importer-api/transactions", map.get(HTTP_REQUEST));
        assertEquals("1.1", map.get(HTTP_VERSION));
        assertEquals("200", map.get(HTTP_STATUS_CODE));
        assertEquals("82", map.get(BYTES_READ));
        assertEquals("-", map.get(REFERRER));
        assertEquals("Java/1.8.0_73", map.get(HTTP_USER_AGENT));
        assertEquals("catalina-exec-128", map.get("HOSTNAME"));
        assertEquals("-", map.get("QS"));
        assertEquals("10.198.128.81", map.get("IPORHOST"));
        assertEquals("30001", map.get("POSINT"));
        assertEquals("128", map.get(TIME_DURATION));
    }

    private Grok grok() throws Exception {
        return Grok.create(GROK_PATTERN_PATH, GROK_EXPRESSION);
    }

    private Map<String, Object> apply(final Grok grok, final String line) {
        final Match gm = grok.match(line);
        gm.captures();
        return gm.toMap();
    }

}
