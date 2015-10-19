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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class CustomerRegexpTest
{
    public static final int REGEXP_MATCHES_REQUIRED = 16;
    public static final String LOG_ENTRY_PATTERN_STRING = "^(\\S+) (\\S+) (\\S+) \\[([\\w:/]+\\s[+\\-]\\d{4})\\] \"(.+?)\" (\\d{3}) (\\S+) \"([^\"]+)\" \"([^\"]+)\" pid:(\\S+) uid:(\\S+) con:(\\S+) cbs:(\\S+) ckr:(\\S+) cst:(\\S+) rtm:\\d+/(\\S+) .*";
    public static final Pattern LOG_ENTRY_REGEXP = Pattern.compile(LOG_ENTRY_PATTERN_STRING);

    @Test
    public void shouldProcessAccessLog()
    {
        final String line = "127.0.0.1 localhost - [10/Oct/2015:00:00:55 +0200] \"GET /restapi/api/protected/receivers/private/top?pageSize=99999&_=1444427757085 HTTP/1.1\" 200 1961 \"https://localhost/index.html?at=c&ts=1444427756237\" \"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.93 Safari/537.36 OPR/32.0.1948.69\" pid:19357/140341736892160 uid:Vhg5FwrG-G4AAEud5gUAAABD con:10.198.253.235/443 cbs:1210/2314 ckr:77 cst:+ rtm:2/2048125 rhd:proxy-server rcs:\"-\" cmp:-% hct:\"application/json\" hco:\"idKunde=B0B8EBF7B369E711; SESSIONID=f0TTWY3LWQZ0hTwhxpR8Ftzp41LmvXBjJMvYh1TyzMyj0pWgTDhG!2099467544; PROXYSESSIONID=5ChvWY3LMSHnFnGh8vQ79QxNKLfCtBMGbVcc0mgwh11G2zKTMC1Q!1338037453; wt3_eid=%3B483115921051253%7C2144442724600356108%232144442805700189299; wt3_sid=%3B483115921051253, SERVERID=localhost\"/\"-\" hac:\"Accept: application/json, text/javascript, */*; q=0.01, Accept-Language: de-AT,de;q=0.8,en-GB;q=0.6,en;q=0.4\" hxa:\"X-REQUEST-ID: ee7f742e-c161-bda4-89ab-1da64734d880, X-proxy-WasRewritten: true, X-Forwarded-For: 10.198.162.157, X-WebLogic-KeepAliveSecs: 30, X-WebLogic-Force-JVMID: 1338037453, X-APPLICATION-USER: XXXXXXXXX, X-ORIG-CLIENT-ID:applicationclient\"/\"X-APPLICATION-REQUEST-ID: ee7f742e-c161-bda4-89ab-1da64734d880, X-APPLICATION-HOST: localhost\" brn:- bsr:- bwr: brc:- ssl:on sve:TLSv1 sci:ECDHE-RSA-AES256-SHA sck:256/256 sid:0883cd142a22b0cac50eb7c7b2937481947bb74ba1a78bd813e6d92c40778899 sre:Resumed sni:- srp:\"-\" scc:\"-\"/\"-\" scv:\"NONE\" sar:-";

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
        final String durationMicro = matcher.group(16);

        assertEquals("127.0.0.1", ipAddress);
        assertEquals("10/Oct/2015:00:00:55 +0200", dateString);
        assertEquals("GET /restapi/api/protected/receivers/private/top?pageSize=99999&_=1444427757085 HTTP/1.1", requestLine);
        assertEquals("200", responseCode);
        assertEquals("1961", bytesSent);
        assertEquals("https://localhost/index.html?at=c&ts=1444427756237", referer);
        assertEquals("Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.93 Safari/537.36 OPR/32.0.1948.69", userAgent);
        assertEquals("2048125", durationMicro);
    }
}
