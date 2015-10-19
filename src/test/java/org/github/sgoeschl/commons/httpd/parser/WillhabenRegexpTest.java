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

public class WillhabenRegexpTest
{
    public static final int REGEXP_MATCHES_REQUIRED = 11;
    public static final String LOG_ENTRY_PATTERN_STRING = "^(\\S+) (\\S+) (\\S+) \\[([\\w:/]+\\s[+\\-]\\d{4})\\] \\\"(.+?)\\\" (\\d{3}) (\\S+) \\\"([^\\\"]*)\\\" \\\"([^\\\"]*)\\\" \\\"([^\\\"]*)\\\"\\s*\\d+\\/(\\d+)";
    public static final Pattern LOG_ENTRY_REGEXP = Pattern.compile(LOG_ENTRY_PATTERN_STRING);

    @Test
    public void shouldProcessAccessLog()
    {
        final String line = "84.112.209.3 - - [24/Oct/2011:23:09:16 +0200] \"GET /iad/kaufen-und-verkaufen/baby-kind/roemer-kindersitz-bis-18-kg-31509842?adId=31509842 HTTP/1.1\" 301 - \"-\" \"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30618)\" \"daskeksi=gut; IAD_CAMPAIGN=_blank; IADVISITOR=386263909; IADPX2=a9f8a120c798bc603e3034799397531422876c81b05b9a992190dd840180c25dac00e4a1c8b061ef; POPUPCHECK=1239404049193; JSESSIONID=0E652515E39AA157E2EBDC148C09238B; testf5=rd10o00000000000000000000ffffc2e8743bo80; OAS_SC1=1239317647367; xtvrn=$397816$; testf5=rd10o00000000000000000000ffffc2e87422o80\"     0/19401";
        final Matcher matcher = LOG_ENTRY_REGEXP.matcher(line);

        assertTrue(matcher.matches());
        assertEquals(REGEXP_MATCHES_REQUIRED, matcher.groupCount());

        String ipAddress       = matcher.group(1);
        String dateString      = matcher.group(4);
        String requestLine     = matcher.group(5);
        String responseCode    = matcher.group(6);
        String bytesSent       = matcher.group(7);
        String referer         = matcher.group(8);
        String userAgent       = matcher.group(9);
        String durationMicro   = matcher.group(11);

        assertEquals("84.112.209.3", ipAddress);
        assertEquals("24/Oct/2011:23:09:16 +0200", dateString);
        assertEquals("GET /iad/kaufen-und-verkaufen/baby-kind/roemer-kindersitz-bis-18-kg-31509842?adId=31509842 HTTP/1.1", requestLine);
        assertEquals("301", responseCode);
        assertEquals("-", bytesSent);
        assertEquals("-", referer);
        assertEquals("Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30618)", userAgent);
        assertEquals("19401", durationMicro);
    }

}
