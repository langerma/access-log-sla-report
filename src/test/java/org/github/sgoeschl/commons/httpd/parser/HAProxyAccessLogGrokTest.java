package org.github.sgoeschl.commons.httpd.parser;

import oi.thekraken.grok.api.Grok;
import oi.thekraken.grok.api.Match;
import org.junit.Ignore;
import org.junit.Test;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class HAProxyAccessLogGrokTest implements GrokAttributeNames {

    private static final int GROK_MATCHES_REQUIRED = 52;
    private static final String GROK_PATTERN_PATH = "./patterns/patterns";
    private static final String GROK_EXPRESSION = "%{HAPROXYHTTP}";

    static {
        Locale.setDefault(Locale.ENGLISH);
    }

    @Test
    public void shouldExtractRequiredAttributesFromGeorgeApiAccessLog() throws Exception {
        final String line = "Jun 15 10:45:41 apprtrf1 haproxy[11325]: 10.195.128.87:57209 [15/Jun/2016:10:45:41.835] lb-geapi.fat.erste-group.net:30012~ lb-geapi.fat.erste-group.net:30012/appngf3.eb.lan.at:30012 33/0/3/66/103 200 14583 - - ---- 38/9/1/2/0 0/0 {application/json; charset=utf-8||de-DE,de;q=0.8,en-US;q=0.6,en;q=0.4|lb-geapi.fat.erste-group.net:30012|https://george.fat.sparkasse.at/index.html?isfirsttime=true?at=c|10.195.162.204|bbc63ff2-27a4-9bb4-600e-0d08d720fba1|400775318|georgeclient} {||application/json|appngf3} \"GET /frontend-api/api/my/transactions?pageSize=50&id=C24329BA6E644424&_=1465980319501 HTTP/1.1\" ssl:1 sve:TLSv1 sci:ECDHE-RSA-AES256-SHA sck:256/256";

        final Map<String, Object> map = apply(grok(), line);

        assertEquals(GROK_MATCHES_REQUIRED, map.size());
        assertTrue("No attributes extracted", !map.isEmpty());
        assertEquals("Jun 15 10:45:41", map.get("syslog_timestamp"));
        assertEquals("apprtrf1", map.get("syslog_server"));
        assertEquals("haproxy[11325]", map.get("SYSLOGPROG"));
        assertEquals("10.195.128.87", map.get(CLIENT_IP));
        assertEquals("57209", map.get("client_port"));
        assertEquals("15/Jun/2016:10:45:41.835", map.get(TIMESTAMP));
        assertEquals("lb-geapi.fat.erste-group.net:30012~", map.get("frontend_name"));
        assertEquals("lb-geapi.fat.erste-group.net:30012", map.get("backend_name"));
        assertEquals("appngf3.eb.lan.at:30012", map.get("server_name"));
        assertEquals("33", map.get("time_request"));
        assertEquals("0", map.get("time_queue"));
        assertEquals("3", map.get("time_backend_connect"));
        assertEquals("66", map.get("time_backend_response"));
        assertEquals("103", map.get(TIME_DURATION));
        assertEquals("200", map.get(HTTP_STATUS_CODE));
        assertEquals("14583", map.get(BYTES_READ));
        assertEquals("38", map.get("actconn"));
        assertEquals("9", map.get("feconn"));
        assertEquals("1", map.get("beconn"));
        assertEquals("2", map.get("srvconn"));
        assertEquals("0", map.get("retries"));
        assertEquals("0", map.get("srv_queue"));
        assertEquals("0", map.get("backend_queue"));
        assertEquals("application/json; charset=utf-8||de-DE,de;q=0.8,en-US;q=0.6,en;q=0.4|lb-geapi.fat.erste-group.net:30012|https://george.fat.sparkasse.at/index.html?isfirsttime=true?at=c|10.195.162.204|bbc63ff2-27a4-9bb4-600e-0d08d720fba1|400775318|georgeclient", map.get("HAPROXYCAPTUREDREQUESTHEADERS"));
        assertEquals("||application/json|appngf3", map.get("HAPROXYCAPTUREDRESPONSEHEADERS"));
        assertEquals("GET", map.get(HTTP_VERB));
        assertEquals("/frontend-api/api/my/transactions?pageSize=50&id=C24329BA6E644424&_=1465980319501", map.get(HTTP_REQUEST));
        assertEquals("1.1", map.get(HTTP_VERSION));
    }

    @Test
    @Ignore("")
    public void shouldExtractRequiredAttributesFromRedisAccessLog() throws Exception {
        // final String grokExpression = "%{SYSLOGTIMESTAMP:syslog_timestamp} %{IPORHOST:syslog_server} %{SYSLOGPROG}: %{IP:client_ip}:%{INT:client_port} \\[%{HAPROXYDATE:timestamp}\\] %{NOTSPACE:frontend_name} %{NOTSPACE:backend_name}/%{NOTSPACE:server_name} %{INT:time_request}/%{INT:time_queue}/%{INT:time_backend_connect}/%{INT:time_backend_response}/%{NOTSPACE:time_duration} %{INT:http_status_code} %{NOTSPACE:bytes_read} %{DATA:captured_request_cookie} %{DATA:captured_response_cookie} %{NOTSPACE:termination_state} %{INT:actconn}/%{INT:feconn}/%{INT:beconn}/%{INT:srvconn}/%{NOTSPACE:retries} %{INT:srv_queue}/%{INT:backend_queue} (\\{%{HAPROXYCAPTUREDREQUESTHEADERS}\\})?( )?(\\{%{HAPROXYCAPTUREDRESPONSEHEADERS}\\})?( )?\"%{WORD:http_verb} %{URIPATHPARAM:http_request}( HTTP/%{NUMBER:http_version}\")?"
        final String grokExpression = "%{SYSLOGTIMESTAMP:syslog_timestamp} %{IPORHOST:syslog_server} %{SYSLOGPROG}: %{IP:client_ip}:%{INT:client_port} \\[%{HAPROXYDATE:timestamp}\\] %{NOTSPACE:frontend_name} %{NOTSPACE:backend_name}/%{NOTSPACE:server_name} %{INT:time_request}/%{INT:time_queue}/%{INT:time_backend_connect}/%{INT:time_backend_response}/%{NOTSPACE:time_duration} ";
        final String line = "Jun 15 00:01:08 apprtrf1 haproxy[11325]: 10.195.128.83:50178 [14/Jun/2016:23:00:00.003] lb-geredis.fat.erste-group.net:30291 lb-geredis.fat.erste-group.net:30291/appredisf1.eb.lan.at:6379 1/0/3668428 2878 CD 22/21/21/21/0 0/0";

        final Map<String, Object> map = apply(grok(grokExpression), line);

        // assertEquals(GROK_MATCHES_REQUIRED, map.size());
        assertTrue("No attributes extracted", !map.isEmpty());
        assertEquals("Jun 15 00:01:08", map.get("syslog_timestamp"));
        assertEquals("apprtrf1", map.get("syslog_server"));
        assertEquals("haproxy[11325]", map.get("SYSLOGPROG"));
        assertEquals("10.195.128.83", map.get(CLIENT_IP));
        assertEquals("50178", map.get("client_port"));
        assertEquals("14/Jun/2016:23:00:00.003", map.get(TIMESTAMP));
        assertEquals("lb-geredis.fat.erste-group.net:30291", map.get("frontend_name"));
        assertEquals("lb-geredis.fat.erste-group.net:30291", map.get("backend_name"));
        assertEquals("appredisf1.eb.lan.at:6379", map.get("server_name"));
        assertEquals("33", map.get("time_request"));
        assertEquals("0", map.get("time_queue"));
        assertEquals("3", map.get("time_backend_connect"));
        assertEquals("66", map.get("time_backend_response"));
        assertEquals("103", map.get(TIME_DURATION));
        assertEquals("200", map.get(HTTP_STATUS_CODE));
        assertEquals("14583", map.get(BYTES_READ));
        assertEquals("38", map.get("actconn"));
        assertEquals("9", map.get("feconn"));
        assertEquals("1", map.get("beconn"));
        assertEquals("2", map.get("srvconn"));
        assertEquals("0", map.get("retries"));
        assertEquals("0", map.get("srv_queue"));
        assertEquals("0", map.get("backend_queue"));
        assertEquals("application/json; charset=utf-8||de-DE,de;q=0.8,en-US;q=0.6,en;q=0.4|lb-geapi.fat.erste-group.net:30012|https://george.fat.sparkasse.at/index.html?isfirsttime=true?at=c|10.195.162.204|bbc63ff2-27a4-9bb4-600e-0d08d720fba1|400775318|georgeclient", map.get("HAPROXYCAPTUREDREQUESTHEADERS"));
        assertEquals("||application/json|appngf3", map.get("HAPROXYCAPTUREDRESPONSEHEADERS"));
        assertEquals("GET", map.get(HTTP_VERB));
        assertEquals("/frontend-api/api/my/transactions?pageSize=50&id=C24329BA6E644424&_=1465980319501", map.get(HTTP_REQUEST));
        assertEquals("1.1", map.get(HTTP_VERSION));
    }


    @Test
    public void shouldParseAcceptDate() throws Exception {
        final SimpleDateFormat simpleDateFormat = new java.text.SimpleDateFormat("dd/MMM/yyyy:HH:mm:ss.SSS", java.util.Locale.ENGLISH);
        final Date date = simpleDateFormat.parse("15/Jun/2016:10:45:41.835");
        assertNotNull(date);
    }

    private Grok grok() throws Exception {
        return Grok.create(GROK_PATTERN_PATH, GROK_EXPRESSION);
    }


    private Grok grok(String grokExpression) throws Exception {
        return Grok.create(GROK_PATTERN_PATH, grokExpression);
    }

    private Map<String, Object> apply(final Grok grok, final String line) {
        final Match gm = grok.match(line);
        gm.captures();
        return gm.toMap();
    }
}
