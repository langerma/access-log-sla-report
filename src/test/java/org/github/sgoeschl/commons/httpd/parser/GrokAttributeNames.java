package org.github.sgoeschl.commons.httpd.parser;

/**
 * Created by sgoeschl on 04.07.16.
 */
public interface GrokAttributeNames {

    String CLIENT_IP = "client_ip";
    String IDENT = "ident";
    String AUTHENTICATION = "auth";
    String TIMESTAMP = "timestamp";
    String HTTP_VERB = "http_verb";
    String HTTP_REQUEST = "http_request";
    String HTTP_VERSION = "http_version";
    String HTTP_STATUS_CODE = "http_status_code";
    String BYTES_READ = "bytes_read";
    String REFERRER = "referrer";
    String HTTP_USER_AGENT = "agent";
    String TIME_DURATION = "time_duration";
}
