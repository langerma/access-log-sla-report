package org.github.sgoeschl.commons.httpd.parser;

import org.junit.Test;

import java.util.regex.Pattern;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Test the regular expression used to differentate between a path & id part of an URL.
 */
public class ResourcePathRegExpTest {

    /** Copy & pasta from the JS */
    private static final Pattern RESOURCE_PATH_PARAMETER_REGEXP = java.util.regex.Pattern.compile("^([a-z]{1,15}+(\\.[a-z]{3,4}|\\d?))$");

    @Test
    public void shouldMatchResourcePath() {
        assertTrue(RESOURCE_PATH_PARAMETER_REGEXP.matcher("transactions").matches());
        assertTrue(RESOURCE_PATH_PARAMETER_REGEXP.matcher("atms").matches());
        assertTrue(RESOURCE_PATH_PARAMETER_REGEXP.matcher("export.csv").matches());
        assertTrue(RESOURCE_PATH_PARAMETER_REGEXP.matcher("export.xlsx").matches());
        assertTrue(RESOURCE_PATH_PARAMETER_REGEXP.matcher("fonts.css").matches());
    }

    @Test
    public void shouldNotMatchResourceIds() {
        assertFalse(RESOURCE_PATH_PARAMETER_REGEXP.matcher("BE56D6184AA9BB1C").matches());
        assertFalse(RESOURCE_PATH_PARAMETER_REGEXP.matcher("S-MOBILE-PROTECT-1").matches());
        assertFalse(RESOURCE_PATH_PARAMETER_REGEXP.matcher("2903243c23586c33353f17370a0d2060PRE").matches());
        assertFalse(RESOURCE_PATH_PARAMETER_REGEXP.matcher("CDB9A904D1295104-CFD68DEAB8F91804").matches());
        assertFalse(RESOURCE_PATH_PARAMETER_REGEXP.matcher("crmImages").matches());
        assertFalse(RESOURCE_PATH_PARAMETER_REGEXP.matcher("user-image").matches());
    }

}
