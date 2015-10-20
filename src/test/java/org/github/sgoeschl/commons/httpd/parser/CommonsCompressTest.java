package org.github.sgoeschl.commons.httpd.parser;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;

import org.apache.commons.compress.compressors.CompressorInputStream;
import org.apache.commons.compress.compressors.CompressorStreamFactory;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class CommonsCompressTest
{
    @Test
    public void shouldStreamGzipCompressedFile() throws Exception
    {
        String line;
        File logFile = new File("./src/test/data/access.log.gz");
        FileInputStream fileInputStream = new FileInputStream(logFile);
        BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);
        CompressorInputStream compressedInputStream = new CompressorStreamFactory().createCompressorInputStream(bufferedInputStream);
        InputStreamReader inputStreamReader = new InputStreamReader(compressedInputStream);
        BufferedReader reader = new BufferedReader(inputStreamReader);

        while ((line = reader.readLine()) != null) {
            assertTrue(line.contains("localhost"));
        }

        reader.close();
    }

    @Test
    public void shouldStreamBzip2CompressedFile() throws Exception
    {
        String line;
        File logFile = new File("./src/test/data/access.log.bz2");
        FileInputStream fileInputStream = new FileInputStream(logFile);
        BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);
        CompressorInputStream compressedInputStream = new CompressorStreamFactory().createCompressorInputStream(bufferedInputStream);
        InputStreamReader inputStreamReader = new InputStreamReader(compressedInputStream);
        BufferedReader reader = new BufferedReader(inputStreamReader);

        while ((line = reader.readLine()) != null) {
            assertTrue(line.contains("localhost"));
        }

        reader.close();
    }
}
