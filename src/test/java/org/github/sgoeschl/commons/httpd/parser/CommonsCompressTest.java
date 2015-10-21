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
