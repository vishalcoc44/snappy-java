// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package org.xerial.snappy.fuzz;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.xerial.snappy.Snappy;
import org.xerial.snappy.SnappyFramedInputStream;
import org.xerial.snappy.SnappyFramedOutputStream;
import org.xerial.snappy.SnappyInputStream;
import org.xerial.snappy.SnappyOutputStream;
import org.xerial.snappy.SnappyHadoopCompatibleOutputStream;
import org.xerial.snappy.BitShuffle;
import org.xerial.snappy.PureJavaCrc32C;
import java.nio.ByteBuffer;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

public class SnappyCombinedFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        int selector = data.consumeInt(0, 7);
        switch (selector) {
            case 0:
                testRawApi(data);
                break;
            case 1:
                testFramed(data);
                break;
            case 2:
                testCrc32C(data);
                break;
            case 3:
                testBlockStream(data);
                break;
            case 4:
                testUtil(data);
                break;
            case 5:
                testBitShuffle(data);
                break;
            case 6:
                testHadoopStream(data);
                break;
            case 7:
                testByteBuffer(data);
                break;
        }
    }

    private static void testRawApi(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        
        try {
            byte[] compressed = Snappy.compress(input);
            byte[] uncompressed = Snappy.uncompress(compressed);
            if (!Arrays.equals(input, uncompressed)) {
                throw new IllegalStateException("Raw compress/uncompress failed");
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        
        try {
            byte[] rawCompressed = Snappy.rawCompress(input, input.length);
            int uncompressedLen = Snappy.uncompressedLength(rawCompressed);
            byte[] rawUncompressed = new byte[uncompressedLen];
            Snappy.rawUncompress(rawCompressed, 0, rawCompressed.length, rawUncompressed, 0);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        
        try {
            Snappy.isValidCompressedBuffer(input);
            Snappy.isValidCompressedBuffer(input, 0, input.length);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        
        try {
            int maxLen = Snappy.maxCompressedLength(input.length);
            if (maxLen < input.length) {
                throw new IllegalStateException("maxCompressedLength too small");
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        
        try {
            byte[] compressed = Snappy.compress(input);
            int len = Snappy.uncompressedLength(compressed);
            int len2 = Snappy.uncompressedLength(compressed, 0, compressed.length);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        
        try {
            int[] intInput = data.consumeInts(100);
            byte[] compressedInts = Snappy.compress(intInput);
            int[] uncompressedInts = Snappy.uncompressIntArray(compressedInts);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        
        try {
            long[] longInput = data.consumeLongs(50);
            byte[] compressedLongs = Snappy.compress(longInput);
            long[] uncompressedLongs = Snappy.uncompressLongArray(compressedLongs);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static void testFramed(FuzzedDataProvider data) {
        byte[] original = data.consumeRemainingAsBytes();
        
        try {
            ByteArrayOutputStream compressedBuf = new ByteArrayOutputStream();
            SnappyFramedOutputStream framedOut = new SnappyFramedOutputStream(compressedBuf);
            framedOut.write(original);
            framedOut.close();
            byte[] compressed = compressedBuf.toByteArray();
            
            for (int bufferSize : new int[]{1, 64, 256, 1024, 4096}) {
                try (SnappyFramedInputStream framedIn = new SnappyFramedInputStream(
                    new ByteArrayInputStream(compressed), true)) {
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    byte[] buf = new byte[bufferSize];
                    int readBytes;
                    while ((readBytes = framedIn.read(buf)) != -1) {
                        out.write(buf, 0, readBytes);
                    }
                    out.flush();
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        
        try (SnappyFramedInputStream invalidIn = new SnappyFramedInputStream(
            new ByteArrayInputStream(data.consumeBytes(100)))) {
            while (invalidIn.read() != -1) {}
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void testCrc32C(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        PureJavaCrc32C crc = new PureJavaCrc32C();
        
        crc.update(input, 0, input.length);
        long value = crc.getValue();
        
        int intValue = crc.getIntegerValue();
        
        crc.reset();
        crc.update(input, 0, input.length);
        long value2 = crc.getValue();
        
        PureJavaCrc32C crcChunked = new PureJavaCrc32C();
        for (int i = 0; i < Math.min(input.length, 1000); i++) {
            crcChunked.update(input[i] & 0xFF);
        }
        
        if (input.length > 2) {
            byte[] partial1 = data.consumeBytes(Math.min(10, input.length));
            byte[] partial2 = data.consumeBytes(Math.min(10, input.length));
            
            PureJavaCrc32C crc1 = new PureJavaCrc32C();
            crc1.update(input, 0, input.length);
            
            PureJavaCrc32C crc2 = new PureJavaCrc32C();
            crc2.update(partial1, 0, partial1.length);
            crc2.update(partial2, 0, partial2.length);
        }
        
        PureJavaCrc32C crcEmpty = new PureJavaCrc32C();
        crcEmpty.update(new byte[0], 0, 0);
        long emptyValue = crcEmpty.getValue();
        
        if (input.length > 0) {
            PureJavaCrc32C crcSingle = new PureJavaCrc32C();
            crcSingle.update(input[0] & 0xFF);
        }
        
        if (input.length > 4) {
            PureJavaCrc32C crcOffset = new PureJavaCrc32C();
            crcOffset.update(input, 1, input.length - 1);
        }
    }

    private static void testBlockStream(FuzzedDataProvider data) {
        byte[] original = data.consumeRemainingAsBytes();
        
        try {
            ByteArrayOutputStream compressedBuf = new ByteArrayOutputStream();
            SnappyOutputStream out = new SnappyOutputStream(compressedBuf, -1);
            out.write(original);
            out.close();
            byte[] compressed = compressedBuf.toByteArray();
            
            try (SnappyInputStream in = new SnappyInputStream(new ByteArrayInputStream(compressed))) {
                ByteArrayOutputStream result = new ByteArrayOutputStream();
                byte[] buf = new byte[1024];
                int read;
                while ((read = in.read(buf)) != -1) {
                    result.write(buf, 0, read);
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        
        try (SnappyInputStream in = new SnappyInputStream(new ByteArrayInputStream(data.consumeBytes(100)))) {
            while (in.read() != -1) {}
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static void testUtil(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        
        try {
            String str = new String(input, java.nio.charset.StandardCharsets.UTF_8);
            byte[] compressed = Snappy.compress(str);
            String uncompressed = Snappy.uncompressString(compressed);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        
        try {
            int maxLen = Snappy.maxCompressedLength(input.length);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        
        try {
            short[] shortInput = new short[Math.min(100, input.length / 2)];
            for (int i = 0; i < shortInput.length; i++) {
                shortInput[i] = (short) data.consumeInt();
            }
            byte[] compressedShorts = Snappy.compress(shortInput);
            short[] uncompressedShorts = Snappy.uncompressShortArray(compressedShorts);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        
        try {
            char[] charInput = new char[Math.min(100, input.length)];
            for (int i = 0; i < charInput.length; i++) {
                charInput[i] = (char) data.consumeInt();
            }
            byte[] compressedChars = Snappy.compress(charInput);
            char[] uncompressedChars = Snappy.uncompressCharArray(compressedChars);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static void testBitShuffle(FuzzedDataProvider data) {
        try {
            int[] intInput = data.consumeInts(100);
            byte[] shuffled = BitShuffle.shuffle(intInput);
            int[] unshuffled = BitShuffle.unshuffleIntArray(shuffled);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        
        try {
            long[] longInput = data.consumeLongs(50);
            byte[] shuffled = BitShuffle.shuffle(longInput);
            long[] unshuffled = BitShuffle.unshuffleLongArray(shuffled);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        
        try {
            short[] shortInput = data.consumeShorts(100);
            byte[] shuffled = BitShuffle.shuffle(shortInput);
            short[] unshuffled = BitShuffle.unshuffleShortArray(shuffled);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static void testHadoopStream(FuzzedDataProvider data) {
        byte[] original = data.consumeRemainingAsBytes();
        
        try {
            ByteArrayOutputStream compressedBuf = new ByteArrayOutputStream();
            SnappyHadoopCompatibleOutputStream out = new SnappyHadoopCompatibleOutputStream(compressedBuf);
            out.write(original);
            out.close();
            byte[] compressed = compressedBuf.toByteArray();
            
            try (SnappyInputStream in = new SnappyInputStream(
                new ByteArrayInputStream(compressed))) {
                ByteArrayOutputStream result = new ByteArrayOutputStream();
                byte[] buf = new byte[1024];
                int read;
                while ((read = in.read(buf)) != -1) {
                    result.write(buf, 0, read);
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static void testByteBuffer(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        
        try {
            ByteBuffer src = ByteBuffer.allocateDirect(input.length);
            src.put(input);
            src.flip();
            ByteBuffer dst = ByteBuffer.allocateDirect(Snappy.maxCompressedLength(input.length));
            int compressed = Snappy.compress(src, dst);
            
            dst.limit(compressed);
            dst.position(0);
            ByteBuffer uncompressedBuf = ByteBuffer.allocateDirect(input.length);
            int uncompressed = Snappy.uncompress(dst, uncompressedBuf);
            
            uncompressedBuf.limit(uncompressed);
            uncompressedBuf.position(0);
            byte[] result = new byte[uncompressed];
            uncompressedBuf.get(result);
            
            if (!Arrays.equals(input, result)) {
                throw new IllegalStateException("ByteBuffer compress failed");
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        
        try {
            ByteBuffer directSrc = ByteBuffer.allocateDirect(input.length);
            directSrc.put(input);
            directSrc.flip();
            
            ByteBuffer directDst = ByteBuffer.allocateDirect(Snappy.maxCompressedLength(input.length));
            Snappy.compress(directSrc, directDst);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
