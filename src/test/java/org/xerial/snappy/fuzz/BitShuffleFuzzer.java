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
import org.xerial.snappy.BitShuffle;
import java.util.Arrays;

public class BitShuffleFuzzer {
  private static final int SIZE = 4096;

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    fuzzBitshuffleInts(data.consumeInts(SIZE));
    fuzzBitshuffleLongs(data.consumeLongs(SIZE));
    fuzzBitshuffleShorts(data.consumeShorts(SIZE));
  }

  private static void runFuzz(RunnableWithException block) {
    try {
      block.run();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @FunctionalInterface
  private interface RunnableWithException {
    void run() throws Exception;
  }

  private static void fuzzBitshuffleInts(int[] original) {
    runFuzz(() -> {
      byte[] shuffledByteArray = BitShuffle.shuffle(original);
      byte[] compressed = Snappy.compress(shuffledByteArray);
      byte[] uncompressed = Snappy.uncompress(compressed);
      int[] result = BitShuffle.unshuffleIntArray(uncompressed);
      if (!Arrays.equals(original, result)) {
        throw new IllegalStateException("Original and uncompressed data are different");
      }
    });
  }

  private static void fuzzBitshuffleLongs(long[] original) {
    runFuzz(() -> {
      byte[] shuffledByteArray = BitShuffle.shuffle(original);
      byte[] compressed = Snappy.compress(shuffledByteArray);
      byte[] uncompressed = Snappy.uncompress(compressed);
      long[] result = BitShuffle.unshuffleLongArray(uncompressed);
      if (!Arrays.equals(original, result)) {
        throw new IllegalStateException("Original and uncompressed data are different");
      }
    });
  }

  private static void fuzzBitshuffleShorts(short[] original) {
    runFuzz(() -> {
      byte[] shuffledByteArray = BitShuffle.shuffle(original);
      byte[] compressed = Snappy.compress(shuffledByteArray);
      byte[] uncompressed = Snappy.uncompress(compressed);
      short[] result = BitShuffle.unshuffleShortArray(uncompressed);
      if (!Arrays.equals(original, result)) {
        throw new IllegalStateException("Original and uncompressed data are different");
      }
    });
  }
}
