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
import java.io.IOException;
import java.util.Arrays;

public class BitShuffleFuzzer {
  private static final int SIZE = 4096;

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    fuzzBitshuffleInts(data.consumeInts(SIZE));
    fuzzBitshuffleLongs(data.consumeLongs(SIZE));
    fuzzBitshuffleShorts(data.consumeShorts(SIZE));
  }

  static void fuzzBitshuffleInts(int[] original) {
    int[] result;

    try {
      byte[] shuffledByteArray = BitShuffle.shuffle(original);
      byte[] compressed = Snappy.compress(shuffledByteArray);
      byte[] uncompressed = Snappy.uncompress(compressed);
      result = BitShuffle.unshuffleIntArray(uncompressed);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }

    if (!Arrays.equals(original, result)) {
      throw new IllegalStateException("Original and uncompressed data are different");
    }
  }

  static void fuzzBitshuffleLongs(long[] original) {
    long[] result;

    try {
      byte[] shuffledByteArray = BitShuffle.shuffle(original);
      byte[] compressed = Snappy.compress(shuffledByteArray);
      byte[] uncompressed = Snappy.uncompress(compressed);
      result = BitShuffle.unshuffleLongArray(uncompressed);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }

    if (!Arrays.equals(original, result)) {
      throw new IllegalStateException("Original and uncompressed data are different");
    }
  }

  static void fuzzBitshuffleShorts(short[] original) {
    short[] result;

    try {
      byte[] shuffledByteArray = BitShuffle.shuffle(original);
      byte[] compressed = Snappy.compress(shuffledByteArray);
      byte[] uncompressed = Snappy.uncompress(compressed);
      result = BitShuffle.unshuffleShortArray(uncompressed);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }

    if (!Arrays.equals(original, result)) {
      throw new IllegalStateException("Original and uncompressed data are different");
    }
  }
}
