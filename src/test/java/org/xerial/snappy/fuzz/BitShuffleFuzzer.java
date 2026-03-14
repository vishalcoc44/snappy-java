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
import java.util.Objects;

public class BitShuffleFuzzer {
  private static final int SIZE = 4096;

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    fuzzBitshuffle(data.consumeInts(SIZE), BitShuffle::shuffle, BitShuffle::unshuffleIntArray, "int[]");
    fuzzBitshuffle(data.consumeLongs(SIZE), BitShuffle::shuffle, BitShuffle::unshuffleLongArray, "long[]");
    fuzzBitshuffle(data.consumeShorts(SIZE), BitShuffle::shuffle, BitShuffle::unshuffleShortArray, "short[]");
    fuzzBitshuffle(data.consumeFloats(SIZE), BitShuffle::shuffle, BitShuffle::unshuffleFloatArray, "float[]");
    fuzzBitshuffle(data.consumeDoubles(SIZE), BitShuffle::shuffle, BitShuffle::unshuffleDoubleArray, "double[]");
  }

  @FunctionalInterface
  private interface ShuffleFn<T> {
    byte[] apply(T input) throws Exception;
  }

  @FunctionalInterface
  private interface UnshuffleFn<T> {
    T apply(byte[] input) throws Exception;
  }

  private static <T> void fuzzBitshuffle(T original, ShuffleFn<T> shuffle, UnshuffleFn<T> unshuffle, String typeName) {
    try {
      byte[] shuffledByteArray = shuffle.apply(original);
      byte[] compressed = Snappy.compress(shuffledByteArray);
      byte[] uncompressed = Snappy.uncompress(compressed);
      T result = unshuffle.apply(uncompressed);
      if (!Objects.deepEquals(original, result)) {
        throw new IllegalStateException("Original and uncompressed " + typeName + " data are different");
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
