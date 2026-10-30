using System;

namespace CryptoLab
{
    public static class BitUtils
    {
        public static byte[] PermuteBits(byte[] input, int[] pBox, BitIndexingRule rule, int startIndex)
        {
            int bitCount = pBox.Length;
            byte[] result = new byte[(bitCount + 7) / 8];

            for (int i = 0; i < bitCount; i++)
            {
                int sourceBitIndex = pBox[i] - startIndex;
                int sourceByteIndex = sourceBitIndex / 8;
                int sourceBitOffset = sourceBitIndex % 8;

                if (sourceByteIndex >= input.Length) continue;

                bool bitValue = (rule == BitIndexingRule.MsbToLsb)
                    ? (input[sourceByteIndex] & (1 << (7 - sourceBitOffset))) != 0
                    : (input[sourceByteIndex] & (1 << sourceBitOffset)) != 0;

                if (bitValue)
                {
                    int targetByteIndex = i / 8;
                    int targetBitOffset = i % 8;
                    if (rule == BitIndexingRule.MsbToLsb)
                        result[targetByteIndex] |= (byte)(1 << (7 - targetBitOffset));
                    else
                        result[targetByteIndex] |= (byte)(1 << targetBitOffset);
                }
            }
            return result;
        }

        public static byte[] Xor(byte[] a, byte[] b)
        {
            int len = Math.Min(a.Length, b.Length);
            byte[] res = new byte[len];
            for (int i = 0; i < len; i++)
                res[i] = (byte)(a[i] ^ b[i]);
            return res;
        }
    }
}
