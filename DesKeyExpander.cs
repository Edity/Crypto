using System;

namespace CryptoLab
{
    public class DesKeyExpander : IKeyExpander
    {
        private static readonly int[] PC1_C = {
            57, 49, 41, 33, 25, 17, 9, 1,
            58, 50, 42, 34, 26, 18, 10, 2,
            59, 51, 43, 35, 27, 19, 11, 3,
            60, 52, 44, 36
        };
        private static readonly int[] PC1_D = {
            63, 55, 47, 39, 31, 23, 15, 7,
            62, 54, 46, 38, 30, 22, 14, 6,
            61, 53, 45, 37, 29, 21, 13, 5,
            28, 20, 12, 4
        };
        private static readonly int[] Shifts = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
        private static readonly int[] PC2 = {
            14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
        };

        public byte[][] ExpandKey(byte[] inputKey)
        {
            if (inputKey.Length < 8)
                throw new ArgumentException("Ключ DES должен быть длиной 8 байт.");

            uint c = Extract28Bits(inputKey, PC1_C);
            uint d = Extract28Bits(inputKey, PC1_D);
            byte[][] roundKeys = new byte[16][];

            for (int i = 0; i < 16; i++)
            {
                c = ShiftLeft28(c, Shifts[i]);
                d = ShiftLeft28(d, Shifts[i]);
                byte[] cd56 = Combine28Bits(c, d);
                roundKeys[i] = BitUtils.PermuteBits(cd56, PC2, BitIndexingRule.MsbToLsb, 1);
            }
            return roundKeys;
        }

        private static uint Extract28Bits(byte[] input, int[] pcTable)
        {
            uint res = 0;
            for (int i = 0; i < 28; i++)
            {
                int bitIdx = pcTable[i] - 1;
                int byteIdx = bitIdx / 8;
                int bitOffset = bitIdx % 8;
                bool bit = (input[byteIdx] & (1 << (7 - bitOffset))) != 0;
                if (bit) res |= (uint)(1 << (27 - i));
            }
            return res;
        }

        private static uint ShiftLeft28(uint val, int shift) =>
            ((val << shift) | (val >> (28 - shift))) & 0x0FFFFFFF;

        private static byte[] Combine28Bits(uint c, uint d)
        {
            byte[] result = new byte[7];
            ulong combined = ((ulong)c << 28) | d;
            for (int i = 0; i < 7; i++)
                result[i] = (byte)((combined >> (48 - i * 8)) & 0xFF);
            return result;
        }
    }
}
