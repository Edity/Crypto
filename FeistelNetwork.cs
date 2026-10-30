using System;

namespace CryptoLab
{
    public class FeistelNetwork : ISymmetricCipher
    {
        private readonly IKeyExpander _keyExpander;
        private readonly IRoundFunction _roundFunction;
        private byte[][] _roundKeys = Array.Empty<byte[]>();
        private readonly int _rounds;
        public int BlockSize { get; }

        public FeistelNetwork(IKeyExpander keyExpander, IRoundFunction roundFunction, int blockSize, int rounds)
        {
            _keyExpander = keyExpander;
            _roundFunction = roundFunction;
            BlockSize = blockSize;
            _rounds = rounds;
        }

        public void SetupKeys(byte[] key) => _roundKeys = _keyExpander.ExpandKey(key);
        public byte[] EncryptBlock(byte[] block) => ProcessFeistel(block, false);
        public byte[] DecryptBlock(byte[] block) => ProcessFeistel(block, true);

        private byte[] ProcessFeistel(byte[] block, bool reverseKeys)
        {
            int halfSize = BlockSize / 2;
            byte[] left = new byte[halfSize];
            byte[] right = new byte[halfSize];
            Array.Copy(block, 0, left, 0, halfSize);
            Array.Copy(block, halfSize, right, 0, halfSize);

            for (int i = 0; i < _rounds; i++)
            {
                int keyIndex = reverseKeys ? (_rounds - 1 - i) : i;
                byte[] roundKey = _roundKeys[keyIndex];
                byte[] fResult = _roundFunction.Transform(right, roundKey);
                byte[] newRight = BitUtils.Xor(left, fResult);
                left = right;
                right = newRight;
            }

            byte[] result = new byte[BlockSize];
            Array.Copy(right, 0, result, 0, halfSize);
            Array.Copy(left, 0, result, halfSize, halfSize);
            return result;
        }
    }
}
