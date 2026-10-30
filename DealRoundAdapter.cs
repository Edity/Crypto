using System;

namespace CryptoLab
{
    public class DealRoundAdapter : IRoundFunction
    {
        private readonly ISymmetricCipher _desCipher;
        private readonly object _lock = new object();

        public DealRoundAdapter(ISymmetricCipher desCipher)
        {
            _desCipher = desCipher;
        }

        public byte[] Transform(byte[] inputBlock, byte[] roundKey)
        {
            lock (_lock)
            {
                _desCipher.SetupKeys(roundKey);
                return _desCipher.EncryptBlock(inputBlock);
            }
        }
    }
}
