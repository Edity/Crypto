namespace CryptoLab
{
    public interface ISymmetricCipher
    {
        void SetupKeys(byte[] key);
        byte[] EncryptBlock(byte[] block);
        byte[] DecryptBlock(byte[] block);
        int BlockSize { get; }
    }
}
