namespace CryptoLab
{
    public interface IRoundFunction
    {
        byte[] Transform(byte[] inputBlock, byte[] roundKey);
    }
}
