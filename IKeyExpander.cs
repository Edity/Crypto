namespace CryptoLab
{
    public interface IKeyExpander
    {
        byte[][] ExpandKey(byte[] inputKey);
    }
}
