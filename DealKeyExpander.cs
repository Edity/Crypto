namespace CryptoLab
{
    public class DealKeyExpander : IKeyExpander
    {
        public byte[][] ExpandKey(byte[] inputKey)
        {
            byte[][] keys = new byte[6][];
            for (int i = 0; i < 6; i++)
            {
                keys[i] = new byte[8];
                for (int j = 0; j < 8; j++)
                    keys[i][j] = (byte)(inputKey[j % inputKey.Length] ^ (i * 13 + j));
            }
            return keys;
        }
    }
}
