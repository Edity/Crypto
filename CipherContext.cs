using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace CryptoLab
{
    public class CipherContext
    {
        private readonly ISymmetricCipher _cipher;
        private readonly CipherMode _mode;
        private readonly PaddingMode _padding;

        private int _zerosPaddingLength;
        private readonly byte[] _iv;

        public CipherContext(ISymmetricCipher cipher, byte[] key, CipherMode mode, PaddingMode padding, byte[]? iv = null)
        {
            _cipher = cipher;
            _cipher.SetupKeys(key);
            _mode = mode;
            _padding = padding;
            _iv = iv ?? new byte[_cipher.BlockSize];
        }

        public async Task<byte[]> EncryptAsync(byte[] data)
        {
            return await Task.Run(() =>
            {
                byte[] paddedData = ApplyPadding(data, _cipher.BlockSize, _padding, out _zerosPaddingLength);
                byte[] prevBlock = (byte[])_iv.Clone();
                byte[] prevXor = (byte[])_iv.Clone();
                long globalBlockIndex = 0;
                return ProcessChunk(paddedData, true, ref prevBlock, ref prevXor, ref globalBlockIndex);
            });
        }

        public async Task<byte[]> DecryptAsync(byte[] data)
        {
            return await Task.Run(() =>
            {
                byte[] prevBlock = (byte[])_iv.Clone();
                byte[] prevXor = (byte[])_iv.Clone();
                long globalBlockIndex = 0;
                byte[] decryptedPadded = ProcessChunk(data, false, ref prevBlock, ref prevXor, ref globalBlockIndex);
                return RemovePadding(decryptedPadded, _padding, _zerosPaddingLength);
            });
        }

        public async Task EncryptFileAsync(string inputFilePath, string outputFilePath, int bufferSize = 4096)
        {
            int blockSize = _cipher.BlockSize;
            bufferSize = Math.Max(blockSize, (bufferSize / blockSize) * blockSize);

            using var inputStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
            using var outputStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);

            byte[] buffer = new byte[bufferSize];
            byte[] prevBlock = (byte[])_iv.Clone();
            byte[] prevXor = (byte[])_iv.Clone();
            long globalBlockIndex = 0;

            if (inputStream.Length == 0)
            {
                byte[] padded = ApplyPadding(Array.Empty<byte>(), _cipher.BlockSize, _padding, out _zerosPaddingLength);
                byte[] processed = ProcessChunk(padded, true, ref prevBlock, ref prevXor, ref globalBlockIndex);
                await outputStream.WriteAsync(processed, 0, processed.Length);
                return;
            }

            int bytesRead;
            while ((bytesRead = await inputStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
            {
                bool isLastChunk = inputStream.Position == inputStream.Length;
                byte[] chunkToProcess;
                if (isLastChunk)
                {
                    byte[] exactData = new byte[bytesRead];
                    Array.Copy(buffer, 0, exactData, 0, bytesRead);
                    chunkToProcess = ApplyPadding(exactData, blockSize, _padding, out _zerosPaddingLength);
                }
                else
                {
                    chunkToProcess = new byte[bytesRead];
                    Array.Copy(buffer, 0, chunkToProcess, 0, bytesRead);
                }

                byte[] processed = ProcessChunk(chunkToProcess, true, ref prevBlock, ref prevXor, ref globalBlockIndex);
                await outputStream.WriteAsync(processed, 0, processed.Length);
            }
        }

        public async Task DecryptFileAsync(string inputFilePath, string outputFilePath, int bufferSize = 4096)
        {
            int blockSize = _cipher.BlockSize;
            bufferSize = Math.Max(blockSize, (bufferSize / blockSize) * blockSize);

            using var inputStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
            using var outputStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);

            byte[] buffer = new byte[bufferSize];
            byte[] prevBlock = (byte[])_iv.Clone();
            byte[] prevXor = (byte[])_iv.Clone();
            long globalBlockIndex = 0;

            int bytesRead;
            while ((bytesRead = await inputStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
            {
                bool isLastChunk = inputStream.Position == inputStream.Length;
                byte[] chunkToProcess = new byte[bytesRead];
                Array.Copy(buffer, 0, chunkToProcess, 0, bytesRead);

                byte[] processed = ProcessChunk(chunkToProcess, false, ref prevBlock, ref prevXor, ref globalBlockIndex);
                if (isLastChunk)
                    processed = RemovePadding(processed, _padding);

                await outputStream.WriteAsync(processed, 0, processed.Length);
            }
        }

        private byte[] ProcessChunk(byte[] data, bool isEncrypting, ref byte[] prevBlock, ref byte[] prevXor, ref long globalBlockIndex)
        {
            int blockSize = _cipher.BlockSize;
            int blockCount = data.Length / blockSize;
            byte[] result = new byte[data.Length];

            for (int i = 0; i < blockCount; i++)
            {
                byte[] block = new byte[blockSize];
                Array.Copy(data, i * blockSize, block, 0, blockSize);

                switch (_mode)
                {
                    case CipherMode.ECB:
                    {
                        byte[] processed = isEncrypting ? _cipher.EncryptBlock(block) : _cipher.DecryptBlock(block);
                        Array.Copy(processed, 0, result, i * blockSize, blockSize);
                        break;
                    }
                    case CipherMode.CBC:
                    {
                        if (isEncrypting)
                        {
                            byte[] xored = BitUtils.Xor(block, prevBlock);
                            byte[] enc = _cipher.EncryptBlock(xored);
                            Array.Copy(enc, 0, result, i * blockSize, blockSize);
                            prevBlock = enc;
                        }
                        else
                        {
                            byte[] dec = _cipher.DecryptBlock(block);
                            byte[] xored = BitUtils.Xor(dec, prevBlock);
                            Array.Copy(xored, 0, result, i * blockSize, blockSize);
                            prevBlock = block;
                        }
                        break;
                    }
                    case CipherMode.PCBC:
                    {
                        if (isEncrypting)
                        {
                            byte[] xored = BitUtils.Xor(block, prevXor);
                            byte[] enc = _cipher.EncryptBlock(xored);
                            Array.Copy(enc, 0, result, i * blockSize, blockSize);
                            prevXor = BitUtils.Xor(block, enc);
                        }
                        else
                        {
                            byte[] dec = _cipher.DecryptBlock(block);
                            byte[] plain = BitUtils.Xor(dec, prevXor);
                            Array.Copy(plain, 0, result, i * blockSize, blockSize);
                            prevXor = BitUtils.Xor(plain, block);
                        }
                        break;
                    }
                    case CipherMode.CFB:
                    {
                        byte[] encShift = _cipher.EncryptBlock(prevBlock);
                        byte[] xored = BitUtils.Xor(block, encShift);
                        Array.Copy(xored, 0, result, i * blockSize, blockSize);
                        prevBlock = isEncrypting ? xored : block;
                        break;
                    }
                    case CipherMode.OFB:
                    {
                        prevBlock = _cipher.EncryptBlock(prevBlock);
                        byte[] xored = BitUtils.Xor(block, prevBlock);
                        Array.Copy(xored, 0, result, i * blockSize, blockSize);
                        break;
                    }
                    case CipherMode.CTR:
                    {
                        long currentIdx = globalBlockIndex++;
                        byte[] counter = (byte[])_iv.Clone();
                        for (int j = 0; j < 8 && j < counter.Length; j++)
                            counter[counter.Length - 1 - j] ^= (byte)(currentIdx >> (j * 8));
                        byte[] encCounter = _cipher.EncryptBlock(counter);
                        byte[] xored = BitUtils.Xor(block, encCounter);
                        Array.Copy(xored, 0, result, i * blockSize, blockSize);
                        break;
                    }
                    case CipherMode.RandomDelta:
                    {
                        long currentIdx = globalBlockIndex++;
                        byte[] delta = _cipher.EncryptBlock(_iv);
                        byte[] v = AddDelta((byte[])_iv.Clone(), delta, currentIdx);
                        byte[] encV = _cipher.EncryptBlock(v);
                        byte[] xored = BitUtils.Xor(block, encV);
                        Array.Copy(xored, 0, result, i * blockSize, blockSize);
                        break;
                    }
                }
            }
            return result;
        }

        private static byte[] AddDelta(byte[] baseVector, byte[] delta, long multiplier)
        {
            byte[] result = (byte[])baseVector.Clone();
            ulong carry = 0;
            for (int j = result.Length - 1; j >= 0; j--)
            {
                ulong term = (ulong)delta[j] * (ulong)multiplier + carry;
                ulong sum = (ulong)result[j] + (term & 0xFF);
                result[j] = (byte)sum;
                carry = (term >> 8) + (sum >> 8);
            }
            return result;
        }

        private static byte[] ApplyPadding(
            byte[] data,
            int blockSize,
            PaddingMode mode,
            out int zerosPaddingLength)
        {
            int paddingLength = blockSize - (data.Length % blockSize);

            if (paddingLength == 0)
                paddingLength = blockSize;

            byte[] padded = new byte[data.Length + paddingLength];

            Array.Copy(data, 0, padded, 0, data.Length);

            zerosPaddingLength = mode == PaddingMode.Zeros
                ? paddingLength
                : 0;

            switch (mode)
            {
                case PaddingMode.PKCS7:
                    for (int i = data.Length; i < padded.Length; i++)
                        padded[i] = (byte)paddingLength;
                    break;

                case PaddingMode.ANSIX923:
                    padded[padded.Length - 1] = (byte)paddingLength;
                    break;

                case PaddingMode.ISO10126:
                    using (var rng = RandomNumberGenerator.Create())
                    {
                        byte[] randomBytes = new byte[paddingLength - 1];
                        rng.GetBytes(randomBytes);

                        Array.Copy(
                            randomBytes, 0,
                            padded, data.Length,
                            randomBytes.Length);
                    }

                    padded[padded.Length - 1] = (byte)paddingLength;
                    break;

                case PaddingMode.Zeros:
                    break;

                default:
                    throw new ArgumentOutOfRangeException(nameof(mode));
            }

            return padded;
        }

        private static byte[] RemovePadding(
            byte[] data,
            PaddingMode mode,
            int zerosPaddingLength = 0)
        {
            if (data.Length == 0)
                return data;

            if (mode == PaddingMode.Zeros)
            {
                if (zerosPaddingLength < 0 ||
                    zerosPaddingLength > data.Length)
                {
                    throw new CryptographicException(
                        "Некорректная длина Zeros padding.");
                }

                int length = data.Length - zerosPaddingLength;

                byte[] result = new byte[length];
                Array.Copy(data, 0, result, 0, length);

                return result;
            }

            if (mode == PaddingMode.PKCS7 ||
                mode == PaddingMode.ANSIX923 ||
                mode == PaddingMode.ISO10126)
            {
                int paddingLength = data[data.Length - 1];

                if (paddingLength <= 0 ||
                    paddingLength > data.Length)
                {
                    throw new CryptographicException(
                        "Некорректное дополнение.");
                }

                if (mode == PaddingMode.PKCS7)
                {
                    for (int i = data.Length - paddingLength;
                        i < data.Length; i++)
                    {
                        if (data[i] != paddingLength)
                        {
                            throw new CryptographicException(
                                "Некорректное дополнение PKCS7.");
                        }
                    }
                }

                if (mode == PaddingMode.ANSIX923)
                {
                    for (int i = data.Length - paddingLength;
                        i < data.Length - 1; i++)
                    {
                        if (data[i] != 0)
                        {
                            throw new CryptographicException(
                                "Некорректное дополнение ANSIX923.");
                        }
                    }
                }

                byte[] unpadded = new byte[data.Length - paddingLength];

                Array.Copy(data, 0, unpadded, 0, unpadded.Length);

                return unpadded;
            }

            throw new ArgumentOutOfRangeException(nameof(mode));
        }
    }
}
