using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace CryptoLab
{
    internal class Program
    {
        private static async Task Main(string[] args)
        {
            ISymmetricCipher des = new DesCipher();
            byte[] desKey = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
            byte[] iv = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF };
            string testMessage = "Привет хай здарова хело добрый вечер коничива";
            byte[] originalData = Encoding.UTF8.GetBytes(testMessage);

            Console.WriteLine($"Начальное сообщение: \"{testMessage}\"\n");

            foreach (CipherMode mode in Enum.GetValues(typeof(CipherMode)))
            {
                foreach (PaddingMode pad in Enum.GetValues(typeof(PaddingMode)))
                {
                    CipherContext ctx = new CipherContext(des, desKey, mode, pad, iv);
                    byte[] encrypted = await ctx.EncryptAsync(originalData);
                    byte[] decrypted = await ctx.DecryptAsync(encrypted);
                    string resultText = Encoding.UTF8.GetString(decrypted);
                    bool isSuccess = resultText == testMessage;
                    Console.WriteLine($"Режим {mode}: {resultText} (успех: {isSuccess})");
                    Console.WriteLine($"Режим {mode}: {encrypted.Length} {decrypted.Length}");
                }
            }
            CipherContext ctx1 = new CipherContext(des, desKey, CipherMode.CBC, PaddingMode.Zeros, iv);
            byte[] originalData1 = { 0, 0, 0, 0, 0, 0, 0};

            byte[] encrypted1 = await ctx1.EncryptAsync(originalData1);
            byte[] decrypted1 = await ctx1.DecryptAsync(encrypted1);
            Console.WriteLine(originalData1.Length);
            Console.WriteLine(encrypted1.Length);
            Console.WriteLine(decrypted1.Length);

            // string testFile = "demo_input.txt";
            // string encFile = "demo_encrypted.bin";
            // string decFile = "demo_output.txt";
            // CipherContext fileCtx = new CipherContext(des, desKey, CipherMode.PCBC, PaddingMode.PKCS7, iv);

            // StringBuilder largeContent = new StringBuilder();
            // for (int i = 0; i < 30; i++)
            //     largeContent.AppendLine("fakdkajwnfkawndlanwdlnawlfnawlfknalwkfnalwkfnm");

            // await File.WriteAllTextAsync(testFile, largeContent.ToString());
            // await fileCtx.EncryptFileAsync(testFile, encFile, bufferSize: 64);
            // await fileCtx.DecryptFileAsync(encFile, decFile, bufferSize: 64);

            // string originalText = await File.ReadAllTextAsync(testFile);
            // string decryptedText = await File.ReadAllTextAsync(decFile);
            // Console.WriteLine(originalText == decryptedText
            //     ? "Проверка файла успешна!"
            //     : "Ошибка при проверке файла.");

            // if (File.Exists(testFile)) File.Delete(testFile);
            // if (File.Exists(encFile)) File.Delete(encFile);
            // if (File.Exists(decFile)) File.Delete(decFile);
            // await fileCtx.EncryptFileAsync("IMG_1596.jpg", "IMG_1596.enc");
            // await fileCtx.DecryptFileAsync("IMG_1596.enc", "IMG_1596_dec.jpg");

            // await fileCtx.EncryptFileAsync("3_anim.mp4", "3_anim.enc");
            // await fileCtx.DecryptFileAsync("3_anim.enc", "3_anim_dec.mp4");
        }
    }
}
