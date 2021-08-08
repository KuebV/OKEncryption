using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

namespace OKEncryption
{
    public class OKEncryption
    {
        private int ByteInterations;
        private int Keysize;

        // Define the Keysize & ByteInterations
        // Should be noted that Keysize must be divided by 8
        public OKEncryption(int keysize, int byteinterations)
        {
            ByteInterations = byteinterations;
            if ((keysize / 8).GetType() == typeof(float))
            {
                Console.WriteLine("[OKEncryption] Keysize must be divisable by 8 !\n[OKEncryption] Setting default to 256");
                Keysize = 256;
            }
            else if ((keysize / 8).GetType() == typeof(int))
                Keysize = keysize;
        }

        private static byte[] GenerateRandomBytes()
        {
            var randomBytes = new byte[64]; 
            using (var rngCsp = new RNGCryptoServiceProvider())
                rngCsp.GetBytes(randomBytes);

            return randomBytes;
        }

        /// <summary>
        /// Key string acts like a Key to decrypt the encrypted string
        /// </summary>
        /// <param name="Keystring"></param>
        /// <param name="encryptedString"></param>
        /// <returns>Unencrypted String</returns>
        public string DecryptString(string Keystring, string encryptedString)
        {
            var cipherTextBytesWithSaltAndIv = Convert.FromBase64String(encryptedString);
            var saltString = cipherTextBytesWithSaltAndIv.Take(Keysize / 8).ToArray();
            var stringBytes = cipherTextBytesWithSaltAndIv.Skip(Keysize / 8).Take(Keysize / 8).ToArray();
            var cipherTextBytes = cipherTextBytesWithSaltAndIv.Skip((Keysize / 8) * 2).Take(cipherTextBytesWithSaltAndIv.Length - ((Keysize / 8) * 2)).ToArray();

            using (var password = new Rfc2898DeriveBytes(Keystring, saltString, ByteInterations))
            {
                var keyBytes = password.GetBytes(Keysize / 8);
                using (var symmetricKey = new RijndaelManaged())
                {
                    symmetricKey.BlockSize = Keysize;
                    symmetricKey.Mode = CipherMode.CBC;
                    symmetricKey.Padding = PaddingMode.PKCS7;
                    using (var decryptor = symmetricKey.CreateDecryptor(keyBytes, stringBytes))
                    {
                        using (var memoryStream = new MemoryStream(cipherTextBytes))
                        {
                            using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                            {
                                var plainTextBytes = new byte[cipherTextBytes.Length];
                                var decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                                memoryStream.Close();
                                cryptoStream.Close();
                                return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
                            }
                        }
                    }
                }
            }
        }

        public string EncryptString(string KeyString, string rawText)
        {
            var saltStrings = GenerateRandomBytes();
            var stringBytes = GenerateRandomBytes();
            var rawTextBytes = Encoding.UTF8.GetBytes(rawText);
            using (var pass = new Rfc2898DeriveBytes(KeyString, saltStrings, ByteInterations))
            {
                var keyBytes = pass.GetBytes(Keysize / 8);
                using (var symKey = new RijndaelManaged())
                {
                    symKey.BlockSize = Keysize;
                    symKey.Mode = CipherMode.CBC;
                    symKey.Padding = PaddingMode.PKCS7;
                    using (var encryptor = symKey.CreateEncryptor(keyBytes, stringBytes))
                    {
                        using (var memorystream = new MemoryStream())
                        {
                            using (var cryptoStream = new CryptoStream(memorystream, encryptor, CryptoStreamMode.Write))
                            {
                                cryptoStream.Write(rawTextBytes, 0, rawTextBytes.Length);
                                cryptoStream.Flush();

                                var cipherText = saltStrings;
                                cipherText = cipherText.Concat(cipherText).ToArray();
                                cipherText = cipherText.Concat(memorystream.ToArray()).ToArray();
                                cryptoStream.Flush();
                                memorystream.Flush();
                                return Convert.ToBase64String(cipherText);
                            }
                        }
                    }
                }
            }
        }
    }
}
