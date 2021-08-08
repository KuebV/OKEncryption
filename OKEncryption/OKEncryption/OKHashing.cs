using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace OKEncryption
{
    public enum EncryptionMethod
    {
        SHA256 = 1,
        MD5 = 2,
        SHA512 = 3
    }
    public class OKHashing
    {
        EncryptionMethod encryptionMethod;

        /// <summary>
        /// Takes parameter enumerator Encryption Method.
        /// </summary>
        /// <param name="encryption"></param>
        public OKHashing(EncryptionMethod encryption) => encryptionMethod = encryption;

        public string HashString(string unencryptedText)
        {
            switch (encryptionMethod)
            {
                case EncryptionMethod.SHA256:
                    using (SHA256 hash256 = SHA256.Create())
                    {
                        byte[] bytes = hash256.ComputeHash(Encoding.UTF8.GetBytes(unencryptedText));
                        StringBuilder builder = new StringBuilder();
                        for (int i = 0; i < bytes.Length; i++)
                            builder.Append(bytes[i].ToString("x2"));
                        return builder.ToString();
                    }
                case EncryptionMethod.SHA512:
                    using (SHA512 hash512 = SHA512.Create())
                    {
                        byte[] bytes = hash512.ComputeHash(Encoding.UTF8.GetBytes(unencryptedText));
                        StringBuilder builder = new StringBuilder();
                        for (int i = 0; i < bytes.Length; i++)
                            builder.Append(bytes[i].ToString("x2"));
                        return builder.ToString();
                    }
                case EncryptionMethod.MD5:
                    using (MD5 hash512 = MD5.Create())
                    {
                        byte[] bytes = hash512.ComputeHash(Encoding.UTF8.GetBytes(unencryptedText));
                        StringBuilder builder = new StringBuilder();
                        for (int i = 0; i < bytes.Length; i++)
                            builder.Append(bytes[i].ToString("x2"));
                        return builder.ToString();
                    }

            }

            return null;
        }
    }
}
