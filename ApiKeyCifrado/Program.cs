using System;
using System.Text;
using System.IO;
using System.Security.Cryptography;

namespace ApiKeyCifrado
{
    class Program
    {
        static void Main(string[] args)
        {
            string Accion = args[0],
                   Cadena = args[1],
                   Clave = args[2],
                   Resultado = string.Empty;

            //bool Accion = bool.TryParse(args[0], out bool result) ? result : false;

            Clave = ComputeSha256Hash(Clave);
            Clave = Clave.Substring(0, 16);

            if (Accion == "true") Resultado = Encrypt(Cadena, Clave);
            else if (Accion == "false") Resultado = Decrypt(Cadena, Clave);
            else Resultado = "Opcion no valida.";

            Console.WriteLine("{0}", Resultado);
            Console.ReadLine();
        }

        public static string Encrypt(string plainText, string keyString)
        {
            byte[] cipherData;
            Aes aes = Aes.Create();
            aes.Key = Encoding.UTF8.GetBytes(keyString);
            aes.GenerateIV();
            aes.Mode = CipherMode.CBC;
            ICryptoTransform cipher = aes.CreateEncryptor(aes.Key, aes.IV);

            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, cipher, CryptoStreamMode.Write))
                {
                    using (StreamWriter sw = new StreamWriter(cs))
                    {
                        sw.Write(plainText);
                    }
                }
                cipherData = ms.ToArray();
            }

            byte[] combinedData = new byte[aes.IV.Length + cipherData.Length];
            Array.Copy(aes.IV, 0, combinedData, 0, aes.IV.Length);
            Array.Copy(cipherData, 0, combinedData, aes.IV.Length, cipherData.Length);
            return Convert.ToBase64String(combinedData);
        }

        public static string Decrypt(string combinedString, string keyString)
        {
            string plainText;
            byte[] combinedData = Convert.FromBase64String(combinedString);
            Aes aes = Aes.Create();
            aes.Key = Encoding.UTF8.GetBytes(keyString);
            //aes.Key = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
            byte[] iv = new byte[aes.BlockSize / 8];
            byte[] cipherText = new byte[combinedData.Length - iv.Length];
            Array.Copy(combinedData, iv, iv.Length);
            Array.Copy(combinedData, iv.Length, cipherText, 0, cipherText.Length);
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            ICryptoTransform decipher = aes.CreateDecryptor(aes.Key, aes.IV);

            using (MemoryStream ms = new MemoryStream(cipherText))
            {
                using (CryptoStream cs = new CryptoStream(ms, decipher, CryptoStreamMode.Read))
                {
                    using (StreamReader sr = new StreamReader(cs))
                    {
                        plainText = sr.ReadToEnd();
                    }
                }

                return plainText;
            }
        }

        static string ComputeSha256Hash(string rawData)
        {
            // Create a SHA256   
            using (SHA256 sha256Hash = SHA256.Create())
            {
                // ComputeHash - returns byte array  
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));

                // Convert byte array to a string   
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }
    }
}

