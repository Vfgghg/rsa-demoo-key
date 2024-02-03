using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ConsoleApp2 
{
    class Program
    {

        static void Main(string[] args)
        {
            // Specify the paths to your certificate files
            // Specify the paths to your certificate files
            string publicKeyCertificatePath = "C:\\Users\\lenovo\\Downloads\\publicKey.cer";
            string privateKeyCertificatePath = "C:\\Users\\lenovo\\Downloads\\certificates.pfx";
            string privateKeyCertificatePassword = "marwadi"; // Password for the private key certificate

            // Load public key certificate
            X509Certificate2 publicKeyCertificate = new X509Certificate2("C:\\Users\\lenovo\\Downloads\\publicKey.cer");

            // Load private key certificate
            X509Certificate2 privateKeyCertificate= new X509Certificate2("C:\\Users\\lenovo\\Downloads\\certificates.pfx", "marwadi", X509KeyStorageFlags.Exportable);

            // Extract RSA parameters from certificate5555555555555555555555s
            RSAParameters publicKeyParameters = ((RSA)publicKeyCertificate.GetRSAPublicKey()).ExportParameters(false);
            RSAParameters privateKeyParameters = ((RSA)privateKeyCertificate.GetRSAPrivateKey().Decrypt);


            string publicKeyString = GetKeyString(publicKeyParameters);
            string privateKeyString = GetKeyString(privateKeyParameters);

            Console.WriteLine("PUBLIC KEY: ");
            Console.WriteLine(publicKeyString);
            Console.WriteLine("-------------------------------------------");

            Console.WriteLine("PRIVATE KEY: ");
            Console.WriteLine(privateKeyString);
            Console.WriteLine("-------------------------------------------");

            string textToEncrypt = GenerateTestString();
            Console.WriteLine("TEXT TO ENCRYPT: ");
            Console.WriteLine(textToEncrypt);
            Console.WriteLine("-------------------------------------------");

            byte[] encryptedBytes = Encrypt(Encoding.UTF8.GetBytes(textToEncrypt), publicKeyParameters);
            string encryptedText = Convert.ToBase64String(encryptedBytes);
            Console.WriteLine("ENCRYPTED TEXT: ");
            Console.WriteLine(encryptedText);
            Console.WriteLine("-------------------------------------------");

            string decryptedText = Decrypt(Convert.FromBase64String(encryptedText), privateKeyParameters);
            Console.WriteLine("DECRYPTED TEXT: ");
            Console.WriteLine(decryptedText);
        }

        public static string GetKeyString(RSAParameters publicKey)
        {
            var stringWriter = new StringWriter();
            var xmlSerializer = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            xmlSerializer.Serialize(stringWriter, publicKey);
            return stringWriter.ToString();
        }

        public static byte[] Encrypt(byte[] data, RSAParameters publicKeyParameters)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportParameters(publicKeyParameters);
                return rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
            }
        }

        public static string Decrypt(byte[] encryptedData, RSAParameters privateKeyParameters)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportParameters(privateKeyParameters);
                byte[] decryptedData = rsa.Decrypt(encryptedData, RSAEncryptionPadding.OaepSHA256);
                return Encoding.UTF8.GetString(decryptedData);
            }
        }

        private static string GenerateTestString()
        {
            Guid opportunityId = Guid.NewGuid();
            Guid systemUserId = Guid.NewGuid();
            string currentTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");

            StringBuilder sb = new StringBuilder();
            sb.AppendFormat("opportunityid={0}", opportunityId.ToString());
            sb.AppendFormat("&systemuserid={0}", systemUserId.ToString());
            sb.AppendFormat("&currenttime={0}", currentTime);

            return sb.ToString();
        }
    }
}
