using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using System.Text;

namespace RES_LEARN 
{
    class Program
    {

        static void Main(string[] args)
        {
            // Specify the paths to your certificate files
            string publicKeyCertificatePath = "H:\\Temporary\\Vaibhav.Soni\\Marwadi\\server\\public.cer";
            string privateKeyCertificatePath = "H:\\Temporary\\Vaibhav.Soni\\Marwadi\\server\\private.pfx";
            string privateKeyCertificatePassword = "marwadi";

            // Load public key certificate
            X509Certificate2 publicKeyCertificate = new X509Certificate2("H:\\Temporary\\Vaibhav.Soni\\Marwadi\\server\\public.cer");

            // Load private key certificate
            X509Certificate2 privateKeyCertificate = new X509Certificate2("H:\\Temporary\\Vaibhav.Soni\\Marwadi\\server\\private.pfx","test@123", X509KeyStorageFlags.Exportable| X509KeyStorageFlags.MachineKeySet);

            // Extract RSA parameters from certificate
            RSAParameters publicKeyParameters = ((RSA)publicKeyCertificate.GetRSAPublicKey()).ExportParameters(false);
            RSAParameters privateKeyParameters = ((RSA)privateKeyCertificate.GetRSAPrivateKey()).ExportParameters(true);


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

