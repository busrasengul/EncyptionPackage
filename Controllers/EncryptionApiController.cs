using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using Umbraco.Core.Models;
using Umbraco.Web.Security;
using Umbraco.Web.WebApi;

namespace EncyptionPackage.Controllers
{
    public class EncryptionApiController : UmbracoApiController
    {
        public string access_code = "ENCRYPTION-ACCESS";

        public static Aes aes;

        public static Aes getAes()
        {
            return aes;
        }
        public static Aes setAes(string key, string IV)
        {
            aes = Aes.Create();
            aes.Key = hexStringToByteArray(key);
            aes.IV = hexStringToByteArray(IV);
            return aes;
        }

        [System.Web.Http.AcceptVerbs("GET", "POST")]
        [System.Web.Http.HttpGet]
        public string Hash(string pw, string password, string salt)
        {
            string hashPrefix = "[[HASHED]]";
            string savedPasswordHash = "";

            if (password.StartsWith(hashPrefix))
            {
                return password;
            }

            if (pw == access_code)
            {

                // prepend stored salt to entered pw
                string combo = salt.Trim() + password.Trim();

                // get data as byte array 
                var data = Encoding.ASCII.GetBytes(combo);

                using (SHA256CryptoServiceProvider sha256 = new SHA256CryptoServiceProvider())
                {
                    // hash
                    var shadata = sha256.ComputeHash(data);

                    // convert to string and remove any trailing whitespace
                    savedPasswordHash = ByteArrayToHexString(shadata);
                }

                return hashPrefix + savedPasswordHash;
            }
            else
            {
                return "";
            }
        }

        [System.Web.Http.AcceptVerbs("GET", "POST")]
        [System.Web.Http.HttpGet]
        public string Encrypt(string pw, string key, string IV, string string_data, string format = "")
        {
            if (pw == access_code)
            {

                aes = setAes(key, IV);
                string encryptionPrefix = "[[ENCRYPTED]]";

                if (string_data.StartsWith(encryptionPrefix) || String.IsNullOrWhiteSpace(string_data))
                {
                    return string_data;
                }

                if (format == "camel")
                {
                    string_data = Char.ToUpper(string_data[0]) + string_data.Substring(1).ToLower();
                }
                else if (format == "upper")
                {
                    string_data = string_data.ToUpper();
                }
                else if (format == "lower")
                {
                    string_data = string_data.ToLower();
                }

                string encrypted = encryptionPrefix + EncryptStringToBytes_Aes(string_data, key, IV);
                return encrypted;
            }
            else
            {
                return "";
            }
        }

        [System.Web.Http.AcceptVerbs("GET", "POST")]
        [System.Web.Http.HttpGet]
        public string Decrypt(string pw, string key, string IV, string string_data)
        {
            if (pw == access_code)
            {
                aes = setAes(key, IV);
                string encryptionPrefix = "[[ENCRYPTED]]";
                string_data = string_data.Replace(encryptionPrefix, "");
                string roundtrip = DecryptStringFromBytes_Aes(hexStringToByteArray(string_data), key, IV);
                return roundtrip;
            }
            else
            {
                return "";
            }
        }
        static string ByteArrayToHexString(byte[] data)
        {
            StringBuilder hex = new StringBuilder(data.Length * 2);
            foreach (byte b in data)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        public static byte[] hexStringToByteArray(string hex)
        {
            if (hex.Length % 2 == 1)
                throw new Exception("The binary key cannot have an odd number of digits");

            byte[] arr = new byte[hex.Length >> 1];

            for (int i = 0; i < hex.Length >> 1; ++i)
            {
                arr[i] = (byte)((GetHexVal(hex[i << 1]) << 4) + (GetHexVal(hex[(i << 1) + 1])));
            }

            return arr;
        }

        public static int GetHexVal(char hex)
        {
            int val = (int)hex;
            //For uppercase A-F letters:
            //return val - (val < 58 ? 48 : 55);
            //For lowercase a-f letters:
            //return val - (val < 58 ? 48 : 87);
            //Or the two combined, but a bit slower:
            return val - (val < 58 ? 48 : (val < 97 ? 55 : 87));
        }

        public string EncryptStringToBytes_Aes(string plainText, string Key, string IV)
        {

            var authTicket = new System.Web.HttpContextWrapper(System.Web.HttpContext.Current).GetUmbracoAuthTicket();
            if (authTicket != null)
            {
                var currentUser = Services.UserService.GetByUsername(authTicket.Identity.Name);
                bool accesses = currentUser.IsAdmin();

                if (accesses)
                {
                    // Check arguments.
                    if (plainText == null || plainText.Length <= 0)
                        throw new ArgumentNullException("plainText");
                    if (Key == null || Key.Length <= 0)
                        throw new ArgumentNullException("Key");
                    if (IV == null || IV.Length <= 0)
                        throw new ArgumentNullException("IV");
                    byte[] encrypted;

                    aes = setAes(Key, IV);
                    ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    // Create the streams used for encryption.
                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                            {
                                //Write all data to the stream.
                                swEncrypt.Write(plainText);
                            }
                            encrypted = msEncrypt.ToArray();
                        }
                    }

                    // Return the encrypted bytes from the memory stream.
                    return ByteArrayToHexString(encrypted);
                }
                else
                {
                    return "You are not authorised to access this resource.";
                }

            }

            return "You are not authorised to access this resource.";
        }

        public string DecryptStringFromBytes_Aes(byte[] cipherText, string Key, string IV)
        {
            var authTicket = new System.Web.HttpContextWrapper(System.Web.HttpContext.Current).GetUmbracoAuthTicket();
            if (authTicket != null)
            {
                var currentUser = Services.UserService.GetByUsername(authTicket.Identity.Name);
                bool accesses = currentUser.IsAdmin() || currentUser.HasAccessToSensitiveData();

                if (accesses)
                {
                    // Check arguments.
                    if (cipherText == null || cipherText.Length <= 0)
                        throw new ArgumentNullException("cipherText");
                    if (Key == null || Key.Length <= 0)
                        throw new ArgumentNullException("Key");
                    if (IV == null || IV.Length <= 0)
                        throw new ArgumentNullException("IV");

                    // Declare the string used to hold
                    // the decrypted text.
                    string plaintext = null;

                    // Create a decrytor to perform the stream transform.
                    aes = setAes(Key, IV);
                    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    // Create the streams used for decryption.
                    using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {
                                // Read the decrypted bytes from the decrypting stream
                                // and place them in a string.
                                plaintext = srDecrypt.ReadToEnd();
                            }
                        }
                    }

                    return plaintext;
                }
                else
                {
                    return "You are not authorised to access this resource.";
                }
            }

            return "You are not authorised to access this resource.";
        }
    }

}
