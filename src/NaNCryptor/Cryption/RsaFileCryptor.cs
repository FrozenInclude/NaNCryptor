using System;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Windows.Forms;
using System.Numerics;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NaNCryptor.Cryption
{
    public class RsaFileCryptor
    {
        /// <summary>
        /// CallBack delegate for en/decryption success notification
        /// </summary>
        public delegate void SuccessCallback();

        public string inputpath { get; private set; }
        public string outputpath { get; private set; }
        public string Decinputpath { get; private set; }
        public string Decoutputpath { get; private set; }
        private readonly byte[] signature = Encoding.UTF8.GetBytes(("RSA"));

    
        public RsaFileCryptor( )
        {
         
        }

        /// <summary>
        /// set encryption target file.
        /// </summary>
        public void setEnCryptorPath(string input, string output)
        {
            if (!File.Exists(input)) throw new FileNotFoundException("Input path was wrong!");
            this.inputpath = input;
            this.outputpath = output;
        }

        /// <summary>
        /// set decryption target file.
        /// </summary>
        public void setDeCryptorPath(string input, string output)
        {
            if (!File.Exists(input)) throw new FileNotFoundException("Input path was wrong!");
            this.Decinputpath = input;
            this.Decoutputpath = output;
        }
        public void GenerateKey(string ContainerName,string PulicKeyFileOutputPath, string PrivateKeyFileOutputPath)
        {
            const string providername = "Microsoft Strong Cryptographic Provider";
            const int PROVIDER_RSA_FULL = 1;

            CspParameters cspParams;
            cspParams = new CspParameters(PROVIDER_RSA_FULL);
            cspParams.KeyContainerName = ContainerName;
            cspParams.Flags = CspProviderFlags.UseMachineKeyStore;
            cspParams.ProviderName =providername ;

            RSACryptoServiceProvider  rsa = new RSACryptoServiceProvider(2048,cspParams);
            RSAParameters privateKey = RSA.Create().ExportParameters(true);

            rsa.ImportParameters(privateKey);
            string privateKeyText = rsa.ToXmlString(true);

            RSAParameters publicKey = new RSAParameters();
            publicKey.Modulus = privateKey.Modulus;
            publicKey.Exponent = privateKey.Exponent;

            rsa.ImportParameters(publicKey);
            string publicKeyText = rsa.ToXmlString(false);

            StreamWriter output1 = new StreamWriter(PulicKeyFileOutputPath);
            output1.Write(publicKeyText,0,publicKeyText.Length);

            StreamWriter output2 = new StreamWriter(PrivateKeyFileOutputPath);
            output2.Write(privateKeyText, 0, privateKeyText.Length);

            output1.Close();
            output2.Close();
        }
        public bool Encrypt(string publickey, SuccessCallback callback = null)
        {
            if (inputpath == null || outputpath == null) return false;
            string publickeyxml;
            using (StreamReader publick = new StreamReader(publickey))
            {
               publickeyxml=publick.ReadToEnd();
                publick.Close();
                using (FileStream openFS = new FileStream(this.inputpath, FileMode.Open, FileAccess.Read))
                {
                    byte[] data = new byte[openFS.Length];
                    openFS.Read(data, 0, data.Length);
                    openFS.Close();
                    using (FileStream writeFS = new FileStream(this.outputpath, FileMode.Create, FileAccess.Write))
                    {
                        using (RSACryptoServiceProvider provider = new RSACryptoServiceProvider(2048))
                        {
                            //temporarily hard coding;
                            provider.FromXmlString("<RSAKeyValue><Modulus>2VOtymNxhCEJoHKlGWipNCzCYAZTbzOxoxcZ2bOQvAU5A8VSB6p/LDr9LywdpoP917e4F0uzh+VLXlTNEf5bCWwk16W7rpP3Bz9S0Q1w5Jm6ZJSuTI762OSUTvFXf9wy9efZgCnhDGZgLT5f7//BSemuGblJj9JV93Vu6srYRtM=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>");
                            byte[] encryptedByte=provider.Encrypt(data, false);
                            writeFS.Write(encryptedByte, 0, encryptedByte.Length);
                            writeFS.Close();
                        }
                    }
                }
            }
                callback?.Invoke();
                return true;
        }
        public bool Decrypt(string privatekey, SuccessCallback callback = null)
        {
            if (Decinputpath == null || Decoutputpath == null) { return false; }
            string privatekeyxml;
            using (StreamReader publick = new StreamReader(privatekey))
            {
                privatekeyxml = publick.ReadToEnd();
                publick.Close();
                using (FileStream openFS = new FileStream(this.Decinputpath, FileMode.Open, FileAccess.Read))
                {
                    byte[] data = new byte[openFS.Length];
                    openFS.Read(data, 0, data.Length);
                    using (FileStream writeFS = new FileStream(this.Decoutputpath, FileMode.Create, FileAccess.Write))
                    {
                        using (RSACryptoServiceProvider provider = new RSACryptoServiceProvider(2048))
                        {
                            //temporarily hard coding;
                            provider.FromXmlString("<RSAKeyValue><Modulus>2VOtymNxhCEJoHKlGWipNCzCYAZTbzOxoxcZ2bOQvAU5A8VSB6p/LDr9LywdpoP917e4F0uzh+VLXlTNEf5bCWwk16W7rpP3Bz9S0Q1w5Jm6ZJSuTI762OSUTvFXf9wy9efZgCnhDGZgLT5f7//BSemuGblJj9JV93Vu6srYRtM=</Modulus><Exponent>AQAB</Exponent><P>4nWZ/lSHrYlAxkHkVkfwSWurw1zUxQ+soUBmeXmQRCTucBImpQeQw7qRTJ7GxLPSpmq0jxlv67/XPq+GBuZbnQ==</P><Q>9a0bEGk5ftco99yGhaDMM1m75Sht/qa4D0UTgzS43REofVy4Cl0cnvskLnCretBJsOsVxfE1oCodBWr31u25Lw==</Q><DP>29h9Whmn6gGQH6hCSrzl+fEMO8m4SWLRHW5OzWkFdBJCZAxK9fVlRY6uliqiHr3QJ3z5st5n9/8ysAloXPRvRQ==</DP><DQ>BW+BC8noNcA47dL5PvehzPkNSTKtzFaP9/aFSf/enzWD+dIVWFVbDsFruYNQp/T3zGxHHQwLLbIA1l/Zf+3ejQ==</DQ><InverseQ>gKdVYE9mIOqbMEdrST94iAp3YfII1pZ8Yl1L7kKza/hPX0kN6Vr9wok9UCr8GJc62UrxYJEELGIHCxxxdaz4Jg==</InverseQ><D>S22Jkgb1rSAyUSe5OZpjr6IhTGalqqDMdIheBnsWLsu5QB/KGrMINHe8zBSJrfN9tNMk56D0jKP+hpz0F9yqB3VNUGgLdcxQMBZZ82YZlaKHPQlSLP4JojM3Op435LD9dv5+59C1Pdzt22dEloCUOy7hy5xFYdZTQsBqRuv0WtE=</D></RSAKeyValue>");
                            byte[] encryptedByte = provider.Decrypt(data, false);
                            writeFS.Write(encryptedByte, 0, encryptedByte.Length);
                            writeFS.Close();
                        }
                    }
                }
            }
            callback?.Invoke();
            return true;
        }


        private void SignFile(byte[] key)
        {
            using (HMACSHA256 hmac = new HMACSHA256(key))
            {
                using (FileStream inoutstream = new FileStream(this.outputpath, FileMode.OpenOrCreate, FileAccess.ReadWrite))
                {
                    byte[] binarydata = new byte[inoutstream.Length];
                    byte[] hashValue;
                    int bytesRead;
                    byte[] buffer = new byte[1024];

                    inoutstream.Read(binarydata, 0, binarydata.Length);
                    hashValue = hmac.ComputeHash(binarydata);
                    inoutstream.Position = 0;
                    inoutstream.Write(signature, 0, signature.Length);
                    inoutstream.Write(hashValue, 0, hashValue.Length);
                    do
                    {
                        bytesRead = inoutstream.Read(buffer, 0, 1024);
                        inoutstream.Write(buffer, 0, bytesRead);
                    } while (bytesRead > 0);
                    inoutstream.Write(binarydata, 0, binarydata.Length);
                }
            }
            return;
        }

        private bool VerifyFile(byte[] key)
        {
            using (HMACSHA256 hmac = new HMACSHA256(key))
            {
                using (FileStream inoutstream = new FileStream(this.Decinputpath, FileMode.OpenOrCreate, FileAccess.ReadWrite))
                {
                    int hashsize = (hmac.HashSize / 8);
                    byte[] binarydata = new byte[hashsize];
                    byte[] checksum = new byte[(inoutstream.Length - hashsize) - signature.Length];
                    byte[] sig = new byte[this.signature.Length];

                    inoutstream.Read(sig, 0, sig.Length);
                    if (!sig.SequenceEqual(this.signature)) return (sig == signature);
                    inoutstream.Read(binarydata, 0, hashsize);
                    inoutstream.Read(checksum, 0, checksum.Length);

                    return binarydata.SequenceEqual(hmac.ComputeHash(checksum));
                }
            }
        }
    }
}
