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
            if (!File.Exists(publickey)) throw new FileNotFoundException("Public Key File path was wrong!"); 

            using (StreamReader publick = new StreamReader(publickey))
            {
                string publickeyxml;
                publickeyxml =publick.ReadToEnd();
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
                            provider.FromXmlString(publickeyxml);
                            byte[] encryptedByte=provider.Encrypt(data, false);
                            writeFS.Write(encryptedByte, 0, encryptedByte.Length);
                            writeFS.Close();
                            SignFile();
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
            if (!File.Exists(privatekey)) throw new FileNotFoundException("Public Key File path was wrong!");

            if (!VerifyFile())//hash checksum
            {
                MessageBox.Show("signed Hash value is not right!");
                return false;
            }

            using (StreamReader privatek = new StreamReader(privatekey))
            {
                string privatekeyxml;

                privatekeyxml = privatek.ReadToEnd();
                privatek.Close();

                using (FileStream openFS = new FileStream(this.Decinputpath, FileMode.Open, FileAccess.Read))
                {
                    int dataLength = (int)openFS.Length - (32 + signature.Length);
                    byte[] data = new byte[dataLength];

                    openFS.Position = (32 + signature.Length);
                    openFS.Read(data, 0, data.Length);
                
                    using (FileStream writeFS = new FileStream(this.Decoutputpath, FileMode.Create, FileAccess.Write))
                    {
                        using (RSACryptoServiceProvider provider = new RSACryptoServiceProvider(2048))
                        {
                            provider.FromXmlString(privatekeyxml);
                             try
                             {
                                byte[] encryptedByte = provider.Decrypt(data, false);
                                writeFS.Write(encryptedByte, 0, encryptedByte.Length);
                              }
                             catch (CryptographicException E)
                             {
                             return false;
                             }
                            writeFS.Close();

                        }
                    }
                }
            }
            callback?.Invoke();
            return true;
        }

        private void SignFile()
        {
            byte[] key = Encoding.UTF8.GetBytes("NaNCryptor");

            using (HMACSHA256 hmac = new HMACSHA256(key))
            {
                using (FileStream inoutstream = new FileStream(this.outputpath, FileMode.OpenOrCreate, FileAccess.ReadWrite))
                {
                    byte[] binarydata = new byte[inoutstream.Length];
                    byte[] hashValue;

                    inoutstream.Read(binarydata, 0, binarydata.Length);
                    hashValue = hmac.ComputeHash(binarydata);
                    inoutstream.Position = 0;
                    inoutstream.Write(signature, 0, signature.Length);
                    inoutstream.Write(hashValue, 0, hashValue.Length);
                    inoutstream.Write(binarydata, 0, binarydata.Length);
                }
            }
            return;
        }

        private bool VerifyFile()
        {
            byte[] key = Encoding.UTF8.GetBytes("NaNCryptor");

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
