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

        public string encryptInputFilePath { get; private set; }
        public string encryptOutputFilePath { get; private set; }
        public string decryptInputFilePath { get; private set; }
        public string decryptOutputFilePath { get; private set; }

        private readonly byte[] _signature = Encoding.UTF8.GetBytes(("RSA"));
        private int _rsaKeySize;

        public RsaFileCryptor(int KeySize = 2048)
        {
            this._rsaKeySize = KeySize;
        }
       

        /// <summary>
        /// set encryption target file.
        /// </summary>
        public void SetEnCryptionPath(string input, string output)
        {
            if (!File.Exists(input)) throw new FileNotFoundException("Input path was wrong!");

            this.encryptInputFilePath = input;
            this.encryptOutputFilePath = output;
        }

        /// <summary>
        /// set decryption target file.
        /// </summary>
        public void SetDeCryptionPath(string input, string output)
        {
            if (!File.Exists(input)) throw new FileNotFoundException("Input path was wrong!");

            this.decryptInputFilePath = input;
            this.decryptOutputFilePath = output;
        }

        /// <summary>
        /// generate key xml file for RSA
        /// </summary>
        public void GenerateKey(string containerName,string pulicKeyFileOutputPath, string privateKeyFileOutputPath)
        {
            const string providername = "Microsoft Strong Cryptographic Provider";
            const int PROVIDER_RSA_FULL = 1;

            CspParameters cspParams;
            cspParams = new CspParameters(PROVIDER_RSA_FULL);
            cspParams.KeyContainerName = containerName;
            cspParams.Flags = CspProviderFlags.UseMachineKeyStore;
            cspParams.ProviderName =providername ;

            RSACryptoServiceProvider  rsa = new RSACryptoServiceProvider(this._rsaKeySize,cspParams);
            RSAParameters privateKey = RSA.Create().ExportParameters(true);

            rsa.ImportParameters(privateKey);
            string privateKeyText = rsa.ToXmlString(true);

            RSAParameters publicKey = new RSAParameters();
            publicKey.Modulus = privateKey.Modulus;
            publicKey.Exponent = privateKey.Exponent;

            rsa.ImportParameters(publicKey);
            string publicKeyText = rsa.ToXmlString(false);

            StreamWriter output1 = new StreamWriter(pulicKeyFileOutputPath);
            output1.Write(publicKeyText,0,publicKeyText.Length);

            StreamWriter output2 = new StreamWriter(privateKeyFileOutputPath);
            output2.Write(privateKeyText, 0, privateKeyText.Length);

            output1.Close();
            output2.Close();
        }

        /// <summary>encrypt target file with rsa
        /// <para>return true If Encryption is success</para>
        /// </summary>
        public bool Encrypt(string publickey, SuccessCallback callback = null)
        {
            if (encryptInputFilePath == null || encryptOutputFilePath == null) return false;

            if (!File.Exists(publickey)) throw new FileNotFoundException("Public Key File path was wrong!"); 

            using (StreamReader keyReadStream = new StreamReader(publickey))
            {
                string publickeyxml;
                publickeyxml =keyReadStream.ReadToEnd();
                keyReadStream.Close();

                using (FileStream openFileStream = new FileStream(this.encryptInputFilePath, FileMode.Open, FileAccess.Read))
                {
                    byte[] data = new byte[openFileStream.Length];
                    openFileStream.Read(data, 0, data.Length);
                    openFileStream.Close();

                    using (FileStream writeFileStream = new FileStream(this.encryptOutputFilePath, FileMode.Create, FileAccess.Write))
                    {
                        using (RSACryptoServiceProvider provider = new RSACryptoServiceProvider(2048))
                        {
                            provider.FromXmlString(publickeyxml);

                            try
                            {
                                byte[] encryptedByte = provider.Encrypt(data, false);
                                writeFileStream.Write(encryptedByte, 0, encryptedByte.Length);
                                writeFileStream.Close();
                            }
                            catch (CryptographicException E)
                            {
                                return false;
                            }

                            SignifyFile();
                        }
                    }
                }
            }
                callback?.Invoke();
                return true;
        }

        /// <summary>decrypt target file with rsa
        /// <para>return true If Decryption is success</para>
        /// </summary>
        public bool Decrypt(string privatekey, SuccessCallback callback = null)
        {
            if (decryptInputFilePath == null || decryptOutputFilePath == null) { return false; }

            if (!File.Exists(privatekey)) throw new FileNotFoundException("Public Key File path was wrong!");

            if (!VerifyFile())//hash checksum
            {
                MessageBox.Show("signed Hash value is not right!");
                return false;
            }

            using (StreamReader privateKeyFileStream = new StreamReader(privatekey))
            {
                string privatekeyxml;

                privatekeyxml = privateKeyFileStream.ReadToEnd();
                privateKeyFileStream.Close();

                using (FileStream openFileStream = new FileStream(this.decryptInputFilePath, FileMode.Open, FileAccess.Read))
                {
                    int dataLength = (int)openFileStream.Length - (32 + _signature.Length);
                    byte[] data = new byte[dataLength];

                    openFileStream.Position = (32 + _signature.Length);
                    openFileStream.Read(data, 0, data.Length);
                
                    using (FileStream writeFileStream = new FileStream(this.decryptOutputFilePath, FileMode.Create, FileAccess.Write))
                    {
                        using (RSACryptoServiceProvider provider = new RSACryptoServiceProvider(2048))
                        {
                            provider.FromXmlString(privatekeyxml);
                             try
                             {
                                byte[] encryptedByte = provider.Decrypt(data, false);
                                writeFileStream.Write(encryptedByte, 0, encryptedByte.Length);
                              }
                             catch (CryptographicException E)
                             {
                             return false;
                             }
                            writeFileStream.Close();

                        }
                    }
                }
            }
            callback?.Invoke();
            return true;
        }

        /*
      -File checksum-

      Signify
      1.do sha 256 with encrypted file's binary
      2.write cipertext(32bytes) in the beginning of file by using streamwriter
      3.write the rest 

      Verify
      1.read encryted file's binary by using streamreader
      2.do sha 256 binary without 32bytes ciphertext in the beginning of binary
      3.compare result to ciphertext  if comparing is true,func return true or return false
      */
        private void SignifyFile()
        {
            byte[] key = Encoding.UTF8.GetBytes("NaNCryptor");

            using (HMACSHA256 hmac = new HMACSHA256(key))
            {
                using (FileStream _fileStream = new FileStream(this.encryptOutputFilePath, FileMode.OpenOrCreate, FileAccess.ReadWrite))
                {
                    byte[] binarydata = new byte[_fileStream.Length];
                    byte[] hashValue;

                    _fileStream.Read(binarydata, 0, binarydata.Length);
                    hashValue = hmac.ComputeHash(binarydata);
                    _fileStream.Position = 0;
                    _fileStream.Write(_signature, 0, _signature.Length);
                    _fileStream.Write(hashValue, 0, hashValue.Length);
                    _fileStream.Write(binarydata, 0, binarydata.Length);
                }
            }
            return;
        }

        private bool VerifyFile()
        {
            byte[] key = Encoding.UTF8.GetBytes("NaNCryptor");

            using (HMACSHA256 hmac = new HMACSHA256(key))
            {
                using (FileStream _fileStream = new FileStream(this.decryptInputFilePath, FileMode.OpenOrCreate, FileAccess.ReadWrite))
                {
                    int hashsize = (hmac.HashSize / 8);
                    byte[] binarydata = new byte[hashsize];
                    byte[] checksum = new byte[(_fileStream.Length - hashsize) - _signature.Length];
                    byte[] sig = new byte[this._signature.Length];

                    _fileStream.Read(sig, 0, sig.Length);
                    if (!sig.SequenceEqual(this._signature)) return (sig == _signature);
                    _fileStream.Read(binarydata, 0, hashsize);
                    _fileStream.Read(checksum, 0, checksum.Length);

                    return binarydata.SequenceEqual(hmac.ComputeHash(checksum));
                }
            }
        }
    }
}
