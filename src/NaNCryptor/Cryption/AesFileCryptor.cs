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
    public class AesFileCryptor
    {
        /// <summary>
        /// CallBack delegate for en/decryption success notification
        /// </summary>
        public delegate void SuccessCallback();
        private string _inputpath;
        private string _outputpath;
        private string _Dinputpath;
        private string _Doutputpath;
        public AesFileCryptor() { }
       
        /// <summary>
        /// set encryption target file.
        /// </summary>
        public void setEnCryptorPath(string input, string output)
        {
            if (!File.Exists(input)) throw new FileNotFoundException("Input path was wrong!");
            this._inputpath = input;
            this._outputpath = output;
        }
        /// <summary>
        /// set decryption target file.
        /// </summary>
        public void setDeCryptorPath(string input, string output)
        {
            if (!File.Exists(input)) throw new FileNotFoundException("Input path was wrong!");
            this._Dinputpath = input;
            this._Doutputpath = output;
        }
        /// <summary>encrypt target file with aes256
        /// <para>return true If Encryption is success</para>
        /// </summary>
        public bool Encrypt(string password,SuccessCallback callback=null)
        {
            byte[] Salt = Encoding.ASCII.GetBytes(((password.Length).ToString()));
            PasswordDeriveBytes secret = new PasswordDeriveBytes(password, Salt);
            byte[] Key = secret.GetBytes(32);
            byte[] IV = secret.GetBytes(16);
            using (FileStream openFS = new FileStream(this._inputpath, FileMode.Open, FileAccess.Read))
            {
                using (FileStream writeFS = new FileStream(this._outputpath, FileMode.Create, FileAccess.Write))
                {
                    byte[] arr = new byte[openFS.Length];
                    openFS.Read(arr, 0, arr.Length);
                    AesCryptoServiceProvider aesCrypto = new AesCryptoServiceProvider();
                  //  aesCrypto.Mode = CipherMode.CBC;
                    ICryptoTransform aescrypt = aesCrypto.CreateEncryptor(Key, IV);
                    CryptoStream Crpstream = new CryptoStream(writeFS, aescrypt, CryptoStreamMode.Write);
                    Crpstream.Write(arr, 0, arr.Length);
                    Crpstream.Close();
                    writeFS.Close();
                    openFS.Close();
                    SignFile(Key);
                }
            }
            callback?.Invoke();
            return true;
        }
        /// <summary>decrypt target file with aes256
        /// <para>return true If Decryption is success</para>
        /// </summary>
        public bool Decrypt(string password, SuccessCallback callback = null)
        {
            byte[] Salt = Encoding.ASCII.GetBytes(((password.Length).ToString()));
            PasswordDeriveBytes secret = new PasswordDeriveBytes(password, Salt);
            byte[] Key = secret.GetBytes(32);
            byte[] IV = secret.GetBytes(16);

            if (!VerifyFile(Key))//hash checksum
            {
                MessageBox.Show("signed Hash value is not right!");
               return false;
            }

            using (FileStream DopenFS = new FileStream(this._Dinputpath, FileMode.Open, FileAccess.Read))
            {
                DopenFS.Position = 32;//sha 256's size is always 32bytes
                using (StreamWriter DwriteFS = new StreamWriter(this._Doutputpath))
                {
                    AesCryptoServiceProvider aesDrypto = new AesCryptoServiceProvider();
                    ICryptoTransform aesdcrypt = aesDrypto.CreateDecryptor(Key, IV);
                    CryptoStream cryptosteam = new CryptoStream(DopenFS, aesdcrypt, CryptoStreamMode.Read);
                    DwriteFS.Write(new StreamReader(cryptosteam).ReadToEnd());
                    DwriteFS.Flush();
                }
            }
            callback?.Invoke();
            return true;
        }

        private void SignFile(byte[] key)
        {
            using (HMACSHA256 hmac = new HMACSHA256(key))
            {
                using (FileStream inoutstream = new FileStream(this._outputpath, FileMode.OpenOrCreate, FileAccess.ReadWrite))
                {
                    byte[] binarydata = new byte[inoutstream.Length];
                    byte[] hashValue;
                    inoutstream.Read(binarydata, 0, binarydata.Length);
                    hashValue = hmac.ComputeHash(binarydata);
                    inoutstream.Position = 0;
                    inoutstream.Write(hashValue, 0, hashValue.Length);
                    int bytesRead;
                    byte[] buffer = new byte[1024];
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
                using (FileStream inoutstream = new FileStream(this._Dinputpath, FileMode.OpenOrCreate, FileAccess.ReadWrite))
                {
                    int hashsize=(hmac.HashSize / 8);
                    byte[] binarydata = new byte[hashsize];
                    byte[] checksum = new byte[inoutstream.Length - hashsize];
                    byte[] hashvalue;
                    inoutstream.Read(binarydata, 0,hashsize);
                    inoutstream.Read(checksum, 0,(int)inoutstream.Length - hashsize);
                    hashvalue= hmac.ComputeHash(checksum); 
                    return binarydata.SequenceEqual(hmac.ComputeHash(checksum));
                }
            }
        }
        }
        }
