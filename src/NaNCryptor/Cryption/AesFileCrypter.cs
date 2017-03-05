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
    public class AesFileCrypter
    {
        /// <summary>
        /// CallBack delegate for en/decryption success notification
        /// </summary>
        public delegate void SuccessCallback();

        public string encryptInputFilePath { get; private set; }
        public string encryptOutputFilePath { get; private set; }
        public string decryptInputFilePath { get; private set; }
        public string decryptOutputFilePath { get; private set; }

        private readonly byte[] _signature = Encoding.UTF8.GetBytes(("AES"));
        private CipherMode _ciphermode;
        private PaddingMode _padding;

        /// <summary>
        ///<para>Default settings</para>
        /// <para>CipherMode:<seealso cref="CipherMode.CBC"/></para>
        ///<para>PaddingMode:<seealso cref="PaddingMode.PKCS7"/></para>
        /// </summary>
        public AesFileCrypter() : this(CipherMode.CBC,PaddingMode.PKCS7) { }
        public AesFileCrypter(CipherMode cipermod) : this(cipermod, PaddingMode.PKCS7) { }
        public AesFileCrypter(PaddingMode padmod) : this(CipherMode.CBC,padmod) { }
        public AesFileCrypter(CipherMode cipermod,PaddingMode padmod)
        {
           this._ciphermode = cipermod;
           this._padding =padmod;
        }
       
        /// <summary>
        /// set encryption target file.
        /// </summary>
        public void SetEncryptionPath(string input, string output)
        {
            if (!File.Exists(input)) throw new FileNotFoundException("Input path was wrong!");

            this.encryptInputFilePath = input;
            this.encryptOutputFilePath = output;

            return;
        }

        /// <summary>
        /// set decryption target file.
        /// </summary>
        public void SetDeCryptionPath(string input, string output)
        {
            if (!File.Exists(input)) throw new FileNotFoundException("Input path was wrong!");

            this.decryptInputFilePath = input;
            this.decryptOutputFilePath = output;

            return;
        }

        /// <summary>encrypt target file with aes
        /// <para>return true If Encryption is success</para>
        /// </summary>
        public bool Encrypt(string password,SuccessCallback callback=null)
        {
            if (encryptInputFilePath == null||encryptOutputFilePath==null) return false;

            byte[] Salt = Encoding.ASCII.GetBytes(((password.Length).ToString()));

            PasswordDeriveBytes secret = new PasswordDeriveBytes(password, Salt);

            byte[] Key = secret.GetBytes(32);
            byte[] IV = secret.GetBytes(16);

            using (FileStream openFileStream = new FileStream(this.encryptInputFilePath, FileMode.Open, FileAccess.Read))
            {
                using (FileStream writeFileStream = new FileStream(this.encryptOutputFilePath, FileMode.Create, FileAccess.Write))
                {
                    byte[] arr = new byte[openFileStream.Length];
                    openFileStream.Read(arr, 0, arr.Length);

                    AesCryptoServiceProvider aesCrypto = new AesCryptoServiceProvider();
                    aesCrypto.Mode = this._ciphermode;
                    aesCrypto.Padding = this._padding;

                    ICryptoTransform aescrypt = aesCrypto.CreateEncryptor(Key, IV);
                    CryptoStream crpstream = new CryptoStream(writeFileStream, aescrypt, CryptoStreamMode.Write);
                    crpstream.Write(arr, 0, arr.Length);
                    crpstream.Close();

                    writeFileStream.Close();
                    openFileStream.Close();

                    SignifyFile(Key);
                }
            }
            callback?.Invoke();
            return true;
        }

        /// <summary>decrypt target file with aes
        /// <para>return true If Decryption is success</para>
        /// </summary>
        public bool Decrypt(string password, SuccessCallback callback = null)
        {
            if (decryptInputFilePath == null || decryptOutputFilePath == null) return false;

            byte[] Salt = Encoding.ASCII.GetBytes(((password.Length).ToString()));

            PasswordDeriveBytes secret = new PasswordDeriveBytes(password, Salt);

            byte[] Key = secret.GetBytes(32);
            byte[] IV = secret.GetBytes(16);

            if (!VerifyFile(Key))//hash checksum
            {
                MessageBox.Show("signed Hash value is not right!");
               return false;
            }

            using (FileStream openFileStream = new FileStream(this.decryptInputFilePath, FileMode.Open, FileAccess.Read))
            {
                openFileStream.Position = (32+_signature.Length);//sha 256's size is always 32bytes
                using (StreamWriter DwriteFS = new StreamWriter(this.decryptOutputFilePath))
                {
                    AesCryptoServiceProvider aesDrypto = new AesCryptoServiceProvider();
                    aesDrypto.Mode = this._ciphermode;
                    aesDrypto.Padding = this._padding;

                    ICryptoTransform aesdcrypt = aesDrypto.CreateDecryptor(Key, IV);
                    CryptoStream cryptosteam = new CryptoStream(openFileStream, aesdcrypt, CryptoStreamMode.Read);
                    DwriteFS.Write(new StreamReader(cryptosteam).ReadToEnd());
                    DwriteFS.Flush();
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
        private void SignifyFile(byte[] key)
        {
            using (HMACSHA256 hmac = new HMACSHA256(key))
            {
                using (FileStream _filestream = new FileStream(this.encryptOutputFilePath, FileMode.OpenOrCreate, FileAccess.ReadWrite))
                {
                    byte[] binarydata = new byte[_filestream.Length];
                    byte[] hashValue;
                    int bytesRead;
                    byte[] buffer = new byte[1024];

                    _filestream.Read(binarydata, 0, binarydata.Length);
                    hashValue = hmac.ComputeHash(binarydata);
                    _filestream.Position = 0;
                    _filestream.Write(_signature, 0, _signature.Length);
                    _filestream.Write(hashValue, 0, hashValue.Length);
                    do
                    {
                        bytesRead = _filestream.Read(buffer, 0, 1024);
                        _filestream.Write(buffer, 0, bytesRead);
                    } while (bytesRead > 0);
                    _filestream.Write(binarydata, 0, binarydata.Length);
                }
            }
            return;
        }

        private bool VerifyFile(byte[] key)
        {
            using (HMACSHA256 hmac = new HMACSHA256(key))
            {
                using (FileStream _filestream = new FileStream(this.decryptInputFilePath, FileMode.OpenOrCreate, FileAccess.ReadWrite))
                {
                    int hashsize=(hmac.HashSize / 8);
                    byte[] binarydata = new byte[hashsize];
                    byte[] checksum = new byte[(_filestream.Length - hashsize)- _signature.Length];
                    byte[] sig = new byte[this._signature.Length];

                   _filestream.Read(sig, 0, sig.Length);

                   if(!sig.SequenceEqual(this._signature))return (sig==_signature);

                   _filestream.Read(binarydata, 0,hashsize);
                   _filestream.Read(checksum, 0,checksum.Length);

                   return binarydata.SequenceEqual(hmac.ComputeHash(checksum));
                }
            }
        }
    }
}




