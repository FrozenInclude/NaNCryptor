using System;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Numerics;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NaNCryptor.Cryption
{
  public  class AesCryptor
    {
        private string _inputpath;
        private string _outputpath;
        private FileStream openFS;
        private FileStream writeFS;
        private FileStream DopenFS;
        private StreamWriter DwriteFS;
        public AesCryptor()
        {

        }
        public void createCryptor(string input,string output)
        {
            this._inputpath = input;
            this._outputpath = output;
            openFS = new FileStream(this._inputpath,FileMode.Open,FileAccess.Read);
            writeFS = new FileStream(this._outputpath, FileMode.Create, FileAccess.Write);
            DopenFS = new FileStream(this._inputpath, FileMode.Open, FileAccess.Read);
            DwriteFS = new StreamWriter(this._outputpath);
        }
        public void Encrypt(string key)
        {
            if (openFS == null || writeFS == null) throw new NullReferenceException("call SetCryptor fist!!");
            byte[] Salt = Encoding.ASCII.GetBytes(((key.Length*5)/2).ToString());
            PasswordDeriveBytes secret = new PasswordDeriveBytes(key, Salt);
            byte[] arr = new byte[openFS.Length];
            openFS.Read(arr, 0, arr.Length);
            AesCryptoServiceProvider aesCrypto = new AesCryptoServiceProvider();
            ICryptoTransform aescrypt = aesCrypto.CreateEncryptor(secret.GetBytes(32),secret.GetBytes(16));
            CryptoStream Crpstream = new CryptoStream(writeFS, aescrypt, CryptoStreamMode.Write);
            Crpstream.Write(arr, 0, arr.Length);
            Crpstream.Close();
        }
        public void Decrypt(string key)
        {
            if (DopenFS == null || DwriteFS == null) throw new NullReferenceException("call SetCryptor fist!!");
            byte[] Salt = Encoding.ASCII.GetBytes(((key.Length * 4) / 2).ToString());
            PasswordDeriveBytes secret = new PasswordDeriveBytes(key, Salt);
            AesCryptoServiceProvider aesDrypto = new AesCryptoServiceProvider();
            ICryptoTransform aesdcrypt =aesDrypto.CreateDecryptor(secret.GetBytes(32), secret.GetBytes(16));
            CryptoStream cryptosteam = new CryptoStream(DopenFS, aesdcrypt, CryptoStreamMode.Read);
            DwriteFS.Write(new StreamReader(cryptosteam).ReadToEndAsync());
            DwriteFS.FlushAsync();
        }
        public void close()
        { 
            this._inputpath="";
            this._outputpath="";
            openFS.Close();
            writeFS.Close();
            DopenFS.Close();
            DwriteFS.Close();
        }
}
}
