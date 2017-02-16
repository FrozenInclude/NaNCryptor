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

        private CipherMode mode;
        private PaddingMode padding;

        private readonly byte[] signature = Encoding.UTF8.GetBytes(("RSA"));

        public RsaFileCryptor() : this(CipherMode.CBC, PaddingMode.PKCS7) { }
        public RsaFileCryptor(CipherMode cipermod) : this(cipermod, PaddingMode.PKCS7) { }
        public RsaFileCryptor(PaddingMode padmod) : this(CipherMode.CBC, padmod) { }
        public RsaFileCryptor(CipherMode cipermod, PaddingMode padmod)
        {
            this.mode = cipermod;
            this.padding = padmod;
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

        public bool Encrypt(string password, SuccessCallback callback = null)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            RSAParameters privateKey = RSA.Create().ExportParameters(true);
            rsa.ImportParameters(privateKey);
            string privateKeyText = rsa.ToXmlString(true);

            // 공개키 생성
            RSAParameters publicKey = new RSAParameters();
            publicKey.Modulus = privateKey.Modulus;
            publicKey.Exponent = privateKey.Exponent;
            rsa.ImportParameters(publicKey);
            string publicKeyText = rsa.ToXmlString(false);

            rsa.FromXmlString(password);
            //암호화할 문자열을 UFT8인코딩
         //   using 
            //암호화
         //   byte[] encbuf = rsa.Encrypt(inbuf, false);
      
            callback?.Invoke();
            return true;
         }
        public bool Decrypt(string password, SuccessCallback callback = null)
        {
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
