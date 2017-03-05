using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.Management;

namespace NaNCryptor.Cryption.USB
{
  public class USBFileCrypter
    {
        public delegate void SuccessCallback();

        private readonly byte[] _signature = Encoding.UTF8.GetBytes(("USB"));

        private string encryptInputFilePath;
        private string encryptOutputFilePath;
        private string decryptInputFilePath;
        private string decryptOutputFilePath;


        public USBFileCrypter()
        {

        }

        private string GenerateUSBKey(USBDeviceInfo device)
        {
            string key ="";
            string deviceID = device.DeviceID;
            string pnpDeviceID=device.PnpDeviceID;
            string description=device.Description;

            byte[] arr = Encoding.Default.GetBytes(deviceID+pnpDeviceID+description);
          
            for(int i = 0; i < arr.Length; ++i)
            {
                arr[i] ^= (byte)(i+arr.Length & 0xff);
                key += arr[i].ToString();
            }
            return key;
        }

        public void SetEncryptionFilePath(string input, string output)
        {
            this.encryptInputFilePath = input;
            this.encryptOutputFilePath = output;
        }
        
        public void SetDecryptionFilePath(string input,string output)
        {
            this.decryptInputFilePath = input;
            this.decryptOutputFilePath = output;
        }
        static List<USBDeviceInfo> GetUSBDevices()
        {
            List<USBDeviceInfo> devices = new List<USBDeviceInfo>();

            ManagementObjectCollection collection;

            using (var searcher = new ManagementObjectSearcher(@"SELECT * FROM Win32_PnPEntity where DeviceID Like ""USB%"""))
                collection = searcher.Get();

            foreach (var device in collection)
            {
                devices.Add(new USBDeviceInfo(
                (string)device.GetPropertyValue("DeviceID"),
                (string)device.GetPropertyValue("PNPDeviceID"),
                (string)device.GetPropertyValue("Description")
                ));
            }

            collection.Dispose();
            return devices;
        }

        public bool Encrypt(USBDeviceInfo device, SuccessCallback callback = null)
        {
            if (encryptInputFilePath == null || encryptOutputFilePath == null) return false;
            string password = GenerateUSBKey(device);

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
                    ICryptoTransform aescrypt = aesCrypto.CreateEncryptor(Key, IV);
                    CryptoStream crpstream = new CryptoStream(writeFileStream, aescrypt, CryptoStreamMode.Write);
                    crpstream.Write(arr, 0, arr.Length);
                    crpstream.Close();

                    writeFileStream.Close();
                    openFileStream.Close();

               //     SignFile(Key);
                }
            }
            callback?.Invoke();
            return true;
        }
        public bool Decrypt(USBDeviceInfo device, SuccessCallback callback = null)
        {
            if (decryptInputFilePath == null || decryptOutputFilePath == null) return false;

            string password = GenerateUSBKey(device);

            byte[] Salt = Encoding.ASCII.GetBytes(((password.Length).ToString()));

            PasswordDeriveBytes secret = new PasswordDeriveBytes(password, Salt);

            byte[] Key = secret.GetBytes(32);
            byte[] IV = secret.GetBytes(16);

        //    if (!VerifyFile(Key))//hash checksum
          //  {
          //      MessageBox.Show("signed Hash value is not right!");
         //       return false;
       //     }

            using (FileStream openFileStream = new FileStream(this.decryptInputFilePath, FileMode.Open, FileAccess.Read))
            {
                openFileStream.Position = (32 + _signature.Length);//sha 256's size is always 32bytes
                using (StreamWriter DwriteFS = new StreamWriter(this.decryptOutputFilePath))
                {
                    AesCryptoServiceProvider aesDrypto = new AesCryptoServiceProvider();
                
                    ICryptoTransform aesdcrypt = aesDrypto.CreateDecryptor(Key, IV);
                    CryptoStream cryptosteam = new CryptoStream(openFileStream, aesdcrypt, CryptoStreamMode.Read);
                    DwriteFS.Write(new StreamReader(cryptosteam).ReadToEnd());
                    DwriteFS.Flush();
                }
            }
            callback?.Invoke();
            return true;
        }
        private void SignifyFile(USBDeviceInfo device)
        {
            byte[] key = Encoding.Default.GetBytes(GenerateUSBKey(device));

            using (HMACSHA256 hmac = new HMACSHA256(key))
            {
                using (FileStream _fileStream = new FileStream(this.encryptOutputFilePath, FileMode.OpenOrCreate, FileAccess.ReadWrite))
                {
                    byte[] binarydata = new byte[_fileStream.Length];
                    byte[] hashValue;
                    byte[] deviceIdHash = hmac.ComputeHash(Encoding.Default.GetBytes(device.DeviceID));
                    byte[] pnpDeviceIdHash = hmac.ComputeHash(Encoding.Default.GetBytes(device.PnpDeviceID));
                    byte[]  descriptionHash = hmac.ComputeHash(Encoding.Default.GetBytes(device.Description));

                    _fileStream.Read(binarydata, 0, binarydata.Length);

                    hashValue = hmac.ComputeHash(binarydata);

                    _fileStream.Position = 0;

                    _fileStream.Write(_signature, 0, _signature.Length);

                    _fileStream.Write(deviceIdHash, 0, deviceIdHash.Length);

                    _fileStream.Write(pnpDeviceIdHash, 0, pnpDeviceIdHash.Length);

                    _fileStream.Write(descriptionHash, 0, descriptionHash.Length);

                    _fileStream.Write(hashValue, 0, hashValue.Length);

                    _fileStream.Write(binarydata, 0, binarydata.Length);
                }
            }
            return;
        }
    }
}
