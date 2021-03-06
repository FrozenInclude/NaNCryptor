﻿using System;
using System.ComponentModel;
using System.Windows.Input;
using System.Collections.Generic;
using System.Windows.Forms;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NaNCryptor.Cryption;

namespace NaNCryptor.MVVM
{
    public class MainViewModel : INotifyPropertyChanged 
    {
        private ICommand _AesEncryptCommand;
        public ICommand AesEncryptCommand
        {
            get { return (this._AesEncryptCommand) ?? (this._AesEncryptCommand = new DelegateCommand(encryption,CanEncryption));}
        }
        private string _encTargetpath;
        public  string  encTargetpath
        {
            get { return _encTargetpath;}
            set
            {
                _encTargetpath = value;
                OnPropertyUpdate("encTargetpath");
            }
        }

        private string _decTargetpath;
        public string decTargetpath
        {
            get { return _decTargetpath; }
            set
            {
                _decTargetpath = value;
                OnPropertyUpdate("decTargetpath");
            }
        }
        private bool CanEncryption()
        {
            if (true) return true;
        }

        private Func<string,DialogResult> notification = (str) => MessageBox.Show(str); 

        private void encryption()
        {
            NaNCryptor.Cryption.USB.USBFileCrypter a = new Cryption.USB.USBFileCrypter();
            /*    AesFileCryptor a = new AesFileCryptor();
                a.setEnCryptorPath(@"C:\write.txt", @"c:\writqe.en");
                a.Encrypt("16", success);
                a.setDeCryptorPath(@"C:\writqe.en", @"c:\writese.txt");
                a.Decrypt("16", success);*/
        /*   RsaFileCrypter a = new RsaFileCrypter();
            a.GenerateKey("nimi", @"C:\nimi.public",@"C:\nimi.private");
             a.SetEnCryptionPath(@"C:\write.txt", @"c:\writqe.enz");
           a.Encrypt(@"C:\nimi.public", success);
         a.SetDeCryptionPath(@"C:\writqe.enz", @"c:\writeseq.txt");
         a.Decrypt(@"C:\nimi.private", success);*/
        }
        private void success()
        {
            notification.DynamicInvoke("성공!");
        }

        public event PropertyChangedEventHandler PropertyChanged;

        private void OnPropertyUpdate(string name)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }
}
