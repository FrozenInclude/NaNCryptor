using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.IO;
using Microsoft.Win32;
using System.Windows.Controls;

namespace NaNCryptor.IO
{
    public class RecentFileSystem
    {
        private string filePath;
        public bool loaderr = false;
        private Queue<string> recentFilepath = new Queue<string>();
        private INIsystem ini;
        private const int Qlimit = 10;
        private string reading;
        private MenuItem displayMenu;
        public string Getreading { get { return this.reading; } set { value = this.reading; } }
        public string GetfilePath { get { return this.filePath; } set { value = this.filePath; } }
        public RecentFileSystem(ref Queue<string> fileQue, ref MenuItem displayMenu, string QueSavePath)
        {
            ini = new INIsystem(QueSavePath);
            fileQue = recentFilepath;
            this.displayMenu = displayMenu;
            LoadQueue();
        }
        public async void LoadFileWithoutDialog(string path)
        {
            loaderr = false;
            try
            {
                using (System.IO.StreamReader sr = new System.IO.StreamReader(path))
                {
                    await Task.Run(() =>
                    {
                        this.reading = sr.ReadToEnd();
                        this.filePath = path;
                    });
                }
            }
            catch (FileNotFoundException)
            {
                loaderr = true;
                return;
            }
        }
        public async void LoadFile(string filter = "BTF Files (*.btf)|*.btf")
        {
            loaderr = false;
            OpenFileDialog dlg = new OpenFileDialog();
            dlg.Filter = filter;
            bool? result = dlg.ShowDialog();
            if (result == true)
            {
                using (System.IO.StreamReader sr = new System.IO.StreamReader(dlg.FileName))
                {
                    await Task.Run(() =>
                    {
                        this.reading = sr.ReadToEnd();
                        this.filePath = dlg.FileName;
                    });

                    if (!recentFilepath.Contains(dlg.FileName))
                    {
                        if (recentFilepath.Count == Qlimit)
                        {
                            recentFilepath.Dequeue();
                            recentFilepath.Enqueue(filePath);
                        }
                        else if (recentFilepath.Count < Qlimit)
                        {
                            recentFilepath.Enqueue(filePath);
                        }
                    }
                }
            }
            else
            {
                loaderr = true;
            }
        }
        public void SaveQueue()
        {
            for (int i = 0; i < recentFilepath.Count; i++)
            {
                ini.Write("Queue." + i.ToString(), recentFilepath.ElementAt(i).ToString(), "File");
            }
            ini.Write("QueueCount", (recentFilepath.Count).ToString(), "File");
        }
        public void LoadQueue()
        {
            if (ini.Read("QueueCount", "File") != "")
            {
                bool cannadd;
                for (int i = 0; i < Int64.Parse(ini.Read("QueueCount", "File")); i++)
                {
                    cannadd = true;
                    try
                    {
                        System.IO.StreamReader sr = new System.IO.StreamReader(ini.Read("Queue." + i.ToString(), "File"));
                    }
                    catch (FileNotFoundException)
                    {
                        cannadd = false;
                    }
                    if (cannadd)
                    {
                        recentFilepath.Enqueue(ini.Read("Queue." + i.ToString(), "File"));
                        if (ini.Read("Queue." + i.ToString(), "File") == null)
                        {
                            return;
                        }
                    }
                }
            }
        }
        public async void SaveFile(string text, bool useDialog, string fileName = "untitled", string defaultExt = ".btf", string filter = "BTF Files(*.btf)|*.btf")
        {
            if (useDialog)
            {
                SaveFileDialog Savecode = new SaveFileDialog();
                string dir = "";
                Savecode.FileName = fileName;
                Savecode.DefaultExt = defaultExt;
                Savecode.Filter = filter;
                bool? result = Savecode.ShowDialog();
                if (result == true)
                {
                    dir = Savecode.FileName;
                    FileStream fs = new FileStream(dir, FileMode.Create, FileAccess.Write);
                    StreamWriter sw = new StreamWriter(fs);
                    await sw.WriteLineAsync(text);
                    filePath = Savecode.FileName;
                    if (!recentFilepath.Contains(Savecode.FileName))
                    {
                        if (recentFilepath.Count == Qlimit)
                        {
                            recentFilepath.Dequeue();
                            recentFilepath.Enqueue(filePath);
                        }
                        else if (recentFilepath.Count < Qlimit)
                        {
                            recentFilepath.Enqueue(filePath);
                        }
                    }
                    sw.Flush();
                    sw.Close();
                    fs.Close();
                }
            }
            else if (!useDialog)
            {
                StreamWriter sw = new StreamWriter(filePath, false);
                await sw.WriteAsync(text);
                sw.Flush();
                sw.Close();
            }
        }
    }
}
