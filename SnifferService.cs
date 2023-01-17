using System;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Net;
using System.Net.Sockets;
using System.ServiceProcess;
using ServiceSniffer;

namespace IpTrafSniffer
{
    public class SnifferService : ServiceBase
    {
        public void StartSocket()
        {
            _capturingSocket.Bind(new IPEndPoint(IpAddress, 80));
            _capturingSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
            
            var optionInValue = new byte[4] { 1, 0, 0, 0 };
            var optionOutValue = new byte[4] { 1, 0, 0, 0 };
            
            _capturingSocket.IOControl(IOControlCode.ReceiveAll,  optionInValue, optionOutValue);
            _capturingSocket.BeginReceive(_byteData, 0, _byteData.Length, SocketFlags.None, OnReceive, null);
        }

        //TODO: Add event logging service
        public StreamWriter File;
        public short NumOfProcesses = 1;
        
        protected override void OnStart(string[] args)
        {
            _capturingSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);

            if (Process.GetProcessesByName("chrome.exe").Length != 0)
                StartSocket();
            
            WatchForProcessStart("chrome.exe"); 
            WatchForProcessEnd("chrome.exe");
        }

        private void WatchForProcessStart(string processName)
        {
            string queryString =
                $"SELECT TargetInstance FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'" +
                $" AND TargetInstance.Name = '{processName}'";
            
            var watcher = new ManagementEventWatcher(SCOPE, queryString);
            watcher.EventArrived += ProcessStarted;
            watcher.Start();
        } 

        private void WatchForProcessEnd(string processName)
        {
            string queryString =
                $"SELECT TargetInstance FROM __InstanceDeletionEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'" +
                $" AND TargetInstance.Name = '{processName}'";

            var watcher = new ManagementEventWatcher(SCOPE, queryString);
            watcher.EventArrived += ProcessEnded;
            watcher.Start();
        }

        private void ProcessEnded(object sender, EventArrivedEventArgs e)
        {
            var targetInstance = (ManagementBaseObject)e.NewEvent.Properties["TargetInstance"].Value;
            var processName = targetInstance.Properties["Name"].Value.ToString();
            File.WriteLine($"{processName} process finished");
            File.Flush();
            
            NumOfProcesses--;
            if (NumOfProcesses != 0) return;
            _isCapturing = false;
            _capturingSocket.Close();
            File.WriteLine("Chrome is not active!!! Sniffing finished!!!");
            File.Flush();
        }

        private void ProcessStarted(object sender, EventArrivedEventArgs e)
        {
            var targetInstance = (ManagementBaseObject)e.NewEvent.Properties["TargetInstance"].Value;
            var processName = targetInstance.Properties["Name"].Value.ToString();
            File.WriteLine($"{processName} process started");
            
            if (NumOfProcesses == 1)
                File.WriteLine("Listening chrome...");
            
            File.Flush();
            NumOfProcesses++;
            StartSocket();         
        }   
      
        private void OnReceive(IAsyncResult ar)
        {
            if (!_isCapturing) return;
            try
            {
                int nReceived = _capturingSocket.EndReceive(ar);

                ParseData(new IPHeader(_byteData, nReceived));

                _byteData = new byte[4096];
                
                _capturingSocket.BeginReceive(_byteData, 0, _byteData.Length, SocketFlags.None, OnReceive, null);
            }
            catch (ObjectDisposedException) { }
            catch (Exception)
            {
                File.WriteLine("Error reading packet");
                File.Flush();
            }
        }

        private void ParseData(IPHeader header)
        {
            File.WriteLine($"{header.SourceAddress}-{header.DestinationAddress}___{DateTime.Now:SystemDate: HH:mm:ss}");
            File.Flush();

            try
            {
                IPHostEntry host = Dns.GetHostEntry(header.DestinationAddress);
                File.WriteLine($"Receiver address: {host.HostName}\n");
            }
            catch
            {
                File.WriteLine($"Domain name [{header.DestinationAddress}] can't be identified\n");
            }
            finally
            {
                File.Flush();
            }
        }

        private IPAddress IpAddress => IPAddress.Parse($"{_hostEntry.AddressList[_hostEntry.AddressList.Length - 1]}");
        private Socket _capturingSocket;
        private readonly IPHostEntry _hostEntry = Dns.GetHostEntry(Dns.GetHostName()); 
        private byte[] _byteData = new byte[4096];
        private bool _isCapturing = true;
        private const string SCOPE = @"\\.\root\CIMV2";
    }
}
