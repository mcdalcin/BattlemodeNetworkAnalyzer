using SharpPcap;
using SharpPcap.Npcap;
using SharpPcap.WinPcap;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace BattlemodeNetworkAnalyzer {
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window {
        class PacketInfo {
            /** Time of sending/receiving packet. */
            public DateTime time;

            /** Length in bytes. */
            public int length;

            public PacketInfo(DateTime time, int length) {
                this.time = time;
                this.length = length;
            }
        }

        class IPInfo {
            public List<PacketInfo> outboundPackets = new List<PacketInfo>();
            public List<PacketInfo> inboundPackets = new List<PacketInfo>();

            public string serverIp;
            public IPInfo(string serverIp) {
                this.serverIp = serverIp;
            }
        }

        class CaptureDeviceInfo {
            public CaptureDeviceInfo(NpcapDevice device) {
                this.device = device;

                foreach (var addr in device.Addresses) {
                    if (addr.Addr != null && addr.Addr.ipAddress != null && addr.Netmask != null) {
                        IPAddress ipOut;
                        string ipAddressStr = addr.Addr.ipAddress.ToString();
                        if (IPAddress.TryParse(ipAddressStr, out ipOut)) {
                            if (ipOut.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) {
                                ipv4Address = ipOut.ToString();
                            }
                        }
                    }
                }
            }
            
            public NpcapDevice device;
            public string ipv4Address;
        }

        /** Info about the currently capturing device. */
        private CaptureDeviceInfo _captureDeviceInfo;

        /** IP Address to statistical information. */
        private Dictionary<string, IPInfo> _addressToInfo = new Dictionary<string, IPInfo>();
        private Object _addressToInfoLock = new Object();
       
        public MainWindow() {
            InitializeComponent();
            InitializeDevices();
            
            new Thread(ShowStatistics).Start();
        }

        private void ShowStatistics() {
            // Periodically update stats. This is an expensive operation as it locks
            // the entire container. Therefore, we only do it every 5 seconds.
            while (true) {
                Application.Current.Dispatcher.Invoke(
                    new Action(() => {
                        lock (_addressToInfoLock) {

                            cbIps.Items.Clear();
                            foreach (string ip in _addressToInfo.Keys) {
                                cbIps.Items.Add(ip);
                            }
                        }
                    }));
                Thread.Sleep(5000);
            }
        }

        private void RefreshInfo() {

        }

        private void InitializeDevices() {
            var devices = NpcapDeviceList.Instance;

            if (devices.Count < 1) {
                Trace.WriteLine("No devices were found on this machine.");
                return;
            }

            for (int i = 0; i < devices.Count; i++) {
                var dev = devices[i];
                cbDevices.Items.Add(dev.Description);
                Trace.WriteLine(i + ") " + dev.Name + " " + dev.Description);
            }
        }

        private void StartCapturing(object sender, RoutedEventArgs e) {
            var devices = NpcapDeviceList.Instance;
            
            if (cbDevices.SelectedIndex < 0) {
                return;
            }

            var device = devices[cbDevices.SelectedIndex];

            _captureDeviceInfo = new CaptureDeviceInfo(device);

            device.OnPacketArrival +=
                new PacketArrivalEventHandler(OnPacketArrival);

            int readTimeoutMilliseconds = 1000;
            device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);

            // Trace.WriteLine("Listening on " + device.ToString() + "..." + device.Name + " ... " + device.MacAddress.ToString());

            device.Filter = "udp";
            device.StartCapture();
        }

        private void StopCapturing(object sender, RoutedEventArgs e) {
            if (_captureDeviceInfo == null) {
                return;
            }

            _captureDeviceInfo.device.StopCapture();
            _captureDeviceInfo = null;
        }

        private void RefreshInfo(object sender, RoutedEventArgs e) {

        }

        private void OnPacketArrival(object sender, CaptureEventArgs e) {
            var time = e.Packet.Timeval.Date;
            var length = e.Packet.Data.Length;
            var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var udpPacket = packet.Extract<PacketDotNet.UdpPacket>();
            if (udpPacket != null) {
                var ipPacket = (PacketDotNet.IPPacket)udpPacket.ParentPacket;
                IPAddress srcIp = ipPacket.SourceAddress;
                IPAddress destIp = ipPacket.DestinationAddress;
                
                bool isInbound;
                string serverIp;
                // Verify that one of the addresses equals our capture device IP.
                if (srcIp.ToString().Equals(_captureDeviceInfo.ipv4Address)) {
                    isInbound = false;
                    serverIp = destIp.ToString();
                } else if (destIp.ToString().Equals(_captureDeviceInfo.ipv4Address)) {
                    isInbound = true;
                    serverIp = srcIp.ToString();
                } else {
                    // This should never happen, but if it does, let's report the error.
                    Trace.WriteLine(
                        "Neither src nor dest ip matches current device IP. " + 
                        srcIp.ToString() + " " + destIp.ToString() + " " + 
                        _captureDeviceInfo.ipv4Address);
                    return;
                }
                // Look to see if we have encountered the IP already.
                lock (_addressToInfoLock) {
                    IPInfo info =
                        _addressToInfo.ContainsKey(serverIp)
                            ? _addressToInfo[serverIp]
                            : new IPInfo(serverIp);

                    // Create the packet.
                    PacketInfo packetInfo = new PacketInfo(time, length);
                    if (isInbound) {
                        info.inboundPackets.Add(packetInfo);
                    } else {
                        info.outboundPackets.Add(packetInfo);
                    }
                }
            }
        }

    }
}
