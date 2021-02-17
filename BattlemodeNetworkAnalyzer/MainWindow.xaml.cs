using SharpPcap;
using SharpPcap.Npcap;
using SharpPcap.WinPcap;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text;
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
        class Packet {
            public DateTime time;

            public Packet(DateTime time) {
                this.time = time;
            }
        }

        class IPInfo {
            public List<Packet> outboundPackets = new List<Packet>();
            public List<Packet> inboundPackets = new List<Packet>();

            public System.Net.IPAddress destIp;
            public IPInfo(System.Net.IPAddress destIp) {
                this.destIp = destIp;
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
        private Dictionary<System.Net.IPAddress, IPInfo> addressToInfo;

        public MainWindow() {
            InitializeComponent();
            InitializeDevices();
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
            //device.StartCapture();
        }

        private void StopCapturing(object sender, RoutedEventArgs e) {
            if (_captureDeviceInfo == null) {
                return;
            }

            _captureDeviceInfo.device.StopCapture();
            _captureDeviceInfo = null;
        }



        private static void OnPacketArrival(object sender, CaptureEventArgs e) {
            var time = e.Packet.Timeval.Date;
            var len = e.Packet.Data.Length;
            var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var udpPacket = packet.Extract<PacketDotNet.UdpPacket>();
            if (udpPacket != null) {

                // 
                var ipPacket = (PacketDotNet.IPPacket)udpPacket.ParentPacket;
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress destIp = ipPacket.DestinationAddress;
                
                // Look to see if we have encountered the IP already.
                IPInfo info = 

                
                Trace.WriteLine(srcIp.ToString() + " : " + destIp.ToString() + " : " + ipPacket.Protocol.ToString());
            }
        }

    }
}
