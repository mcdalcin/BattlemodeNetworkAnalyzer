using LiveCharts;
using LiveCharts.Configurations;
using LiveCharts.Defaults;
using LiveCharts.Dtos;
using LiveCharts.Geared;
using SharpPcap;
using SharpPcap.Npcap;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Threading;
using System.Windows;
using System.Windows.Media;

namespace BattlemodeNetworkAnalyzer {
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window {

        /** Info about the currently capturing device. */
        private CaptureDeviceInfo _captureDeviceInfo;

        /** IP Address to statistical information. */
        private Dictionary<string, IPInfo> _addressToInfo =
            new Dictionary<string, IPInfo>();
        private Object _addressToInfoLock = new Object();

        private string _initializedIp = "";

        public MainWindow() {
            InitializeComponent();
            InitializeDevices();
            DataContext = this;

            new Thread(ShowStatistics).Start();
        }

        private void ShowStatistics() {
            // Periodically update stats. This is an expensive operation as it locks
            // the entire container. Therefore, we only do it every 5 seconds.
            while (true) {
                Application.Current.Dispatcher.Invoke(
                    () => {
                        RefreshInfo(null, null);
                        return true;
                    });
                Thread.Sleep(100);

        }
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
            
            if (_captureDeviceInfo != null) {
                return;
            }

            if (cbDevices.SelectedIndex < 0) {
                return;
            }

            var device = devices[cbDevices.SelectedIndex];

            _captureDeviceInfo = new CaptureDeviceInfo(device);

            device.OnPacketArrival +=
                new PacketArrivalEventHandler(OnPacketArrival);

            int readTimeoutMilliseconds = 1000;
            device.Open(DeviceMode.Normal, readTimeoutMilliseconds);

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

        /** May only be called from UI thread. */
        private void RefreshInfo(object sender, RoutedEventArgs e) {
            lock (_addressToInfoLock) {
                // Check for currently selected item.
                string selectedIp =
                    cbIps.SelectedItem == null
                        ? "" 
                        : cbIps.SelectedItem.ToString();
                int index = 0;
                int selectedIpIndex = -1;
                List<string> ips = new List<string>();
                foreach (string ip in _addressToInfo.Keys) {
                    // Filter out any spurious UDP packets. 
                    IPInfo ipInfo = _addressToInfo[ip];
                    if (ipInfo.inboundChartValues.Count + ipInfo.inboundPackets.Count < 100 ||
                        ipInfo.outboundChartValues.Count + ipInfo.outboundPackets.Count < 100) {
                        continue;
                    }
                    ips.Add(ip);
                    if (ip.Equals(selectedIp)) {
                        selectedIpIndex = index;
                    }
                    index++;
                }

                if (ips.Count != cbIps.Items.Count) {
                    cbIps.Items.Clear();
                    foreach (string ip in ips) {
                        cbIps.Items.Add(ip);
                    }
                    cbIps.SelectedIndex = selectedIpIndex;
                }

                // Update the map for the selected IP.
                var secondConfig = Mappers.Weighted<DateTimePoint>()
                    .X((x, index) => index)
                    .Y(x => x.Value);
                var pointConfig = Mappers.Xy<CorePoint>()
                    .X(corePoint => corePoint.X)
                    .Y(corePoint => corePoint.Y);
                if (_addressToInfo.ContainsKey(selectedIp)) {
                    var ipInfo = _addressToInfo[selectedIp];

                    tbIpInfo.Text = ipInfo.ToString();

                    // Update the chart values.
                    ipInfo.TransferToChartValues();

                    if (_initializedIp.Equals(selectedIp)) {
                        return;
                    }
                    
                    // Inbound packet length graph.
                    InboundGraph.Series = new SeriesCollection(secondConfig) {
                        new GLineSeries {
                            Values = ipInfo.inboundChartValues,
                            Fill = Brushes.Transparent,
                            PointGeometrySize = 0,
                            LineSmoothness = 1,
                            StrokeThickness = 1
                        },
                    };

                    // Outbound packet length graph.
                    OutboundGraph.Series = new SeriesCollection(secondConfig) {
                        new GLineSeries {
                            Values = ipInfo.outboundChartValues,
                            Fill = Brushes.Transparent,
                            PointGeometrySize = 0,
                            LineSmoothness = 1,
                            StrokeThickness = 1
                        },
                    };

                    // Inbound time diff graph.
                    InboundTimeDiffGraph.Series = new SeriesCollection(pointConfig) {
                        new GLineSeries {
                            Values = ipInfo.inboundTimeDiffChartValues,
                            Fill = Brushes.Transparent,
                            PointGeometrySize = 0,
                            LineSmoothness = 1,
                            StrokeThickness = 1
                        },
                    };

                    // Outbound time diff graph.
                    OutboundTimeDiffGraph.Series = new SeriesCollection(pointConfig) {
                        new GLineSeries {
                            Values = ipInfo.outboundTimeDiffChartValues,
                            Fill = Brushes.Transparent,
                            PointGeometrySize = 0,
                            LineSmoothness = 1,
                            StrokeThickness = 1
                        },
                    };

                    _initializedIp = selectedIp;
                }
            }
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
                    serverIp = destIp.ToString() + " src_port: " + udpPacket.SourcePort + " dest_port: " + udpPacket.DestinationPort;
                } else if (destIp.ToString().Equals(_captureDeviceInfo.ipv4Address)) {
                    isInbound = true;
                    serverIp = srcIp.ToString() + " src_port: " + udpPacket.DestinationPort + " dest_port: " + udpPacket.SourcePort;
                } else {
                    // We don't care about these packets.
                    return;
                }
                // Look to see if we have encountered the IP already.
                lock (_addressToInfoLock) {
                    if (!_addressToInfo.ContainsKey(serverIp)) {
                        _addressToInfo[serverIp] = new IPInfo(serverIp);
                    }
                    IPInfo info = _addressToInfo[serverIp];
                    
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
