using SharpPcap.Npcap;
using System.Net;

namespace BattlemodeNetworkAnalyzer {
    public partial class MainWindow {
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

    }
}
