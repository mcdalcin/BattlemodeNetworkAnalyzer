using System;

namespace BattlemodeNetworkAnalyzer {
    public partial class MainWindow {
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

    }
}
