using LiveCharts;
using LiveCharts.Defaults;
using LiveCharts.Dtos;
using LiveCharts.Geared;
using System.Collections.Generic;

namespace BattlemodeNetworkAnalyzer {
    public partial class MainWindow {
        class IPInfo {

            class PacketInfoWrapper {
                public PacketInfo p;

                public PacketInfoWrapper(PacketInfo p) {
                    this.p = p;
                }
            }

            public List<PacketInfo> outboundPackets = new List<PacketInfo>();
            public List<PacketInfo> inboundPackets = new List<PacketInfo>();

            public GearedValues<DateTimePoint> outboundChartValues = 
                new GearedValues<DateTimePoint>();
            public GearedValues<DateTimePoint> inboundChartValues =
                new GearedValues<DateTimePoint>();

            public GearedValues<ObservablePoint> outboundTimeDiffChartValues =
                new GearedValues<ObservablePoint>();
            public GearedValues<ObservablePoint> inboundTimeDiffChartValues =
                new GearedValues<ObservablePoint>();

            private PacketInfoWrapper _prevInboundPacketInfoWrapper = new PacketInfoWrapper(null);
            private PacketInfoWrapper _prevOutboundPacketInfoWrapper = new PacketInfoWrapper(null);

            public string serverIp;
            public IPInfo(string serverIp) {
                this.serverIp = serverIp;

                outboundChartValues.WithQuality(Quality.Medium);
                inboundChartValues.WithQuality(Quality.Medium);
                outboundTimeDiffChartValues.WithQuality(Quality.High);
                inboundTimeDiffChartValues.WithQuality(Quality.High);
            }

            /** Transfer to chart values. Must be called from main thread. */
            public void TransferToChartValues() {
                TransferToChartValuesHelper(
                    outboundPackets, outboundChartValues, outboundTimeDiffChartValues, _prevOutboundPacketInfoWrapper);
                TransferToChartValuesHelper(
                    inboundPackets, inboundChartValues, inboundTimeDiffChartValues, _prevInboundPacketInfoWrapper);
            }

            private void TransferToChartValuesHelper(
                List<PacketInfo> packetInfo,
                GearedValues<DateTimePoint> packetLengthChartValues,
                GearedValues<ObservablePoint> timeDiffChartValues,
                PacketInfoWrapper prevPacketInfoWrapper) {
                int timeDiffStartOffset = timeDiffChartValues.Count;
                List<DateTimePoint> dateTimePoints = new List<DateTimePoint>();
                List<ObservablePoint> timeDiffPoints = new List<ObservablePoint>();
                foreach (PacketInfo p in packetInfo) {
                    DateTimePoint dtp = new DateTimePoint(p.time, p.length);
                    dateTimePoints.Add(dtp);

                    if (prevPacketInfoWrapper.p != null) {
                        int diffMs = 
                            (int) (p.time - prevPacketInfoWrapper.p.time).TotalMilliseconds;
                        ObservablePoint point = 
                            new ObservablePoint(timeDiffPoints.Count + timeDiffStartOffset, diffMs);
                        timeDiffPoints.Add(point);
                    }
                    prevPacketInfoWrapper.p = p;
                }

                packetInfo.Clear();
                packetLengthChartValues.AddRange(dateTimePoints);
                timeDiffChartValues.AddRange(timeDiffPoints);
            }

            /** Should only be called when we have an exclusive lock on this object. */
            public override string ToString() {
                // Count, average time in between packets.
                double msDiffTotal = 0;
                for (int i = 1; i < outboundPackets.Count; i++) {
                    double msDiff = 
                        (outboundPackets[i].time - outboundPackets[i-1].time).TotalMilliseconds;
                    msDiffTotal += msDiff;
                }
                double msDiffAvg = msDiffTotal / (outboundPackets.Count - 1);

                string outboundPacketInfo =
                    "Outbound Packet Info | " +
                    "Count waiting: " + outboundPackets.Count + " " +
                    "Count in graph: " + outboundChartValues.Count + " " + 
                    "Time diff avg (ms): " + msDiffAvg;

                msDiffTotal = 0;
                for (int i = 1; i < inboundPackets.Count; i++) {
                    double msDiff =
                        (inboundPackets[i].time - inboundPackets[i - 1].time).TotalMilliseconds;
                    msDiffTotal += msDiff;
                }
                msDiffAvg = msDiffTotal / (inboundPackets.Count - 1);

                string inboundPacketInfo =
                    "Inbound Packet Info | " +
                    "Count waiting: " + inboundPackets.Count + " " +
                    "Count in graph: " + inboundChartValues.Count + " " +
                    "Time diff avg (ms): " + msDiffAvg;

                return inboundPacketInfo + "\n\n" + outboundPacketInfo;
            }
        }

    }
}
