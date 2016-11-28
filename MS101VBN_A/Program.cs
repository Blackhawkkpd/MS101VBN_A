using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;

//pcap library including
using PcapDotNet.Core;
using PcapDotNet.Packets;


namespace MS101VBN_A
{ 
    public class QoS
    {
        public static int lengthOfPacketU = 0;
        public static int lengthOfPacketD = 0;

        // This method that will be called when the thread is started
        public void Speed()
        {
            while (true)
            {
                // Put the Main thread to sleep for 1 second
                Thread.Sleep(1000);
                int tmpU, tmpD;
                lock (this)
                {
                    tmpU = lengthOfPacketU;
                    tmpD = lengthOfPacketD;
                    lengthOfPacketD = 0;
                    lengthOfPacketU = 0;
                }
                tmpU = (tmpU * 8);
                tmpD = (tmpD * 8);
                Console.Write("Upload speed avg = " + tmpU / 1000 + "kbps\t\t\t");
                Console.WriteLine("Download speed avg = " + tmpD / 1000 + "kbps");
            }
        }
    }

    class Program
    {
        private static PacketDevice selectedDevice;

        static void Main(string[] args)
        {
            QoS qos = new QoS();
            Console.WriteLine("Hellow world");
            
            // Create the thread object, passing in the Alpha.Beta method
            // via a ThreadStart delegate. This does not start the thread.
            Thread speedCalThrd = new Thread(new ThreadStart(qos.Speed));

            // Start the thread
            speedCalThrd.Start();
            
            Console.ReadKey();

            // Request that oThread be stopped
            //speedCalThrd.Abort();

            // Retrieve the device list from the local machine
            IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;

            // Scan the list printing every entry
            for (int i = 0; i != allDevices.Count(); ++i)
            {
                DevicePrint(allDevices[i]);
            }

            //check the devices
            if (allDevices.Count == 0)
            {
                Console.WriteLine("No interfaces found! Make sure WinPcap is installed.");
                return;
            }

            // Print the list
            for (int i = 0; i != allDevices.Count; ++i)
            {
                LivePacketDevice device = allDevices[i];
                Console.Write((i + 1) + ". " + device.Name);
                if (device.Description != null)
                    Console.WriteLine(" (" + device.Description + ")");
                else
                    Console.WriteLine(" (No description available)");
            }

            int deviceIndex = 0;
            do
            {
                Console.WriteLine("Enter the interface number (1-" + allDevices.Count + "):");
                string deviceIndexString = Console.ReadLine();
                if (!int.TryParse(deviceIndexString, out deviceIndex) ||
                    deviceIndex < 1 || deviceIndex > allDevices.Count)
                {
                    deviceIndex = 0;
                }
            } while (deviceIndex == 0);
            //test read value.
            //Console.WriteLine(deviceIndex.ToString());

            // Take the selected adapter
            selectedDevice = allDevices[deviceIndex - 1];

            //Console.WriteLine(selectedDevice.Addresses[1].Address);
            //Console.ReadKey();
            // Open the device

            // 65536                                    - portion of the packet to capture 65536 guarantees that the whole packet 
            //                                             will be captured on all the link layers
            // PacketDeviceOpenAttributes.Promiscuous   - promiscuous mode
            // 1000                                     - read timeout
            using (PacketCommunicator communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.NoCaptureRemote, 1000))                                                    
            {
                Console.WriteLine("Listening on " + selectedDevice.Description + "...");
                /*
                Packet packet, tmpPacket;
                do
                {
                    PacketCommunicatorReceiveResult result = communicator.ReceivePacket(out packet);
                    switch (result)
                    {
                        case PacketCommunicatorReceiveResult.Timeout:
                            // Timeout elapsed
                            continue;
                        case PacketCommunicatorReceiveResult.Ok:
                            //Console.WriteLine(packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " length:" + packet.Length);
                            lock (qos)
                            {
                                tmpPacket  = packet;
                            }
                            //qos.lengthOfPacket += tmpPacket.Length;
                            Console.WriteLine("IP S: " + tmpPacket.IpV4.Source + " , IP D: " + tmpPacket.IpV4.Destination);
                            break;
                        default:
                            throw new InvalidOperationException("The result " + result + " shoudl never be reached here");
                    }
                } while (true);
                */
                // start the capture
                communicator.ReceivePackets(0, PacketHandler);
                //communicator.ReceiveStatistics(0, StatiscitsHandler);
            }


           // Console.ReadKey();
        }

        private static void StatiscitsHandler(PacketSampleStatistics stat)
        {
            Console.WriteLine("speed from stat : " + stat.AcceptedBytes.ToString());
        }

        // Callback function invoked by Pcap.Net for every incoming packet
        private static void PacketHandler(Packet packet)
        {
            string packsource = packet.Ethernet.IpV4.Source.ToString();
            string packdeviceip = selectedDevice.Addresses[1].Address.ToString().Remove(0,9);

            //download packets 
            if( packsource.Equals(packdeviceip) )
            {
                QoS.lengthOfPacketU += packet.Length;
            }

            //upload packets
            else
            {
                QoS.lengthOfPacketD += packet.Length;
            }
            //Console.WriteLine(packet.Ethernet.IpV4.Source + "  " + packet.Ethernet.IpV4.Destination + " " + packet.Ethernet.IpV4.Tcp.SourcePort);
            //Console.WriteLine(packet.Ethernet.IpV4.Source + "  " + packet.Ethernet.IpV4.Destination + " " + packet.Ethernet.IpV4.Tcp.SourcePort);
            //Console.WriteLine(packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " length:" + packet.Length);               
        }

        // Print all the available information on the given interface
        private static void DevicePrint(IPacketDevice device)
        {
            // Name
            Console.WriteLine(device.Name);

            // Description
            if (device.Description != null)
                Console.WriteLine("\tDescription: " + device.Description);

            // Loopback Address
            Console.WriteLine("\tLoopback: " +
                              (((device.Attributes & DeviceAttributes.Loopback) == DeviceAttributes.Loopback)
                                   ? "yes"
                                   : "no"));

            // IP addresses
            foreach (DeviceAddress address in device.Addresses)
            {
                Console.WriteLine("\tAddress Family: " + address.Address.Family);

                if (address.Address != null)
                    Console.WriteLine(("\tAddress: " + address.Address));
                if (address.Netmask != null)
                    Console.WriteLine(("\tNetmask: " + address.Netmask));
                if (address.Broadcast != null)
                    Console.WriteLine(("\tBroadcast Address: " + address.Broadcast));
                if (address.Destination != null)
                    Console.WriteLine(("\tDestination Address: " + address.Destination));
            }
            Console.WriteLine();
        }
    }
}
