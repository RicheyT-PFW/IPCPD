package org.example;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import java.io.EOFException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.TimeoutException;

public class PacketSniffingTest {

    public PacketSniffingTest() {
        super();
    }

    // Get the IP and NIC of the Device that will capture packets
    private PcapNetworkInterface getNIF() throws PcapNativeException, UnknownHostException {
        InetAddress addr = InetAddress.getByName("10.0.0.216");
        return Pcaps.getDevByAddress(addr);
    }

    // Open pcap handle so that we can capture packets, send packets and so on
    private PcapHandle openHandle() throws UnknownHostException, PcapNativeException {

        int snapLen = 65536;
        PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
        int timeout = 10;
        return getNIF().openLive(snapLen, mode, timeout);
    }

    // Test for packet sniffing
    public void test(int packetCountToCapture) throws RuntimeException, UnknownHostException, PcapNativeException {

        PcapHandle handle = openHandle();

        Thread getPackets = new Thread(() -> {
            System.out.println("Preparing for sniffing");

            // Show the packets captured
            int validCount = 0;
            int nullCount = 0;

            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                e.getStackTrace();
            }

            while (validCount < packetCountToCapture) {
                Packet packet = null;

                try {
                    packet = handle.getNextPacketEx();
                    Thread.sleep(1);
                } catch (InterruptedException | NotOpenException | PcapNativeException | EOFException | TimeoutException | NullPointerException e) {
                    e.getStackTrace();
                } finally {
                    if (packet != null ) {
                        System.out.println("\n\n" + packet.getClass()+ "\n\n");
                        System.out.println("Ethernet Packet:" + (validCount + 1) + ":\n" + packet);
                        System.out.println();
                        validCount++;

                    } else {
                        nullCount++;
                    }
                }
            }


            System.out.println("Valid Count: " + validCount);
            System.out.println("Null Count: " + nullCount);
            handle.close();
       });

        getPackets.start();


    }
}
