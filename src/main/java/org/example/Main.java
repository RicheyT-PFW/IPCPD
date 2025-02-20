package org.example;

import java.io.EOFException;
import java.net.UnknownHostException;
import java.util.concurrent.TimeoutException;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;


public class Main {
    public static void main(String[] args) throws UnknownHostException, NotOpenException, EOFException, PcapNativeException, TimeoutException, InterruptedException {
    PacketSniffingTest testObj = new PacketSniffingTest();
    testObj.test(5);

    }
}