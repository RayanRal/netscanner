package com.gmail.netscanner;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.*;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;

import java.io.IOException;
import java.util.*;

/**
 * Created by le012ch on 2015-02-13.
 */
public class NetScanner {

    public static void main(String[] args) throws IOException {
        PcapIf device = getDeviceInterface();
        System.out.printf("\nChoosing '%s' on your behalf:\n", (device.getDescription() != null) ? device.getDescription() : device.getName());

        /***************************************************************************
         * Second we open up the selected device
         **************************************************************************/
        int snaplen = 64 * 1024;           // Capture all packets, no trucation
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
        int timeout = 10 * 1000;           // 10 seconds in millis
        Pcap pcap = getPcap(device, snaplen, flags, timeout);

        /***************************************************************************
         * Third we create a packet handler which will receive packets from the
         * libpcap loop.
         **************************************************************************/
        PcapPacketHandler<StringBuffer> jpacketHandler = new PcapPacketHandlerImpl<StringBuffer>();

        JScanner.getThreadLocal().setFrameNumber(0);

        final PcapPacket packet = new PcapPacket(JMemory.POINTER);
//        final Tcp tcp = new Tcp();

        /*for (int i = 0; i < 5; i++) {
            pcap.nextEx(packet);

            if (packet.hasHeader(tcp)) {
                System.out.printf("#%d seq=%08X%n", packet.getFrameNumber(), tcp.seq());
            }
        }*/

        final Map<JFlowKey, JFlow> flows = getFlowsMap(pcap, packet);


        /*
         * Now that we added 50 packets to various flows maintained by the flows
         * Map, we can now access those flows and the packet within it. The packets
         * are now grouped into flows.
         */
        for (JFlow flow : flows.values()) {
            processFlow(flow);
        }

        /*
         * We still haven't read all the packets from our offline file. Here is an
         * easier way to retrieve all the packets while grouping them into flows.
         * jNetPcap provides a neat little class that does all of the above work for
         * us. Its called JFlowMap, not only that it implements a JPacketHandler
         * interface suitable for usage with Pcap.loop or Pcap.dispatch calls and it
         * will add all packets received into appropriate flows.
         */
        JFlowMap superFlowMap = new JFlowMap();

        /*
         * So lets finish this file off, and read the remaining packets into our new
         * superFlowMap and do a pretty print of all the flows it finds. The 3rd
         * argument to Pcap.loop is unused so we just set it to null.
         * Pcap.LOOP_INFINITE flag tells the Pcap.loop method to read all the
         * packets until the end of file. Since we already read some packets, this
         * will read remaining packets from the current position in the file until
         * the end.
         */
//        pcap.loop(Pcap.LOOP_INFINITE, superFlowMap, null);

        System.out.printf("superFlowMap::%s%n", superFlowMap);

        /***************************************************************************
         * Fourth we enter the loop and tell it to capture 10 packets. The loop
         * method does a mapping of pcap.datalink() DLT value to JProtocol ID, which
         * is needed by JScanner. The scanner scans the packet buffer and decodes
         * the headers. The mapping is done automatically, although a variation on
         * the loop method exists that allows the programmer to sepecify exactly
         * which protocol ID to use as the data link type for this pcap interface.
         **************************************************************************/
        pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, new StringBuffer("jNetPcap rocks!"));


        /***************************************************************************
         * Last thing to do is close the pcap handle
         **************************************************************************/
        pcap.close();
    }

    private static Pcap getPcap(PcapIf device, int snaplen, int flags, int timeout) {
        StringBuilder errorBuffer = new StringBuilder();
        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errorBuffer);

        if (pcap == null) {
            System.err.printf("Error while opening device for capture: " + errorBuffer);
            throw new RuntimeException(errorBuffer.toString());
        }

        return pcap;
    }

    private static PcapIf getDeviceInterface() {
        List<PcapIf> alldevs = new ArrayList<>(); // Will be filled with NICs
        StringBuilder errbuf = new StringBuilder(); // For any error msgs

        /***************************************************************************
         * First get a list of devices on this system
         **************************************************************************/
        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r != Pcap.OK || alldevs.isEmpty()) {
            System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
            throw new RuntimeException();//todo
        }

        System.out.println("Network devices found:");

        int deviceNumber = 0;
        for (PcapIf device : alldevs) {
            String description = (device.getDescription() != null) ? device.getDescription() : "No description available";
            System.out.printf("#%d: %s [%s]\n", deviceNumber++, device.getName(), description);
        }

        return alldevs.get(0);        // We know we have at least 1 device
    }

    /*
         * Each packet scanned, also has a flow key associated with it. The flow key
         * is generated based on the headers in each packet and stored with packet
         * state. We can use the flow key to uniquely identify packets belonging to
         * the same stream of packets between end host systems. We will keep a map
         * of various flows with packets in it.
         */
    private static Map<JFlowKey, JFlow> getFlowsMap(Pcap pcap, PcapPacket packet) {
        final Map<JFlowKey, JFlow> flows = new HashMap<JFlowKey, JFlow>();

        for (int i = 0; i < 50; i++) {
            pcap.nextEx(packet);
            final JFlowKey key = packet.getState().getFlowKey();

            JFlow flow = flows.get(key);
            if (flow == null) {
                flows.put(key, flow = new JFlow(key));
            }

            flow.add(new PcapPacket(packet));
        }
        return flows;
    }

    private static void processFlow(JFlow flow) {
    /*
     * Flows can be bi-directional. That is packets going between host A and B
     * would be considered in forward-direction, while packets between host B
     * and A can be considered reserverse direction. Although both forward and
     * reverse are going in the opposite directions, jnetpcap flows consider
     * them the same flows. You have 3 types of accessors for retrieving
     * packets from a flow. JFlow.getForward, JFlow.getReverse or
     * JFlow.getAll. JFlow.getAll gets a list of packets, no matter which
     * direction they are going, while the other 2 accessors only get the
     * packets that are going in the specified direction.
     */
        if (flow.isReversable()) {
            /*
             * We can get directional flow packets, but only if the flow is
             * reversable. Not all flows are reversable and this is determined by
             * the header types. If a flow is not reversable, flow.getReverse will
             * return empty list, which is something we don't want to have to
             * process.
             */

            List<JPacket> forward = flow.getForward();
            for (JPacket p : forward) {
                System.out.printf("%d, ", p.getFrameNumber());
            }
            System.out.println();

            List<JPacket> reverse = flow.getReverse();
            for (JPacket p : reverse) {
                System.out.printf("%d, ", p.getFrameNumber());
            }
        } else {

            /*
             * Otherwise we have to get All the packets and there is no
             * forward/reverse direction associated with the packets. Here is how we
             * can do this a little more compactly.
             */
            for (JPacket p : flow.getAll()) {
                System.out.printf("%d, ", p.getFrameNumber());
            }
        }
        System.out.println();
    }

}
