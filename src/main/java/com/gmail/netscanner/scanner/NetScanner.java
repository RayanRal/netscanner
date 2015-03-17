package com.gmail.netscanner.scanner;

import com.gmail.netscanner.exceptions.AccessDeviceException;
import com.gmail.netscanner.exceptions.GetDeviceException;
import com.gmail.netscanner.scanner.PcapPacketHandlerImpl;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.*;

import java.io.IOException;
import java.util.*;

/**
 * Created by le012ch on 2015-02-13.
 */
public class NetScanner {

	public List<PcapIf> findAllDevs() {
		StringBuilder errbuf = new StringBuilder(); // For any error msgs

		List<PcapIf> alldevs = new ArrayList<>();
		int r = Pcap.findAllDevs(alldevs, errbuf);

		if (r != Pcap.OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
			throw new GetDeviceException(errbuf.toString());
		}

		return alldevs;
	}

	/*
		 * Each packet scanned, also has a flow key associated with it. The flow key
		 * is generated based on the headers in each packet and stored with packet
		 * state. We can use the flow key to uniquely identify packets belonging to
		 * the same stream of packets between end host systems. We will keep a map
		 * of various flows with packets in it.
		 */
	private static Map<JFlowKey, JFlow> getFlowsMap(Pcap pcap, PcapPacket packet) {
		final Map<JFlowKey, JFlow> flows = new HashMap<>();

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
