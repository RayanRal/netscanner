package com.gmail.netscanner.handlers;

import javafx.event.EventTarget;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.tcpip.Http;

import java.awt.*;

/**
 * Created by le012ch on 2015-03-20.
 */
public class HttpPacketHandler extends PacketHandler<Http> {

	private Http http;

	public HttpPacketHandler(EventTarget eventTarget) {
		super(eventTarget);
	}

	@Override
	public void nextPacket(PcapPacket packet, Http http) {
		        /*
                 * An easier way of checking if header exists and peering with memory
                 * can be done using a conveniece method JPacket.hasHeader(? extends
                 * JHeader). This method performs both operations at once returning a
                 * boolean true or false. True means that header exists in the packet
                 * and our tcp header difinition object is peered or false if the header
                 * doesn't exist and no peering was performed.
                 */

                /*
                 * A typical and common approach to getting headers from a packet is to
                 * chain them as a condition for the if statement. If we need to work
                 * with both tcp and http headers, for example, we place both of them on
                 * the command line.
                 */
		if (packet.hasHeader(http)) {
	                /*
                     * Now we are guarranteed to have both tcp and http header peered. If
                     * the packet only contained tcp segment even though tcp may have http
                     * port number, it still won't show up here since headers appear right
                     * at the beginning of http session.
                     */

			System.out.printf("http header::%s%n", packet.getHeader(http));
		}

					/*
                     * jNetPcap keeps track of frame numbers for us. The number is simply
                     * incremented with every packet scanned.
                     */
		System.out.printf("frame #%d%n", packet.getFrameNumber());
	}
}
