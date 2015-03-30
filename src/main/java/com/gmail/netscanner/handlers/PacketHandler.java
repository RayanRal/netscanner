package com.gmail.netscanner.handlers;

import com.gmail.netscanner.scanner.HttpPacketEvent;
import com.gmail.netscanner.scanner.TcpPacketEvent;
import javafx.event.Event;
import javafx.event.EventTarget;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;

public class PacketHandler implements PcapPacketHandler {

	private final Integer packetDelay;
	private final Tcp tcp = new Tcp();
	private final Http http = new Http();

	final EventTarget httpTarget;
	final EventTarget tcpTarget;

	/*
	 * Same thing for our http header
	 */
	public PacketHandler(EventTarget httpTarget, EventTarget tcpTarget, Integer packetDelay) {
		this.httpTarget = httpTarget;
		this.tcpTarget = tcpTarget;
		this.packetDelay = packetDelay;
	}


	/**
	 * Our custom handler that will receive all the packets libpcap will
	 * dispatch to us.
	 *
	 * @param packet a packet we captured
	 * @param o our custom user parameter which we chose to be a StringBuilder
	 *               object, but could have chosen anything else we wanted passed
	 *               into our handler by libpcap
	 */
	@Override
	public void nextPacket(PcapPacket packet, Object o) {
		/*
                 * Here we receive 1 packet at a time from the capture file. We are
                 * going to check if we have a tcp packet and do something with tcp
                 * header. We are actually going to do this twice to show 2 different
                 * ways how we can check if a particular header exists in the packet and
                 * then get that header (peer header definition instance with memory in
                 * the packet) in 2 separate steps.
                 */

		if (packet.hasHeader(Tcp.ID) && packet.hasHeader(tcp)) {
            /*
            * Now get our tcp header definition (accessor) peered with actual
            * memory that holds the tcp header within the packet.
            */
			Event.fireEvent(tcpTarget, new TcpPacketEvent(packet.getFrameNumber(), packet.getHeader(tcp),
					packet.getCaptureHeader(), packet.toHexdump()));
			System.out.println("fired tcp event!");
			try {
				Thread.sleep(packetDelay);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}

		if (packet.hasHeader(http)  && packet.hasHeader(Http.ID)) {
			Event.fireEvent(httpTarget, new HttpPacketEvent(packet.getFrameNumber(), packet.getHeader(http), packet.getCaptureHeader()));
			System.out.println("fired http event!");
			try {
				Thread.sleep(packetDelay);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}

	}
}
