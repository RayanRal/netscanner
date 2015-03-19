package com.gmail.netscanner.scanner;

import javafx.event.Event;
import javafx.event.EventTarget;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;

public class PcapPacketHandlerImpl<T> implements PcapPacketHandler<T> {

	final EventTarget target;

	final Tcp tcp = new Tcp();

	/*
	 * Same thing for our http header
	 */
	final Http http = new Http();

	public PcapPacketHandlerImpl(EventTarget target) {
		this.target = target;
	}

	/**
	 * Our custom handler that will receive all the packets libpcap will
	 * dispatch to us. This handler is inside a libpcap loop and will receive
	 * exactly 10 packets as we specified on the Pcap.loop(10, ...) line
	 * above.
	 *
	 * @param packet a packet from our capture file
	 * @param errbuf our custom user parameter which we chose to be a StringBuilder
	 *               object, but could have chosen anything else we wanted passed
	 *               into our handler by libpcap
	 */
	public void nextPacket(PcapPacket packet, T errbuf) {

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
//			packet.getHeader(tcp);
			Event.fireEvent(target, new NextPacketEvent(packet.getFrameNumber(), packet.getHeader(tcp)));

//			System.out.printf("tcp.dst_port=%d%n", tcp.destination());
//			System.out.printf("tcp.src_port=%d%n", tcp.source());
//			System.out.printf("tcp.ack=%x%n", tcp.ack());

		} else {
			System.out.println("Something wrong, not firing event!");
		}

                /*
                 * An easier way of checking if header exists and peering with memory
                 * can be done using a conveniece method JPacket.hasHeader(? extends
                 * JHeader). This method performs both operations at once returning a
                 * boolean true or false. True means that header exists in the packet
                 * and our tcp header difinition object is peered or false if the header
                 * doesn't exist and no peering was performed.
                 */
		/*if (packet.hasHeader(tcp)) {
			//todo can get a lot of info from header
			System.out.printf("tcp header::%s%n", tcp.toString());
		}*/

                /*
                 * A typical and common approach to getting headers from a packet is to
                 * chain them as a condition for the if statement. If we need to work
                 * with both tcp and http headers, for example, we place both of them on
                 * the command line.
                 */
//		if (packet.hasHeader(tcp) && packet.hasHeader(http)) {
	                /*
                     * Now we are guarranteed to have both tcp and http header peered. If
                     * the packet only contained tcp segment even though tcp may have http
                     * port number, it still won't show up here since headers appear right
                     * at the beginning of http session.
                     */

//			System.out.printf("http header::%s%n", http);

                    /*
                     * jNetPcap keeps track of frame numbers for us. The number is simply
                     * incremented with every packet scanned.
                     */

//		}

		System.out.printf("frame #%d%n", packet.getFrameNumber());
	}

}
