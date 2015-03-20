package com.gmail.netscanner.handlers;

import com.gmail.netscanner.scanner.NextPacketEvent;
import javafx.event.Event;
import javafx.event.EventTarget;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.tcpip.Tcp;

public class TcpPacketHandler extends PacketHandler<Tcp> {

//	final Tcp tcp = new Tcp();

	/*
	 * Same thing for our http header
	 */
	public TcpPacketHandler(EventTarget target) {
		super(target);
	}

	/**
	 * Our custom handler that will receive all the packets libpcap will
	 * dispatch to us.
	 *
	 * @param packet a packet we captured
	 * @param tcp our custom user parameter which we chose to be a StringBuilder
	 *               object, but could have chosen anything else we wanted passed
	 *               into our handler by libpcap
	 */
	public void nextPacket(PcapPacket packet, Tcp tcp) {

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
			Event.fireEvent(target, new NextPacketEvent(packet.getFrameNumber(), packet.getHeader(tcp),
					packet.getCaptureHeader(), packet.toHexdump()));
			System.out.println("fired event!");
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}

		} else {
			System.out.println("Something wrong, not firing event!");
		}
	}

}
