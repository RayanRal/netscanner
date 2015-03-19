package com.gmail.netscanner.scanner;

import com.gmail.netscanner.exceptions.AccessDeviceException;
import com.gmail.netscanner.scanner.PcapPacketHandlerImpl;
import javafx.event.EventTarget;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JFlowMap;
import org.jnetpcap.packet.JScanner;

/**
 * Created by le012ch on 2015-03-17.
 */
public class StartButtonAction implements Runnable {

	private PcapIf device;
	private static int snaplen = 64 * 1024;           // Capture all packets, no trucation
	private static int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
	private static int timeout = 10 * 1000;           // 10 seconds in millis
	private EventTarget target;

	public StartButtonAction(PcapIf device, EventTarget target) {
		this.device = device;
		this.target = target;
	}

	public void setDevice(PcapIf device) {
		this.device = device;
	}

	public void setTarget(EventTarget target) {
		this.target = target;
	}

	@Override
	public void run() {
		/***************************************************************************
		 * We open up the selected device
		 **************************************************************************/
		Pcap pcap = getPcap();

		JScanner.getThreadLocal().setFrameNumber(0);

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
		 * Create a packet handler which will receive packets from the
		 * libpcap loop.
		 **************************************************************************/
		/***************************************************************************
		 * Fourth we enter the loop and tell it to capture 10 packets. The loop
		 * method does a mapping of pcap.datalink() DLT value to JProtocol ID, which
		 * is needed by JScanner. The scanner scans the packet buffer and decodes
		 * the headers. The mapping is done automatically, although a variation on
		 * the loop method exists that allows the programmer to sepecify exactly
		 * which protocol ID to use as the data link type for this pcap interface.
		 **************************************************************************/
		int x = 0;
		while(x < 1000) {
//			pcap.loop(Pcap.LOOP_INFINITE, new PcapPacketHandlerImpl<>(target), new StringBuffer("jNetPcap rocks!"));
			pcap.loop(1, new PcapPacketHandlerImpl<>(target), new StringBuffer("jNetPcap rocks!"));
			x++;
			System.out.println("x " + x);
			try {
				Thread.sleep(100);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}

		/***************************************************************************
		 * Last thing to do is close the pcap handle
		 **************************************************************************/
		pcap.close();
	}

	private Pcap getPcap() {
		StringBuilder errorBuffer = new StringBuilder();
		Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errorBuffer);

		if (pcap == null) {
			System.err.printf("Error while opening device for capture: " + errorBuffer);
			throw new AccessDeviceException(errorBuffer.toString());
		}

		return pcap;
	}

}
