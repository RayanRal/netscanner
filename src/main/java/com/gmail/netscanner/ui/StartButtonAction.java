package com.gmail.netscanner.ui;

import com.gmail.netscanner.handlers.AllPacketHandler;
import com.gmail.netscanner.scanner.Scanner;
import com.gmail.netscanner.utils.Utils;
import javafx.event.EventTarget;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.protocol.tcpip.Tcp;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Created by le012ch on 2015-03-17.
 */
public class StartButtonAction implements Runnable {

	private EventTarget httpTarget;
	private EventTarget tcpTarget;
	private Pcap pcap;
	private final ExecutorService executorService;

	public StartButtonAction(PcapIf device, EventTarget httpTarget, EventTarget tcpTarget) {
		this.httpTarget = httpTarget;
		this.tcpTarget = tcpTarget;
		pcap = Scanner.initialize(device);
		executorService = Executors.newSingleThreadExecutor();
	}

	@Override
	public void run() {

        /*
         * We still haven't read all the packets from our offline file. Here is an
         * easier way to retrieve all the packets while grouping them into flows.
         * jNetPcap provides a neat little class that does all of the above work for
         * us. Its called JFlowMap, not only that it implements a JPacketHandler
         * interface suitable for usage with Pcap.loop or Pcap.dispatch calls and it
         * will add all packets received into appropriate flows.
         */
//		JFlowMap superFlowMap = new JFlowMap();

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

//		System.out.printf("superFlowMap::%s%n", superFlowMap);



		/***************************************************************************
		 * Fourth we enter the loop and tell it to start capturing packets. The loop
		 * method does a mapping of pcap.datalink() DLT value to JProtocol ID, which
		 * is needed by JScanner. The scanner scans the packet buffer and decodes
		 * the headers. The mapping is done automatically, although a variation on
		 * the loop method exists that allows the programmer to specify exactly
		 * which protocol ID to use as the data link type for this pcap interface.
		 **************************************************************************/
		executorService.execute(() -> {
					pcap.loop(Pcap.LOOP_INFINITE, new AllPacketHandler(httpTarget, tcpTarget), new Tcp());
				}
		);
	}



}
