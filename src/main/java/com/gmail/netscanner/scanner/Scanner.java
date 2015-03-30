package com.gmail.netscanner.scanner;

import com.gmail.netscanner.exceptions.DeviceAccessException;
import com.gmail.netscanner.exceptions.GetDeviceException;
import com.gmail.netscanner.utils.TcpSourceDestinationTuple;
import com.gmail.netscanner.utils.Utils;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Created by le012ch on 2015-03-20.
 */
public class Scanner {

	private static int snaplen = 64 * 1024;           // Capture all packets, no trucation
	private static int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
	private static int timeout = 10 * 1000;           // 10 seconds in millis
	private static volatile Pcap pcap;
	private static StringBuilder errorBuffer = new StringBuilder();

	//to diversify incoming and outgoing messages
	private static String ipv4Address;

	private static final List<String> outgoingHosts = new ArrayList<>();
	private static final List<String> incomingHosts = new ArrayList<>();

	private Scanner() {}

	//util method for finding devices
	public static List<PcapIf> findAllDevs() {
		List<PcapIf> alldevs = new ArrayList<>();
		int r = Pcap.findAllDevs(alldevs, errorBuffer);

		if (r != Pcap.OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errorBuffer.toString());
			throw new GetDeviceException(errorBuffer.toString());
		}

		return alldevs;
	}

	//double-checked locking in singleton done right, with volatile modifier
	// and local instance for speeding up
	public static Pcap initialize(PcapIf device) {
		Pcap localPcap = pcap;
		if (localPcap == null) {
			synchronized (Scanner.class) {
				if(localPcap == null) {
					/***************************************************************************
					 * We open up the selected device
					 **************************************************************************/
					pcap = localPcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errorBuffer);
				}
			}
		}
		if (pcap == null) {
			System.err.printf("Error while opening device for capture: " + errorBuffer);
			throw new DeviceAccessException(errorBuffer.toString());
		}

		ipv4Address = Utils.getIpv4Address(device);

		return pcap;
	}

	//this method should be called after initializing
	public static Pcap getPcap() {
		return pcap;
	}

	/***************************************************************************
	 * Last thing to do is close the pcap handle
	 *
	 * This method should be called from UI before exiting application (or when we want to stop capturing packets)
	 **************************************************************************/
	public static void closePcap() {
		pcap.close();
	}

	public static void addHost(TcpSourceDestinationTuple sourceDestinationTuple) {
		if(Objects.equals(sourceDestinationTuple.getSource(), ipv4Address)) {
			addOutgoingHost(sourceDestinationTuple.getDestination());
		} else {
			addIncomingHost(sourceDestinationTuple.getSource())
		}
	}

	private static boolean addIncomingHost(String host) {
		return incomingHosts.add(host);
	}

	private static boolean addOutgoingHost(String host) {
		return outgoingHosts.add(host);
	}

	public static List<String> getOutgoingHosts() {
		return outgoingHosts;
	}

	public static List<String> getIncomingHosts() {
		return incomingHosts;
	}
}
