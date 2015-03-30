package com.gmail.netscanner.utils;

import org.jnetpcap.PcapIf;
import org.jnetpcap.PcapSockAddr;

public class Utils {

	public static String asString(final byte[] mac) {
		final StringBuilder buf = new StringBuilder();
		for (byte b : mac) {
			if (buf.length() != 0) {
				buf.append(':');
			}
			if (b >= 0 && b < 16) {
				buf.append('0');
			}
			buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
		}

		return buf.toString();
	}

	public static String getIpv4Address(PcapIf device) {
		return device.getAddresses().stream()
				.filter(pcapAddr -> pcapAddr.getAddr().getFamily() == PcapSockAddr.AF_INET) //AF_INET family - ipv4 address, AF_INET6 family - ipv6 address
				.findFirst()
				.get() //todo - add error handling
				.getAddr().toString()
				.substring(7).replaceAll("]", "");
	}
}
