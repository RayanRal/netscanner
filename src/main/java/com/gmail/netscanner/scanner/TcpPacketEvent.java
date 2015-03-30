package com.gmail.netscanner.scanner;

import org.jnetpcap.PcapHeader;
import org.jnetpcap.protocol.tcpip.Tcp;

/**
 * Created by le012ch on 2015-03-17.
 */
public class TcpPacketEvent extends PacketEvent {

	private Tcp tcp;
	private String hexDump;

	public TcpPacketEvent(long frameNumber, Tcp tcp, PcapHeader captureHeader, String hexDump) {
		this.frameNumber = frameNumber;
		this.tcp = tcp;
		this.captureHeader = captureHeader;
		this.hexDump = hexDump;
	}

	public String getChecksum() {
		return String.valueOf(tcp.checksum());
	}

	public String isChecksumCorrect() {
		return tcp.isChecksumValid() ? "correct" : "incorrect";
	}

	public String getDestinationPort() {
		return String.valueOf(tcp.destination());
	}

	public String getSourcePort() {
		return String.valueOf(tcp.source());
	}

	public String getAcknowledgement() {
		return String.valueOf(tcp.ack());
	}

	public String getHexDump() {
		return hexDump;
	}
}
