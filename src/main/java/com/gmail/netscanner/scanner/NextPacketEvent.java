package com.gmail.netscanner.scanner;

import javafx.event.Event;
import javafx.event.EventType;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.protocol.tcpip.Tcp;

import java.util.Date;

/**
 * Created by le012ch on 2015-03-17.
 */
public class NextPacketEvent extends Event {

	private Tcp tcp;
	private long frameNumber;
	private PcapHeader captureHeader;
	private String hexDump;

	public NextPacketEvent(long frameNumber, Tcp tcp, PcapHeader captureHeader, String hexDump) {
		super(EventType.ROOT);
		this.frameNumber = frameNumber;
		this.tcp = tcp;
		this.captureHeader = captureHeader;
		this.hexDump = hexDump;
	}

	public String getChecksum() {
		return String.valueOf(tcp.checksum());
	}

	public long getFrameNumber() {
		return frameNumber;
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

	public String getTimestamp() {
		return new Date(captureHeader.timestampInMillis()).toString();
	}

	public String getHexDump() {
		return hexDump;
	}
}
