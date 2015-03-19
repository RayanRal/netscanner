package com.gmail.netscanner.scanner;

import javafx.event.Event;
import javafx.event.EventType;
import org.jnetpcap.protocol.tcpip.Tcp;

/**
 * Created by le012ch on 2015-03-17.
 */
public class NextPacketEvent extends Event {

	private Tcp tcp;
	private long frameNumber;

	public NextPacketEvent(long frameNumber, Tcp tcp) {
		super(EventType.ROOT);
		this.frameNumber = frameNumber;
		this.tcp = tcp;
	}

	public long getFrameNumber() {
		return frameNumber;
	}

	public boolean isChecksumCorrect() {
		return tcp.isChecksumValid();
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
}
