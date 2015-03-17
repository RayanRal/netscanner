package com.gmail.netscanner.scanner;

import javafx.event.Event;
import javafx.event.EventType;

/**
 * Created by le012ch on 2015-03-17.
 */
public class NextPacketEvent extends Event {

	private String checksum;
	private boolean isChecksumCorrect;
	private String destinationPort;
	private String sourcePort;
	private String acknowledgement;

	public NextPacketEvent() {
		super(EventType.ROOT);
	}

	public void setChecksum(String checksum) {
		this.checksum = checksum;
	}

	public void setChecksumCorrect(boolean isChecksumCorrect) {
		this.isChecksumCorrect = isChecksumCorrect;
	}

	public void setDestinationPort(String destinationPort) {
		this.destinationPort = destinationPort;
	}

	public void setSourcePort(String sourcePort) {
		this.sourcePort = sourcePort;
	}

	public void setAcknowledgement(String acknowledgement) {
		this.acknowledgement = acknowledgement;
	}

	public String getChecksum() {
		return checksum;
	}

	public boolean isChecksumCorrect() {
		return isChecksumCorrect;
	}

	public String getDestinationPort() {
		return destinationPort;
	}

	public String getSourcePort() {
		return sourcePort;
	}

	public String getAcknowledgement() {
		return acknowledgement;
	}
}
