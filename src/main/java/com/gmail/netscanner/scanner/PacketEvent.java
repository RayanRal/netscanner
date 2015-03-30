package com.gmail.netscanner.scanner;

import javafx.event.Event;
import javafx.event.EventType;
import org.jnetpcap.PcapHeader;

import java.util.Date;

/**
 * Created by le012ch on 2015-03-30.
 */
public abstract class PacketEvent extends Event {

	protected long frameNumber;
	protected PcapHeader captureHeader;

	public PacketEvent(long frameNumber, PcapHeader captureHeader) {
		super(EventType.ROOT);
		this.frameNumber = frameNumber;
		this.captureHeader = captureHeader;
	}

	public long getFrameNumber() {
		return frameNumber;
	}

	public String getTimestamp() {
		return new Date(captureHeader.timestampInMillis()).toString();
	}
}
