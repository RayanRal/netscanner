package com.gmail.netscanner.scanner;

import org.jnetpcap.PcapHeader;
import org.jnetpcap.protocol.tcpip.Http;

/**
 * Created by le012ch on 2015-03-30.
 */
public class HttpPacketEvent extends PacketEvent {

	private Http http;

	public HttpPacketEvent(long frameNumber, Http http, PcapHeader captureHeader) {
		this.frameNumber = frameNumber;
		this.http = http;
		this.captureHeader = captureHeader;
	}




}
