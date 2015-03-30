package com.gmail.netscanner.scanner;

import org.jnetpcap.PcapHeader;
import org.jnetpcap.protocol.tcpip.Http;

import java.util.Arrays;
import java.util.Optional;

/**
 * Created by le012ch on 2015-03-30.
 */
public class HttpPacketEvent extends PacketEvent {

	private Http http;

	public HttpPacketEvent(long frameNumber, Http http, PcapHeader captureHeader) {
		super(frameNumber, captureHeader);
		this.http = http;
	}

	public String getContentType() {
		return http.contentType(); //todo check where to get - now null
	}

	public String getRequestType() {
		String header = http.header();
		return header.substring(0, header.indexOf(" "));
	}

	public String getHost() {
		return getValueFromHeader("Host: ");
	}

	public String getConnectionInfo() {
		return getValueFromHeader("Connection: ");
	}

	public String getMessageType() {
		return http.getMessageType().toString();
	}

	private String getValueFromHeader(String key) {
		String header = http.header();
		Optional<String> value = Arrays.asList(header.split("\n")).stream().filter(s -> s.startsWith(key)).findFirst();
		return value.isPresent() ? value.get().split(" ")[1] : "";
	}


}
