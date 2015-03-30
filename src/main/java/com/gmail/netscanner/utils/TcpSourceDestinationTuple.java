package com.gmail.netscanner.utils;

/**
 * Created by le012ch on 2015-03-30.
 */
public class TcpSourceDestinationTuple {

	public String source;
	public String destination;

	public TcpSourceDestinationTuple(String source, String destination) {
		this.source = source;
		this.destination = destination;
	}

	public String getSource() {
		return source;
	}

	public String getDestination() {
		return destination;
	}
}
