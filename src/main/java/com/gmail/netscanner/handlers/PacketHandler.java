package com.gmail.netscanner.handlers;

import javafx.event.EventTarget;
import org.jnetpcap.packet.PcapPacketHandler;

/**
 * Created by le012ch on 2015-03-20.
 */
public abstract class PacketHandler<T> implements PcapPacketHandler<T> {

	final EventTarget target;

	protected PacketHandler(EventTarget target) {
		this.target = target;
	}

}
