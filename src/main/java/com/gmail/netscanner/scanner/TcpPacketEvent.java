package com.gmail.netscanner.scanner;

import com.gmail.netscanner.utils.TcpSourceDestinationTuple;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import java.util.Objects;
import java.util.Optional;

/**
 * Created by le012ch on 2015-03-17.
 */
public class TcpPacketEvent extends PacketEvent {

	private Tcp tcp;
	private String hexDump;
	private TcpSourceDestinationTuple sourceDestinationTuple;

	public TcpPacketEvent(long frameNumber, Tcp tcp, PcapHeader captureHeader, String hexDump) {
		super(frameNumber, captureHeader);
		this.tcp = tcp;
		this.hexDump = hexDump;
		sourceDestinationTuple = new TcpSourceDestinationTuple(getValueFromHeader("source"), getValueFromHeader("destination"));
		Scanner.addHost(sourceDestinationTuple);
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

	public String getDestination() {
		return sourceDestinationTuple.getDestination();
	}

	public String getTcpSource() {
		return sourceDestinationTuple.getSource();
	}

	private String getValueFromHeader(String key) {
		Ip4 ip4 = new Ip4();
		tcp.getPacket().getHeader(ip4);
		String ip4String = ip4.toString();
		Optional<Integer> keyIndex = Optional.ofNullable(!ip4String.contains(key) ? null : ip4String.indexOf(key));
		return keyIndex.isPresent() ? ip4String.substring(keyIndex.get()).split(" |\n")[2] : "";
	}
}
