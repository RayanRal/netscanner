package com.gmail.netscanner;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Created by le012ch on 2015-02-13.
 */
public class NetScanner {

	public static void main(String[] args) throws IOException {
		InetAddress localhost = InetAddress.getLocalHost();
		// this code assumes IPv4 is used
		byte[] ip = localhost.getAddress();
		for (int i = 1; i <= 254; i++)
		{
			ip[3] = (byte)i;
			InetAddress address = InetAddress.getByAddress(ip);
			System.out.println("Started checking:" + address.getHostAddress());
			if (address.isReachable(10))
			{
				System.out.println(address.getHostAddress() + " is reachable");
			}
			else if (!address.getHostAddress().equals(address.getHostName()))
			{
				System.out.println(address.getHostName() + " is resolved");
			}
			else
			{
				// the host address and host name are equal, meaning the host name could not be resolved
			}
		}
	}

}
