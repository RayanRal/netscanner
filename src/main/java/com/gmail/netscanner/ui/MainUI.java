package com.gmail.netscanner.ui;

import com.gmail.netscanner.scanner.HttpPacketEvent;
import com.gmail.netscanner.scanner.Scanner;
import com.gmail.netscanner.scanner.TcpPacketEvent;
import com.gmail.netscanner.utils.Utils;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.event.EventType;
import javafx.scene.Group;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.RadioButton;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleGroup;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.scene.text.Text;
import javafx.stage.Stage;
import org.jnetpcap.PcapIf;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by le012ch on 2015-03-17.
 */
public class MainUI extends Application {

	public static final String CHOOSE_NETWORK_INTERFACE = "Please, choose network interface to get data from: ";
	public static final String APP_NAME = "Net Scanner";
	public static final String TCP_TAB_NAME = "TCP package info";
	public static final String HTTP_TAB_NAME = "HTTP package info";
	public static final String TCP_HOSTS_TAB_NAME = "TCP hosts info";
	public static final String SETTINGS_TAB_NAME = "Settings";
	public static final String PACKET_CAPTURING_DELAY = "\n\nInput packet capturing delay in ms: ";

	PcapIf selectedDevice = Scanner.findAllDevs().get(0);
	Text tcpInfoText = getTcpInfoText();
	Text httpInfoText = getHttpInfoText();
	Button httpStartButton = createStartButton();
	Button tcpStartButton = createStartButton();
	TextField packetCapturingDelay = new TextField();

	@Override
	public void start(Stage primaryStage) throws Exception {
		TabPane tabPane = new TabPane();
		BorderPane borderPane = new BorderPane();
		borderPane.setCenter(tabPane);
		Group root = new Group();
		Scene scene = new Scene(root, 500, 300);
		borderPane.prefHeightProperty().bind(scene.heightProperty());
		borderPane.prefWidthProperty().bind(scene.widthProperty());

		Tab tcpTab = createTcpTab();
		Tab httpTab = createHttpTab();
		Tab tcpHostsTab = createTcpHostsTab();
		Tab settingsTab = createSettingsTab();

		tabPane.getTabs().addAll(tcpTab, httpTab, tcpHostsTab, settingsTab);
		root.getChildren().add(borderPane);

		primaryStage.setTitle(APP_NAME);
		primaryStage.setScene(scene);

		scene.setRoot(root);
		primaryStage.setScene(scene);

		primaryStage.show();
	}

	private Tab createTcpHostsTab() {
		Tab tcpHostsTab = new Tab(TCP_HOSTS_TAB_NAME);

		HBox tcpHostsBox = new HBox(50);

		VBox incomingBox = new VBox(10);
		VBox outgoingBox = new VBox(10);
		tcpHostsBox.getChildren().addAll(incomingBox, outgoingBox);

		incomingBox.getChildren().add(new Text("Incoming hosts: \n\n"));
		outgoingBox.getChildren().add(new Text("Outgoing hosts: \n\n"));

		Button refreshButton = new Button("Refresh");
		refreshButton.setOnAction(actionEvent -> {
			incomingBox.getChildren().clear();
			outgoingBox.getChildren().clear();

			incomingBox.getChildren().add(new Text("Incoming hosts: \n\n"));
			outgoingBox.getChildren().add(new Text("Outgoing hosts: \n\n"));

			fillHostsBox(incomingBox, Scanner.getIncomingHosts());
			fillHostsBox(outgoingBox, Scanner.getOutgoingHosts());
		});
		tcpHostsBox.getChildren().add(refreshButton);

		tcpHostsTab.setContent(tcpHostsBox);
		return tcpHostsTab;
	}

	private void fillHostsBox(VBox infoBox, List<String> hosts) {
		int i = 1;
		for(String host : hosts) {
			infoBox.getChildren().add(new Text(i + ": " + host));
			i++;
		}
	}

	private Tab createSettingsTab() throws IOException {
		Tab settingsTab = new Tab(SETTINGS_TAB_NAME);

		VBox mainBox = new VBox(10);

		Text choose = new Text(CHOOSE_NETWORK_INTERFACE);

		List<HBox> devicesList = getDevicesList();

		mainBox.getChildren().add(choose);
		mainBox.getChildren().addAll(devicesList);

		packetCapturingDelay.setPromptText("500");
		mainBox.getChildren().addAll(new Text(PACKET_CAPTURING_DELAY), packetCapturingDelay);

		settingsTab.setContent(mainBox);
		return settingsTab;
	}

	private List<HBox> getDevicesList() throws IOException {
		List<HBox> devicesUiInfo = new ArrayList<>();

		int deviceNumber = 1;
		final ToggleGroup group = new ToggleGroup();

		List<PcapIf> devices = Scanner.findAllDevs();
		for (PcapIf device : devices) {
			devicesUiInfo.add(getDeviceUiInfo(deviceNumber, group, device));
			deviceNumber++;
		}

		return devicesUiInfo;
	}

	private HBox getDeviceUiInfo(int deviceNumber, ToggleGroup group, PcapIf device) throws IOException {
		HBox deviceUiInfo = new HBox(10);

		String ipv4address = Utils.getIpv4Address(device);
		deviceUiInfo.getChildren().add(createRadioButton(deviceNumber, group, device));
		deviceUiInfo.getChildren().add(new Text(device.getDescription()));
		deviceUiInfo.getChildren().add(new Text(ipv4address));

		//get the mac of device
		final byte[] mac = device.getHardwareAddress();
		deviceUiInfo.getChildren().add(new Text(mac != null ? Utils.asString(mac) : "No MAC available"));

		return deviceUiInfo;
	}

	private RadioButton createRadioButton(int deviceNumber, ToggleGroup group, PcapIf device) {
		RadioButton radioButton = new RadioButton("" + deviceNumber);
		radioButton.setToggleGroup(group);
		if (deviceNumber == 1)
			radioButton.setSelected(true);
		radioButton.setOnAction(event -> selectedDevice = device);
		return radioButton;
	}

	private Tab createTcpTab() {
		Tab tcpTab = new Tab(TCP_TAB_NAME);

		HBox mainHorizontalBox = new HBox(30);

		VBox packageInfoBox = getTcpPackageInfoBox();
		mainHorizontalBox.getChildren().addAll(tcpStartButton, packageInfoBox);

		tcpTab.setContent(mainHorizontalBox);
		return tcpTab;
	}

	private Tab createHttpTab() {
		Tab httpTab = new Tab(HTTP_TAB_NAME);

		HBox mainHorizontalBox = new HBox(30);

		VBox packageInfoBox = getHttpPackageInfoBox();
		mainHorizontalBox.getChildren().addAll(httpStartButton, packageInfoBox);

		httpTab.setContent(mainHorizontalBox);
		return httpTab;
	}

	private VBox getHttpPackageInfoBox() {
		VBox box = new VBox(5);
		box.getChildren().add(httpInfoText);
		return box;
	}

	private VBox getTcpPackageInfoBox() {
		VBox box = new VBox(5);
		box.getChildren().add(tcpInfoText);
		return box;
	}

	private Text getTcpInfoText() {
		Text text = new Text("Here will be tcpInfoText!");
		text.addEventHandler(EventType.ROOT, event -> Platform.runLater(
						() -> {
							if (event instanceof TcpPacketEvent) {
								TcpPacketEvent packetEvent = (TcpPacketEvent) event;
								text.setText("Frame number: " + packetEvent.getFrameNumber() + "\n" +
										"Timestamp: " + packetEvent.getTimestamp() + "\n" +
										"Checksum: " + packetEvent.getChecksum() + " (" + packetEvent.isChecksumCorrect() + ")\n" +
										"Source: " + packetEvent.getTcpSource() + ":" + packetEvent.getSourcePort() + " \n" +
										"Destination: " + packetEvent.getDestination() + ":" + packetEvent.getDestinationPort() + "\n" +
										"\nHexDump: \n" + packetEvent.getHexDump() + "\n" +
										"");
							}
							event.consume();
						})
		);
		return text;
	}

	private Text getHttpInfoText() {
		Text text = new Text("Here will be httpInfoText!");
		text.addEventHandler(EventType.ROOT, event ->	Platform.runLater(
						() -> {
							if (event instanceof HttpPacketEvent) {
								HttpPacketEvent packetEvent = (HttpPacketEvent) event;
								text.setText("Frame number: " + packetEvent.getFrameNumber() + "\n" +
										"Timestamp: " + packetEvent.getTimestamp() + "\n" +
										"Content-type: " + packetEvent.getContentType() + "\n" +
										"Request-type: " + packetEvent.getRequestType() + "\n" +
										"Message-type: " + packetEvent.getMessageType() + "\n" +
										"Host: " + packetEvent.getHost() + "\n" +
										"Connection info: " + packetEvent.getConnectionInfo() + "\n" +
										"");
							}
							event.consume();
						})
		);
		return text;
	}

	private Button createStartButton() {
		Button startButton = new Button("Start catching packets");
		startButton.setOnAction(event -> {
			Integer packetDelay = packetCapturingDelay.getText().isEmpty() ? 500 : Integer.valueOf(packetCapturingDelay.getText());
			Platform.runLater(new StartButtonAction(selectedDevice, httpInfoText, tcpInfoText, packetDelay));
			httpStartButton.setVisible(false);
			tcpStartButton.setVisible(false);
		});
		return startButton;
	}

	public static void main(String[] args) {
		launch(args);
	}

}
