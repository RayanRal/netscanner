package com.gmail.netscanner.ui;

import com.gmail.netscanner.scanner.Scanner;
import com.gmail.netscanner.scanner.NextPacketEvent;
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
	public static final String SETTINGS_TAB_NAME = "Settings";
	public static final String APP_NAME = "Net Scanner";
	public static final String MAIN_TAB_NAME = "Main";

	PcapIf selectedDevice = Scanner.findAllDevs().get(0);
	Button startButton = createStartButton();
	Text text = getInfoText();

	@Override
	public void start(Stage primaryStage) throws Exception {
		TabPane tabPane = new TabPane();
		BorderPane borderPane = new BorderPane();
		borderPane.setCenter(tabPane);
		Group root = new Group();
		Scene scene = new Scene(root, 500, 300);
		borderPane.prefHeightProperty().bind(scene.heightProperty());
		borderPane.prefWidthProperty().bind(scene.widthProperty());

		Tab mainTab = createMainTab();
		Tab settingsTab = createSettingsTab();

		tabPane.getTabs().addAll(mainTab, settingsTab);
		root.getChildren().add(borderPane);

		primaryStage.setTitle(APP_NAME);
		primaryStage.setScene(scene);

		scene.setRoot(root);
		primaryStage.setScene(scene);

		primaryStage.show();
	}

	private Tab createSettingsTab() throws IOException {
		Tab settingsTab = new Tab(SETTINGS_TAB_NAME);

		VBox mainBox = new VBox(10);

		Text choose = new Text(CHOOSE_NETWORK_INTERFACE);

		List<HBox> devicesList = getDevicesList();

		mainBox.getChildren().add(choose);
		mainBox.getChildren().addAll(devicesList);

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

		deviceUiInfo.getChildren().add(createRadioButton(deviceNumber, group, device));
		deviceUiInfo.getChildren().add(new Text(device.getName()));

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

	private Tab createMainTab() {
		Tab mainTab = new Tab(MAIN_TAB_NAME);

		HBox mainHorizontalBox = new HBox(30);

		VBox packageInfoBox = getPackageInfoBox();
		mainHorizontalBox.getChildren().addAll(startButton, packageInfoBox);

		mainTab.setContent(mainHorizontalBox);
		return mainTab;
	}

	private VBox getPackageInfoBox() {
		VBox box = new VBox(5);
		box.getChildren().add(text);
		return box;
	}

	private Text getInfoText() {
		Text text = new Text("Here will be text!");
		text.addEventHandler(EventType.ROOT, event ->	Platform.runLater(
						() -> {
							if (event instanceof NextPacketEvent) {
								NextPacketEvent packetEvent = (NextPacketEvent) event;
								text.setText("Frame number: " + packetEvent.getFrameNumber() + "\n" +
										"Timestamp: " + packetEvent.getTimestamp() + "\n" +
										"Checksum: " + packetEvent.getChecksum() + " (" + packetEvent.isChecksumCorrect() + ")\n" +
										"Source: " + packetEvent.getSourcePort() + "\n" +
										"Destination: " + packetEvent.getDestinationPort() + "\n" +
										"\nHexDump: \n" + packetEvent.getHexDump() + "\n" +
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
			Platform.runLater(new StartButtonAction(selectedDevice, text));
			startButton.setVisible(false);
		});
		return startButton;
	}

	public static void main(String[] args) {
		launch(args);
	}

}
