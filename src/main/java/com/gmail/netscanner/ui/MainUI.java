package com.gmail.netscanner.ui;

import com.gmail.netscanner.scanner.NetScanner;
import com.gmail.netscanner.scanner.StartButtonAction;
import com.gmail.netscanner.Utils;
import javafx.application.Application;
import javafx.application.Platform;
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

	NetScanner scanner = new NetScanner();
	PcapIf selectedDevice = scanner.findAllDevs().get(0);

	@Override
	public void start(Stage primaryStage) throws Exception {
		Group root = new Group();
		TabPane tabPane = new TabPane();
		BorderPane borderPane = new BorderPane();
		Scene scene = new Scene(root, 500, 300);
		borderPane.setCenter(tabPane);
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

		List<PcapIf> devices = scanner.findAllDevs();

		int deviceNumber = 1;
		final ToggleGroup group = new ToggleGroup();
		for (PcapIf device : devices) {
			HBox deviceUiInfo = new HBox(10);

			deviceUiInfo.getChildren().add(createRadioButton(deviceNumber, group, device));
			deviceUiInfo.getChildren().add(new Text(device.getName()));

//			String description = (device.getDescription() != null) ? device.getDescription() : "No description available";
//			deviceUiInfo.getChildren().add(new Text(description));

			//get the mac of device
			final byte[] mac = device.getHardwareAddress();
			deviceUiInfo.getChildren().add(new Text(mac != null ? Utils.asString(mac) : "No MAC available"));

			devicesUiInfo.add(deviceUiInfo);

			deviceNumber++;
		}

		return devicesUiInfo;
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
		Button startButton = new Button("Start catching packets");
		startButton.setOnAction(event -> Platform.runLater(new StartButtonAction(selectedDevice)));
		mainHorizontalBox.getChildren().add(startButton);

		mainTab.setContent(mainHorizontalBox);
		return mainTab;
	}

	public static void main(String[] args) {
		launch(args);
	}

}
