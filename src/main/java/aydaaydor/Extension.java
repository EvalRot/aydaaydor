package aydaaydor;

import aydaaydor.config.AydaConfig;
import aydaaydor.ui.AydaTab;
import aydaaydor.scanner.AydaScanner;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.Preferences;
import burp.api.montoya.ui.UserInterface;

import javax.swing.*;

public class Extension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("AydaAydor");

        Preferences prefs = api.persistence().preferences();
        Logging log = api.logging();

        AydaConfig config = new AydaConfig(prefs, log);
        config.load();

        // UI Tab
        UserInterface ui = api.userInterface();
        AydaScanner scanner = new AydaScanner(api, config);
        JPanel tab = new AydaTab(config, log, scanner);
        ui.applyThemeToComponent(tab);
        ui.registerSuiteTab("AydaAydor", tab);

        // HTTP handler
        api.http().registerHttpHandler(scanner);

        // Clean shutdown
        api.extension().registerUnloadingHandler(new ExtensionUnloadingHandler() {
            @Override
            public void extensionUnloaded() {
                scanner.shutdown();
                config.save();
            }
        });

        log.logToOutput("AydaAydor initialized. Ready to detect IDORs.");
    }
}
