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
import java.awt.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Extension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("AydaAydor");

        Preferences prefs = api.persistence().preferences();
        Logging log = api.logging();

        AydaConfig config = new AydaConfig(prefs, log);
        config.load();

        // Startup project folder prompt (asks only for folder path)
        try {
            showProjectFolderDialog(config);
        } catch (Throwable t) {
            log.logToError("AydaAydor: Project folder dialog failed: " + t);
        }

        // Reload YAML-based project settings after folder selection
        try {
            // Calling save() will persist the selected folder and write YAML with current ignored params
            config.save();
        } catch (Throwable t) {
            log.logToError("AydaAydor: Failed to persist initial project settings: " + t);
        }

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

    private void showProjectFolderDialog(AydaConfig config) {
        JTextField dirField = new JTextField(30);
        Path existing = config.getProjectDir();
        if (existing != null) dirField.setText(existing.toString());
        JButton browse = new JButton("Browse...");
        browse.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            if (existing != null) fc.setCurrentDirectory(existing.toFile());
            int res = fc.showOpenDialog(null);
            if (res == JFileChooser.APPROVE_OPTION && fc.getSelectedFile() != null) {
                dirField.setText(fc.getSelectedFile().getAbsolutePath());
            }
        });

        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4,4,4,4);
        c.fill = GridBagConstraints.HORIZONTAL; c.weightx = 1;
        c.gridx = 0; c.gridy = 0; panel.add(new JLabel("Project folder"), c);
        JPanel dirPanel = new JPanel(new BorderLayout());
        dirPanel.add(dirField, BorderLayout.CENTER);
        dirPanel.add(browse, BorderLayout.EAST);
        c.gridx = 1; panel.add(dirPanel, c);

        int option = JOptionPane.showConfirmDialog(null, panel, "AydaAydor Setup", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (option == JOptionPane.OK_OPTION) {
            String dir = dirField.getText();
            if (dir != null && !dir.isBlank()) {
                Path p = Paths.get(dir.trim());
                try {
                    // Create subfolder aydaaydor
                    Path configDir = p.resolve("aydaaydor");
                    if (!Files.exists(configDir)) Files.createDirectories(configDir);
                    config.setProjectDir(p);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(null, "Failed to create project subfolder: " + ex.getMessage());
                }
            }
        }
    }
}
