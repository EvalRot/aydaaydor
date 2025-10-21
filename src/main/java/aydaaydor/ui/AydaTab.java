package aydaaydor.ui;

import aydaaydor.config.AydaConfig;
import aydaaydor.config.DedupMode;
import aydaaydor.config.IdGroup;
import aydaaydor.scanner.ScannerControls;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.logging.Logging;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.Arrays;

import static java.util.stream.Collectors.toList;

public class AydaTab extends JPanel {
    private final AydaConfig config;
    private final Logging log;
    private final ScannerControls controls;
    private final DefaultListModel<String> groupsModel = new DefaultListModel<>();
    private final JList<String> groupsList = new JList<>(groupsModel);
    private final JTextArea idsArea = new JTextArea(10, 40);
    private final JLabel typeLabel = new JLabel("Type: ");
    private final JTextArea deniedArea = new JTextArea(6, 40);
    private final JCheckBox enabledBox = new JCheckBox("Enable scanning");
    private final JComboBox<DedupMode> dedupModeBox = new JComboBox<>(DedupMode.values());
    private final JTextField ttlHoursField = new JTextField(6);
    private final JTextField lruSizeField = new JTextField(6);

    // Ignored parameters UI
    private final DefaultListModel<String> ignoredModel = new DefaultListModel<>();
    private final JList<String> ignoredList = new JList<>(ignoredModel);
    private final JComboBox<HttpParameterType> paramTypeBox = new JComboBox<>(HttpParameterType.values());
    private final JTextField paramNameField = new JTextField(16);

    // Filtering UI
    private final DefaultListModel<String> ignoredHeadersModel = new DefaultListModel<>();
    private final JList<String> ignoredHeadersList = new JList<>(ignoredHeadersModel);
    private final JTextField ignoredHeaderField = new JTextField(16);

    private final DefaultListModel<String> skipExtModel = new DefaultListModel<>();
    private final JList<String> skipExtList = new JList<>(skipExtModel);
    private final JTextField skipExtField = new JTextField(10);

    private final JTextArea pathExcludeArea = new JTextArea(5, 40);

    // Ignored JSON keys UI (for response comparison)
    private final DefaultListModel<String> jsonKeysModel = new DefaultListModel<>();
    private final JList<String> jsonKeysList = new JList<>(jsonKeysModel);
    private final JTextField jsonKeyField = new JTextField(16);

    // Performance UI
    private final JTextField timeoutMsField = new JTextField(6);
    private final JTextField delayMsField = new JTextField(6);
    private final JTextField maxMutationsField = new JTextField(6);
    private final JTextField maxParallelField = new JTextField(6);

    public AydaTab(AydaConfig config, Logging log, ScannerControls controls) {
        super(new BorderLayout());
        this.config = config;
        this.log = log;
        this.controls = controls;
        buildUi();
        reloadFromConfig();
    }

    private void buildUi() {
        // Left: groups list + buttons
        JPanel left = new JPanel(new BorderLayout());
        left.setBorder(new TitledBorder("ID Groups"));
        groupsList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        groupsList.addListSelectionListener(e -> onGroupSelected());
        left.add(new JScrollPane(groupsList), BorderLayout.CENTER);

        JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT));
        btns.add(new JButton(new AbstractAction("Add Group") {
            @Override public void actionPerformed(ActionEvent e) { addGroupDialog(); }
        }));
        btns.add(new JButton(new AbstractAction("Remove Group") {
            @Override public void actionPerformed(ActionEvent e) { removeSelectedGroup(); }
        }));
        left.add(btns, BorderLayout.SOUTH);

        // Right: group details, denied strings, ignored parameters
        JPanel right = new JPanel();
        right.setLayout(new BoxLayout(right, BoxLayout.Y_AXIS));

        JPanel groupPanel = new JPanel(new BorderLayout());
        groupPanel.setBorder(new TitledBorder("Selected Group IDs"));
        idsArea.setLineWrap(true);
        idsArea.setWrapStyleWord(true);
        groupPanel.add(new JScrollPane(idsArea), BorderLayout.CENTER);
        JPanel grpSouth = new JPanel(new FlowLayout(FlowLayout.LEFT));
        grpSouth.add(typeLabel);
        grpSouth.add(new JButton(new AbstractAction("Save Group") {
            @Override public void actionPerformed(ActionEvent e) { saveCurrentGroup(); }
        }));
        groupPanel.add(grpSouth, BorderLayout.SOUTH);

        JPanel deniedPanel = new JPanel(new BorderLayout());
        deniedPanel.setBorder(new TitledBorder("Denied strings (one per line, case-insensitive)"));
        deniedArea.setLineWrap(true);
        deniedArea.setWrapStyleWord(true);
        deniedPanel.add(new JScrollPane(deniedArea), BorderLayout.CENTER);
        JPanel deniedSouth = new JPanel(new FlowLayout(FlowLayout.LEFT));
        deniedSouth.add(new JButton(new AbstractAction("Save Denied") {
            @Override public void actionPerformed(ActionEvent e) {
                var lines = Arrays.stream(deniedArea.getText().split("\n")).map(String::trim).filter(s -> !s.isEmpty()).collect(toList());
                config.setDeniedStrings(lines);
                config.save();
            }
        }));
        deniedPanel.add(deniedSouth, BorderLayout.SOUTH);

        enabledBox.setSelected(config.isEnabled());
        enabledBox.addActionListener(e -> { config.setEnabled(enabledBox.isSelected()); config.save(); });

            // Dedup panel
            JPanel dedupPanel = new JPanel();
            dedupPanel.setLayout(new BoxLayout(dedupPanel, BoxLayout.Y_AXIS));
            dedupPanel.setBorder(new TitledBorder("Deduplication"));

            JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT));
            row1.add(new JLabel("Mode:"));
            row1.add(dedupModeBox);
            row1.add(new JLabel("TTL (hours):"));
            row1.add(ttlHoursField);
            row1.add(new JLabel("LRU size:"));
            row1.add(lruSizeField);
            row1.add(new JButton(new AbstractAction("Save Dedup") {
                @Override public void actionPerformed(ActionEvent e) { saveDedupSettings(); }
            }));

            JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT));
            row2.add(new JButton(new AbstractAction("Clear scan cache") {
                @Override public void actionPerformed(ActionEvent e) { if (controls != null) controls.clearScanCache(); }
            }));
            row2.add(new JButton(new AbstractAction("Clear reported dedup") {
                @Override public void actionPerformed(ActionEvent e) { if (controls != null) controls.clearReportedCache(); }
            }));

            dedupPanel.add(row1);
            dedupPanel.add(row2);

            // Ignored parameters panel
            JPanel ignoredPanel = new JPanel(new BorderLayout());
            ignoredPanel.setBorder(new TitledBorder("Ignored parameters (type + name)"));
            ignoredList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
            ignoredPanel.add(new JScrollPane(ignoredList), BorderLayout.CENTER);
            JPanel ignoredSouth = new JPanel(new FlowLayout(FlowLayout.LEFT));
            ignoredSouth.add(new JLabel("Type:"));
            ignoredSouth.add(paramTypeBox);
            ignoredSouth.add(new JLabel("Name:"));
            ignoredSouth.add(paramNameField);
            ignoredSouth.add(new JButton(new AbstractAction("Add Ignore") {
                @Override public void actionPerformed(ActionEvent e) {
                    HttpParameterType t = (HttpParameterType) paramTypeBox.getSelectedItem();
                    String n = paramNameField.getText();
                    if (t == null || n == null || n.trim().isEmpty()) return;
                    config.addIgnoredParam(t, n.trim());
                    config.save();
                    reloadIgnoredParams();
                    paramNameField.setText("");
                }
            }));
            ignoredSouth.add(new JButton(new AbstractAction("Remove Selected") {
                @Override public void actionPerformed(ActionEvent e) {
                    for (String sel : ignoredList.getSelectedValuesList()) {
                        int c = sel.indexOf(':');
                        if (c > 0 && c + 1 < sel.length()) {
                            String type = sel.substring(0, c).trim();
                            String name = sel.substring(c + 1).trim();
                            try {
                                HttpParameterType t = HttpParameterType.valueOf(type);
                                config.removeIgnoredParam(t, name);
                            } catch (Exception ignored) {
                                // skip bad entries
                            }
                        }
                    }
                    config.save();
                    reloadIgnoredParams();
                }
            }));
            ignoredPanel.add(ignoredSouth, BorderLayout.SOUTH);

            // Filtering panels: headers, extensions, path regex
            JPanel filterPanel = new JPanel();
            filterPanel.setLayout(new BoxLayout(filterPanel, BoxLayout.Y_AXIS));

            JPanel hdrPanel = new JPanel(new BorderLayout());
            hdrPanel.setBorder(new TitledBorder("Ignored headers (case-insensitive)"));
            hdrPanel.add(new JScrollPane(ignoredHeadersList), BorderLayout.CENTER);
            JPanel hdrSouth = new JPanel(new FlowLayout(FlowLayout.LEFT));
            hdrSouth.add(new JLabel("Header:"));
            hdrSouth.add(ignoredHeaderField);
            hdrSouth.add(new JButton(new AbstractAction("Add") {
                @Override public void actionPerformed(ActionEvent e) {
                    String n = ignoredHeaderField.getText();
                    if (n == null || n.trim().isEmpty()) return;
                    var list = config.getIgnoredHeaders();
                    list.add(n.trim().toLowerCase());
                    config.setIgnoredHeaders(list);
                    config.save();
                    reloadFiltering();
                    ignoredHeaderField.setText("");
                }
            }));
            hdrSouth.add(new JButton(new AbstractAction("Remove Selected") {
                @Override public void actionPerformed(ActionEvent e) {
                    var list = config.getIgnoredHeaders();
                    for (String sel : ignoredHeadersList.getSelectedValuesList()) {
                        list.remove(sel.toLowerCase());
                    }
                    config.setIgnoredHeaders(list);
                    config.save();
                    reloadFiltering();
                }
            }));
            hdrPanel.add(hdrSouth, BorderLayout.SOUTH);

            JPanel extPanel = new JPanel(new BorderLayout());
            extPanel.setBorder(new TitledBorder("Skip extensions (e.g., .png)"));
            extPanel.add(new JScrollPane(skipExtList), BorderLayout.CENTER);
            JPanel extSouth = new JPanel(new FlowLayout(FlowLayout.LEFT));
            extSouth.add(new JLabel("Extension:"));
            extSouth.add(skipExtField);
            extSouth.add(new JButton(new AbstractAction("Add") {
                @Override public void actionPerformed(ActionEvent e) {
                    String n = skipExtField.getText();
                    if (n == null || n.trim().isEmpty()) return;
                    var list = config.getSkipExtensions();
                    String v = n.trim().toLowerCase();
                    if (!v.startsWith(".")) v = "." + v;
                    if (!list.contains(v)) list.add(v);
                    config.setSkipExtensions(list);
                    config.save();
                    reloadFiltering();
                    skipExtField.setText("");
                }
            }));
            extSouth.add(new JButton(new AbstractAction("Remove Selected") {
                @Override public void actionPerformed(ActionEvent e) {
                    var list = config.getSkipExtensions();
                    for (String sel : skipExtList.getSelectedValuesList()) list.remove(sel);
                    config.setSkipExtensions(list);
                    config.save();
                    reloadFiltering();
                }
            }));
            extPanel.add(extSouth, BorderLayout.SOUTH);

            JPanel pathPanel = new JPanel(new BorderLayout());
            pathPanel.setBorder(new TitledBorder("Path exclude regex (one per line)"));
            pathPanel.add(new JScrollPane(pathExcludeArea), BorderLayout.CENTER);
            JPanel pathSouth = new JPanel(new FlowLayout(FlowLayout.LEFT));
            pathSouth.add(new JButton(new AbstractAction("Save Paths") {
                @Override public void actionPerformed(ActionEvent e) {
                    java.util.List<String> lines = Arrays.stream(pathExcludeArea.getText().split("\n")).map(String::trim).filter(s -> !s.isEmpty()).collect(toList());
                    config.setPathExcludeRegex(lines);
                    config.save();
                }
            }));
            pathPanel.add(pathSouth, BorderLayout.SOUTH);

            // Ignored JSON keys panel
            JPanel jsonPanel = new JPanel(new BorderLayout());
            jsonPanel.setBorder(new TitledBorder("Ignored JSON keys (response compare)"));
            jsonPanel.add(new JScrollPane(jsonKeysList), BorderLayout.CENTER);
            JPanel jsonSouth = new JPanel(new FlowLayout(FlowLayout.LEFT));
            jsonSouth.add(new JLabel("Key:")); jsonSouth.add(jsonKeyField);
            jsonSouth.add(new JButton(new AbstractAction("Add") {
                @Override public void actionPerformed(ActionEvent e) {
                    String key = jsonKeyField.getText();
                    if (key == null || key.trim().isEmpty()) return;
                    var list = config.getIgnoredJsonKeys();
                    String v = key.trim(); // case-sensitive
                    if (!list.contains(v)) list.add(v);
                    config.setIgnoredJsonKeys(list);
                    config.save();
                    reloadFiltering();
                    jsonKeyField.setText("");
                }
            }));
            jsonSouth.add(new JButton(new AbstractAction("Remove Selected") {
                @Override public void actionPerformed(ActionEvent e) {
                    var list = config.getIgnoredJsonKeys();
                    for (String sel : jsonKeysList.getSelectedValuesList()) list.remove(sel);
                    config.setIgnoredJsonKeys(list);
                    config.save();
                    reloadFiltering();
                }
            }));
            jsonPanel.add(jsonSouth, BorderLayout.SOUTH);

            filterPanel.add(hdrPanel);
            filterPanel.add(Box.createVerticalStrut(8));
            filterPanel.add(extPanel);
            filterPanel.add(Box.createVerticalStrut(8));
            filterPanel.add(pathPanel);
            filterPanel.add(Box.createVerticalStrut(8));
            filterPanel.add(jsonPanel);

            // Performance panel
            JPanel perf = new JPanel(new FlowLayout(FlowLayout.LEFT));
            perf.setBorder(new TitledBorder("Performance"));
            perf.add(new JLabel("Timeout ms:")); perf.add(timeoutMsField);
            perf.add(new JLabel("Delay ms:")); perf.add(delayMsField);
            perf.add(new JLabel("Max mutations/base:")); perf.add(maxMutationsField);
            perf.add(new JLabel("Max parallel:")); perf.add(maxParallelField);
            perf.add(new JButton(new AbstractAction("Save Perf") {
                @Override public void actionPerformed(ActionEvent e) {
                    try {
                        config.setRequestTimeoutMs(Integer.parseInt(timeoutMsField.getText().trim()));
                        config.setDelayMsBetweenMutations(Integer.parseInt(delayMsField.getText().trim()));
                        config.setMaxMutationsPerBase(Integer.parseInt(maxMutationsField.getText().trim()));
                        config.setMaxParallelMutations(Integer.parseInt(maxParallelField.getText().trim()));
                        config.save();
                        if (controls != null) controls.applySettings();
                    } catch (Exception ex) {
                        JOptionPane.showMessageDialog(AydaTab.this, "Invalid performance values: " + ex.getMessage());
                    }
                }
            }));

            right.add(groupPanel);
            right.add(Box.createVerticalStrut(8));
            right.add(deniedPanel);
            right.add(Box.createVerticalStrut(8));
            right.add(filterPanel);
            right.add(Box.createVerticalStrut(8));
            right.add(ignoredPanel);
            right.add(Box.createVerticalStrut(8));
            right.add(enabledBox);
            right.add(Box.createVerticalStrut(8));
            right.add(dedupPanel);
            right.add(Box.createVerticalStrut(8));
            right.add(perf);

        add(left, BorderLayout.WEST);
        add(right, BorderLayout.CENTER);
    }

    private void reloadFromConfig() {
            groupsModel.clear();
            for (IdGroup g : config.allGroups()) groupsModel.addElement(g.name);
            if (!groupsModel.isEmpty()) groupsList.setSelectedIndex(0);
            deniedArea.setText(String.join("\n", config.getDeniedStrings()));
            // Dedup settings
            dedupModeBox.setSelectedItem(config.getDedupMode());
            ttlHoursField.setText(Long.toString(Math.max(1, config.getDedupTtlMillis() / (60 * 60 * 1000))));
            lruSizeField.setText(Integer.toString(config.getDedupLruMax()));
            reloadIgnoredParams();
            reloadFiltering();
            timeoutMsField.setText(Integer.toString(config.getRequestTimeoutMs()));
            delayMsField.setText(Integer.toString(config.getDelayMsBetweenMutations()));
            maxMutationsField.setText(Integer.toString(config.getMaxMutationsPerBase()));
            maxParallelField.setText(Integer.toString(config.getMaxParallelMutations()));
        }

    private void reloadIgnoredParams() {
        ignoredModel.clear();
        var map = config.allIgnoredParams();
        java.util.List<String> items = new java.util.ArrayList<>();
        for (var e : map.entrySet()) {
            if (e.getValue() == null) continue;
            java.util.List<String> names = new java.util.ArrayList<>(e.getValue());
            java.util.Collections.sort(names);
            for (String n : names) items.add(e.getKey().name() + ": " + n);
        }
        java.util.Collections.sort(items);
        for (String s : items) ignoredModel.addElement(s);
    }

    private void reloadFiltering() {
        ignoredHeadersModel.clear();
        for (String s : config.getIgnoredHeaders()) ignoredHeadersModel.addElement(s);
        skipExtModel.clear();
        for (String s : config.getSkipExtensions()) skipExtModel.addElement(s);
        pathExcludeArea.setText(String.join("\n", config.getPathExcludeRegex()));
        jsonKeysModel.clear();
        for (String s : config.getIgnoredJsonKeys()) jsonKeysModel.addElement(s);
    }

    private void onGroupSelected() {
        String name = groupsList.getSelectedValue();
        if (name == null) { idsArea.setText(""); typeLabel.setText("Type: "); return; }
        IdGroup g = config.getGroup(name);
        if (g == null) return;
        idsArea.setText(String.join("\n", g.ids));
        g.recalculateType();
        typeLabel.setText("Type: " + g.type);
    }

    private void addGroupDialog() {
        String name = JOptionPane.showInputDialog(this, "New group name:", "Add Group", JOptionPane.PLAIN_MESSAGE);
        if (name == null || name.isBlank()) return;
        if (config.getGroup(name) != null) {
            JOptionPane.showMessageDialog(this, "Group already exists.");
            return;
        }
        IdGroup g = new IdGroup(name.trim());
        config.addGroup(g);
        config.save();
        reloadFromConfig();
        groupsList.setSelectedValue(g.name, true);
    }

    private void removeSelectedGroup() {
        String name = groupsList.getSelectedValue();
        if (name == null) return;
        int opt = JOptionPane.showConfirmDialog(this, "Delete group '" + name + "'?", "Confirm", JOptionPane.OK_CANCEL_OPTION);
        if (opt != JOptionPane.OK_OPTION) return;
        config.removeGroup(name);
        config.save();
        reloadFromConfig();
    }

    private void saveCurrentGroup() {
        String name = groupsList.getSelectedValue();
        if (name == null) return;
        IdGroup g = config.getGroup(name);
        if (g == null) return;
        g.ids.clear();
        for (String line : idsArea.getText().split("\n")) {
            line = line.trim();
            if (!line.isEmpty()) g.ids.add(line);
        }
        g.recalculateType();
        config.save();
        typeLabel.setText("Type: " + g.type);
    }

    private void saveDedupSettings() {
        try {
            DedupMode mode = (DedupMode) dedupModeBox.getSelectedItem();
            long hours = Long.parseLong(ttlHoursField.getText().trim());
            int lru = Integer.parseInt(lruSizeField.getText().trim());
            config.setDedupMode(mode);
            config.setDedupTtlMillis(Math.max(0, hours) * 60L * 60L * 1000L);
            config.setDedupLruMax(lru);
            config.save();
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Invalid Dedup settings: " + ex.getMessage());
        }
    }
}
