package aydaaydor.ui;

import aydaaydor.config.AydaConfig;
import aydaaydor.config.DedupMode;
import aydaaydor.config.IdGroup;
import aydaaydor.scanner.ScannerControls;
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

        // Right: group details and denied strings
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

            right.add(groupPanel);
            right.add(Box.createVerticalStrut(8));
            right.add(deniedPanel);
            right.add(Box.createVerticalStrut(8));
            right.add(enabledBox);
            right.add(Box.createVerticalStrut(8));
            right.add(dedupPanel);

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
