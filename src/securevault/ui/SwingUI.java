package securevault.ui;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import javax.swing.SwingWorker;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.plaf.basic.BasicButtonUI;
import securevault.enums.PasswordStrength;
import securevault.exception.ValidationException;
import securevault.model.Account;
import securevault.model.AccountAnalysis;
import securevault.model.SecurityReport;
import securevault.persistence.FileStore;
import securevault.security.SecurityAnalysisEngine;
import securevault.service.AccountService;
import securevault.service.AuthenticationService;

/** Clean Swing presentation layer backed by the existing services. */
public final class SwingUI {
    static final Color PRIMARY = new Color(31, 78, 121);
    static final Color PRIMARY_DARK = new Color(23, 58, 91);
    static final Color BACKGROUND = new Color(244, 247, 250);
    static final Color CARD = Color.WHITE;
    static final Color TEXT = new Color(31, 41, 55);
    static final Color MUTED = new Color(100, 116, 139);
    static final Color DANGER = new Color(180, 48, 48);

    private final FileStore store;
    private final AuthenticationService authentication;
    private final SecurityAnalysisEngine analysisEngine = new SecurityAnalysisEngine();
    private final JFrame frame = new JFrame("SecureVault");
    private final CardLayout rootLayout = new CardLayout();
    private final JPanel root = new JPanel(rootLayout);
    private final CardLayout contentLayout = new CardLayout();
    private final JPanel content = new JPanel(contentLayout);
    private final DefaultTableModel accountModel = new DefaultTableModel(
            new String[] {"Platform", "Username / Email", "Category", "Password"}, 0) {
        @Override public boolean isCellEditable(int row, int column) { return false; }
    };
    private final JTable accountTable = new JTable(accountModel);
    private final JTextField searchField = new JTextField(24);
    private final JLabel accountCount = new JLabel("0 accounts");
    private final JPanel reportPanel = new JPanel(new BorderLayout(12, 12));
    private final JPanel advicePanel = new JPanel(new BorderLayout(12, 12));
    private AccountService session;
    private List<Account> visibleAccounts = List.of();
    private boolean storeClosed;
    private boolean busy;

    public SwingUI(FileStore store) {
        this.store = store;
        authentication = new AuthenticationService(store);
        configureLookAndFeel();
        buildFrame();
    }

    public void show() { frame.setVisible(true); }

    private void configureLookAndFeel() {
        try { UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName()); }
        catch (ReflectiveOperationException | javax.swing.UnsupportedLookAndFeelException ignored) { }
        UIManager.put("Button.font", new Font(Font.SANS_SERIF, Font.PLAIN, 14));
        UIManager.put("Label.font", new Font(Font.SANS_SERIF, Font.PLAIN, 14));
        UIManager.put("TextField.font", new Font(Font.SANS_SERIF, Font.PLAIN, 14));
        UIManager.put("PasswordField.font", new Font(Font.SANS_SERIF, Font.PLAIN, 14));
        UIManager.put("Table.font", new Font(Font.SANS_SERIF, Font.PLAIN, 14));
        UIManager.put("TableHeader.font", new Font(Font.SANS_SERIF, Font.BOLD, 13));
    }

    private void buildFrame() {
        frame.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        frame.setMinimumSize(new Dimension(1000, 680));
        frame.setSize(1180, 760);
        frame.setLocationRelativeTo(null);
        frame.addWindowListener(new WindowAdapter() {
            @Override public void windowClosing(WindowEvent event) { shutdown(); }
        });
        root.add(buildAuthenticationScreen(), "auth");
        root.add(buildDashboard(), "dashboard");
        frame.setContentPane(root);
        rootLayout.show(root, "auth");
    }

    private JPanel buildAuthenticationScreen() {
        JPanel background = new JPanel(new GridBagLayout());
        background.setBackground(BACKGROUND);
        JPanel card = new JPanel(new BorderLayout(0, 18));
        card.setBackground(CARD);
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(218, 226, 235)), new EmptyBorder(28, 34, 30, 34)));
        card.setPreferredSize(new Dimension(520, 520));

        JPanel heading = new JPanel();
        heading.setOpaque(false);
        heading.setLayout(new BoxLayout(heading, BoxLayout.Y_AXIS));
        JLabel title = new JLabel("SecureVault");
        title.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 30));
        title.setForeground(PRIMARY_DARK);
        title.setAlignmentX(Component.CENTER_ALIGNMENT);
        JLabel subtitle = new JLabel("Personal Digital Security Advisor");
        subtitle.setForeground(MUTED);
        subtitle.setAlignmentX(Component.CENTER_ALIGNMENT);
        heading.add(title);
        heading.add(Box.createVerticalStrut(6));
        heading.add(subtitle);

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Login", loginPanel());
        tabs.addTab("Register", registrationPanel(tabs));
        card.add(heading, BorderLayout.NORTH);
        card.add(tabs, BorderLayout.CENTER);
        background.add(card);
        return background;
    }

    private JPanel loginPanel() {
        JPanel panel = formPanel();
        JTextField username = new JTextField(26);
        JPasswordField password = new JPasswordField(26);
        styleField(username);
        styleField(password);
        JButton login = primaryButton("Login securely");
        addFormField(panel, 0, "Username or email", username);
        addFormField(panel, 1, "Password", password);
        addWide(panel, 2, login);
        JLabel note = smallNote("Five failed attempts lock login for 60 seconds.");
        addWide(panel, 3, note);
        login.addActionListener(event -> {
            String enteredUsername = username.getText();
            char[] entered = password.getPassword();
            runAsync(() -> {
                try { return authentication.login(enteredUsername, entered); }
                finally { Arrays.fill(entered, '\0'); }
            }, openedSession -> {
                session = openedSession;
                password.setText("");
                openDashboard();
            });
        });
        return panel;
    }

    private JPanel registrationPanel(JTabbedPane tabs) {
        JPanel panel = formPanel();
        JTextField username = new JTextField(26);
        JPasswordField password = new JPasswordField(26);
        JPasswordField confirmation = new JPasswordField(26);
        styleField(username);
        styleField(password);
        styleField(confirmation);
        JButton register = primaryButton("Create account");
        addFormField(panel, 0, "Username or email", username);
        addFormField(panel, 1, "Password (12-256 characters)", password);
        addFormField(panel, 2, "Confirm password", confirmation);
        addWide(panel, 3, register);
        addWide(panel, 4, smallNote("There is no password recovery. Use fictional data for demonstrations."));
        register.addActionListener(event -> {
            String enteredUsername = username.getText();
            char[] entered = password.getPassword();
            char[] repeated = confirmation.getPassword();
            if (!Arrays.equals(entered, repeated)) {
                Arrays.fill(entered, '\0');
                Arrays.fill(repeated, '\0');
                message(frame, "The password confirmation does not match.", true);
                return;
            }
            runAsync(() -> {
                try {
                    authentication.register(enteredUsername, entered);
                    return null;
                } finally {
                    Arrays.fill(entered, '\0');
                    Arrays.fill(repeated, '\0');
                }
            }, ignored -> {
                username.setText("");
                password.setText("");
                confirmation.setText("");
                tabs.setSelectedIndex(0);
                message(frame, "Registration complete. You can now log in.", false);
            });
        });
        return panel;
    }

    private JPanel buildDashboard() {
        JPanel dashboard = new JPanel(new BorderLayout());
        dashboard.setBackground(BACKGROUND);
        dashboard.add(buildHeader(), BorderLayout.NORTH);
        dashboard.add(buildSidebar(), BorderLayout.WEST);
        content.setBackground(BACKGROUND);
        content.setBorder(new EmptyBorder(22, 24, 24, 24));
        content.add(accountsPanel(), "accounts");
        content.add(reportPanel, "report");
        content.add(advicePanel, "advice");
        dashboard.add(content, BorderLayout.CENTER);
        return dashboard;
    }

    private JPanel buildHeader() {
        JPanel header = new JPanel(new BorderLayout());
        header.setBackground(PRIMARY_DARK);
        header.setBorder(new EmptyBorder(16, 22, 16, 22));
        JLabel title = new JLabel("SecureVault");
        title.setForeground(Color.WHITE);
        title.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 22));
        JLabel subtitle = new JLabel("Personal Digital Security Advisor");
        subtitle.setForeground(new Color(205, 221, 237));
        header.add(title, BorderLayout.WEST);
        header.add(subtitle, BorderLayout.EAST);
        return header;
    }

    private JPanel buildSidebar() {
        JPanel sidebar = new JPanel();
        sidebar.setLayout(new BoxLayout(sidebar, BoxLayout.Y_AXIS));
        sidebar.setBackground(CARD);
        sidebar.setBorder(new EmptyBorder(20, 14, 18, 14));
        sidebar.setPreferredSize(new Dimension(210, 0));
        JLabel section = new JLabel("NAVIGATION");
        section.setForeground(MUTED);
        section.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        section.setAlignmentX(Component.LEFT_ALIGNMENT);
        sidebar.add(section);
        sidebar.add(Box.createVerticalStrut(12));
        sidebar.add(navButton("Accounts", () -> showContent("accounts")));
        sidebar.add(Box.createVerticalStrut(8));
        sidebar.add(navButton("Security report", this::showReport));
        sidebar.add(Box.createVerticalStrut(8));
        sidebar.add(navButton("Recommendations", this::showAdvice));
        sidebar.add(Box.createVerticalGlue());
        sidebar.add(new JSeparator());
        sidebar.add(Box.createVerticalStrut(12));
        JButton logout = secondaryButton("Logout");
        logout.setAlignmentX(Component.LEFT_ALIGNMENT);
        logout.setMaximumSize(new Dimension(Integer.MAX_VALUE, 42));
        logout.addActionListener(event -> logout());
        sidebar.add(logout);
        return sidebar;
    }

    private JPanel accountsPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 14));
        panel.setOpaque(false);
        JPanel titleRow = new JPanel(new BorderLayout());
        titleRow.setOpaque(false);
        titleRow.add(pageTitle("Your accounts", "Manage the fictional accounts used for security analysis."), BorderLayout.WEST);
        accountCount.setForeground(MUTED);
        titleRow.add(accountCount, BorderLayout.EAST);

        JPanel tools = new JPanel();
        tools.setLayout(new BoxLayout(tools, BoxLayout.Y_AXIS));
        tools.setOpaque(false);
        JPanel searchRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        searchRow.setOpaque(false);
        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        actionRow.setOpaque(false);
        searchField.putClientProperty("JTextField.placeholderText", "Search accounts");
        styleField(searchField);
        JButton search = secondaryButton("Search");
        JButton clear = secondaryButton("Show all");
        JButton add = primaryButton("Add account");
        JButton edit = secondaryButton("Update");
        JButton delete = dangerButton("Delete");
        searchRow.add(searchField);
        searchRow.add(search);
        searchRow.add(clear);
        actionRow.add(add);
        actionRow.add(edit);
        actionRow.add(delete);
        tools.add(searchRow);
        tools.add(Box.createVerticalStrut(9));
        tools.add(actionRow);

        accountTable.setRowHeight(34);
        accountTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        accountTable.setFillsViewportHeight(true);
        accountTable.getTableHeader().setReorderingAllowed(false);
        JScrollPane scroll = new JScrollPane(accountTable);
        scroll.setBorder(BorderFactory.createLineBorder(new Color(218, 226, 235)));

        JPanel center = new JPanel(new BorderLayout(0, 12));
        center.setOpaque(false);
        center.add(tools, BorderLayout.NORTH);
        center.add(scroll, BorderLayout.CENTER);
        panel.add(titleRow, BorderLayout.NORTH);
        panel.add(center, BorderLayout.CENTER);

        search.addActionListener(event -> refreshAccounts(searchField.getText()));
        searchField.addActionListener(event -> refreshAccounts(searchField.getText()));
        clear.addActionListener(event -> { searchField.setText(""); refreshAccounts(""); });
        add.addActionListener(event -> addAccount());
        edit.addActionListener(event -> updateAccount());
        delete.addActionListener(event -> deleteAccount());
        accountTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mouseClicked(java.awt.event.MouseEvent event) {
                if (event.getClickCount() == 2) { updateAccount(); }
            }
        });
        return panel;
    }

    private void openDashboard() {
        frame.setTitle("SecureVault - " + session.getUsername());
        searchField.setText("");
        refreshAccounts("");
        showContent("accounts");
        rootLayout.show(root, "dashboard");
    }

    private void refreshAccounts(String query) {
        visibleAccounts = query == null || query.isBlank() ? session.list() : session.search(query);
        accountModel.setRowCount(0);
        for (Account account : visibleAccounts) {
            accountModel.addRow(new Object[] {account.getPlatform(), account.getUsername(), account.getType(), "Hidden"});
        }
        accountCount.setText(visibleAccounts.size() + (visibleAccounts.size() == 1 ? " account" : " accounts"));
    }

    private void addAccount() {
        AccountDialog dialog = new AccountDialog(frame, null);
        if (!dialog.open()) { return; }
        char[] password = dialog.getPassword();
        try {
            session.add(dialog.getPlatform(), dialog.getUsername(), dialog.getAccountType(), password);
            refreshAccounts(searchField.getText());
            message(frame, "Account added and encrypted successfully.", false);
        } catch (ValidationException | IOException | GeneralSecurityException exception) {
            operationError(exception);
        } finally { Arrays.fill(password, '\0'); }
    }

    private void updateAccount() {
        Account selected = selectedAccount();
        if (selected == null) { return; }
        AccountDialog dialog = new AccountDialog(frame, selected);
        if (!dialog.open()) { return; }
        char[] password = dialog.getPassword();
        if (password.length == 0) { password = selected.copyPassword(); }
        try {
            session.update(selected.getId(), dialog.getPlatform(), dialog.getUsername(), dialog.getAccountType(), password);
            refreshAccounts(searchField.getText());
            message(frame, "Account updated and saved.", false);
        } catch (ValidationException | IOException | GeneralSecurityException exception) {
            operationError(exception);
        } finally { Arrays.fill(password, '\0'); }
    }

    private void deleteAccount() {
        Account selected = selectedAccount();
        if (selected == null) { return; }
        int answer = JOptionPane.showConfirmDialog(frame,
                "Delete " + selected.getPlatform() + " (" + selected.getUsername() + ")?\nThis cannot be undone.",
                "Confirm deletion", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (answer != JOptionPane.YES_OPTION) { return; }
        try {
            session.delete(selected.getId());
            refreshAccounts(searchField.getText());
            message(frame, "Account deleted.", false);
        } catch (ValidationException | IOException | GeneralSecurityException exception) {
            operationError(exception);
        }
    }

    private Account selectedAccount() {
        int row = accountTable.getSelectedRow();
        if (row < 0 || row >= visibleAccounts.size()) {
            message(frame, "Select an account from the table first.", true);
            return null;
        }
        return visibleAccounts.get(row);
    }

    private void showReport() {
        SecurityReport report = analysisEngine.analyze(session.list());
        reportPanel.removeAll();
        reportPanel.setOpaque(false);
        reportPanel.add(pageTitle("Security report", "A fresh analysis of all saved accounts."), BorderLayout.NORTH);
        if (report.getAnalyses().isEmpty()) {
            reportPanel.add(emptyState("No report yet", "Add at least one account to calculate a security score."), BorderLayout.CENTER);
        } else {
            JPanel body = new JPanel(new BorderLayout(0, 16));
            body.setOpaque(false);
            body.add(metricCards(report), BorderLayout.NORTH);
            body.add(reportTable(report), BorderLayout.CENTER);
            reportPanel.add(body, BorderLayout.CENTER);
        }
        showContent("report");
    }

    private JPanel metricCards(SecurityReport report) {
        JPanel metrics = new JPanel(new GridLayout(1, 5, 10, 0));
        metrics.setOpaque(false);
        metrics.add(metric("Security score", report.getScore() + "/100", scoreColor(report.getScore())));
        metrics.add(metric("Total accounts", Integer.toString(report.getAnalyses().size()), PRIMARY));
        metrics.add(metric("Reuse affected", Long.toString(report.getReusedAccountCount()), DANGER));
        metrics.add(metric("Similar affected", Long.toString(report.getSimilarPasswordAccountCount()),
                new Color(190, 125, 15)));
        metrics.add(metric("High / critical", Long.toString(report.getHighRiskCount()), DANGER));
        return metrics;
    }

    private JScrollPane reportTable(SecurityReport report) {
        DefaultTableModel model = new DefaultTableModel(
                new String[] {"Platform", "Strength", "Risk", "Score", "Calculation", "Findings"}, 0) {
            @Override public boolean isCellEditable(int row, int column) { return false; }
        };
        for (AccountAnalysis result : report.getAnalyses()) {
            StringBuilder findings = new StringBuilder();
            if (result.getReuseCount() > 1) { findings.append("Reused across ").append(result.getReuseCount()).append(" accounts"); }
            result.getSimilarPasswords().forEach(match -> {
                if (!findings.isEmpty()) { findings.append("; "); }
                findings.append("Similar to ").append(match.otherPlatform()).append(": ").append(match.reason());
            });
            for (String pattern : result.getPatterns()) {
                if (!findings.isEmpty()) { findings.append("; "); }
                findings.append(pattern);
            }
            if (findings.isEmpty()) { findings.append("No issues detected"); }
            String calculation = result.getStrength().getBaseScore() + " - " + result.getReusePenalty()
                    + " - " + result.getSimilarityPenalty() + " - " + result.getPatternPenalty()
                    + " = " + result.getScore();
            model.addRow(new Object[] {result.getPlatform(), result.getStrength(), result.getRisk(),
                    result.getScore() + "/100", calculation, findings});
        }
        JTable table = new JTable(model);
        table.setRowHeight(34);
        table.setFillsViewportHeight(true);
        table.getTableHeader().setReorderingAllowed(false);
        table.getColumnModel().getColumn(4).setPreferredWidth(170);
        table.getColumnModel().getColumn(5).setPreferredWidth(380);
        JScrollPane scroll = new JScrollPane(table);
        scroll.setBorder(BorderFactory.createLineBorder(new Color(218, 226, 235)));
        return scroll;
    }

    private void showAdvice() {
        SecurityReport report = analysisEngine.analyze(session.list());
        advicePanel.removeAll();
        advicePanel.setOpaque(false);
        advicePanel.add(pageTitle("Recommendations", "Advice created from the current analysis findings."), BorderLayout.NORTH);
        if (report.getAnalyses().isEmpty()) {
            advicePanel.add(emptyState("No recommendations yet", "Add an account to receive personalized advice."), BorderLayout.CENTER);
        } else {
            JList<String> list = new JList<>(report.getRecommendations().toArray(String[]::new));
            list.setFixedCellHeight(38);
            list.setBorder(new EmptyBorder(8, 10, 8, 10));
            list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            JScrollPane scroll = new JScrollPane(list);
            scroll.setBorder(BorderFactory.createLineBorder(new Color(218, 226, 235)));
            advicePanel.add(scroll, BorderLayout.CENTER);
        }
        showContent("advice");
    }

    private void logout() {
        if (session != null) {
            session.close();
            session = null;
        }
        frame.setTitle("SecureVault");
        rootLayout.show(root, "auth");
    }

    private void shutdown() {
        if (busy) {
            message(frame, "Please wait for the current secure operation to finish.", true);
            return;
        }
        if (session != null) { session.close(); session = null; }
        if (!storeClosed) {
            try { store.close(); }
            catch (IOException exception) { message(frame, "Could not close the data store cleanly: " + exception.getMessage(), true); }
            storeClosed = true;
        }
        frame.dispose();
    }

    private void showContent(String name) {
        contentLayout.show(content, name);
        content.revalidate();
        content.repaint();
    }

    private void operationError(Exception exception) {
        if (exception instanceof ValidationException) { message(frame, exception.getMessage(), true); }
        else if (exception instanceof IOException) { message(frame, "File operation failed: " + exception.getMessage(), true); }
        else { message(frame, "The secure vault operation failed. Existing data was not changed.", true); }
    }

    private <T> void runAsync(Callable<T> task, Consumer<T> onSuccess) {
        busy = true;
        frame.getGlassPane().setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.WAIT_CURSOR));
        frame.getGlassPane().setVisible(true);
        new SwingWorker<T, Void>() {
            @Override protected T doInBackground() throws Exception { return task.call(); }

            @Override protected void done() {
                try {
                    onSuccess.accept(get());
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    message(frame, "The operation was interrupted. Please try again.", true);
                } catch (ExecutionException exception) {
                    Throwable cause = exception.getCause();
                    if (cause instanceof ValidationException) { message(frame, cause.getMessage(), true); }
                    else if (cause instanceof IOException) { message(frame, "File operation failed: " + cause.getMessage(), true); }
                    else if (cause instanceof GeneralSecurityException) {
                        message(frame, "The secure vault operation failed. Existing data was not changed.", true);
                    } else {
                        message(frame, "Unexpected error: " + cause.getMessage(), true);
                    }
                } finally {
                    busy = false;
                    frame.getGlassPane().setVisible(false);
                    frame.getGlassPane().setCursor(java.awt.Cursor.getDefaultCursor());
                }
            }
        }.execute();
    }

    private JPanel formPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setOpaque(false);
        panel.setBorder(new EmptyBorder(8, 18, 8, 18));
        return panel;
    }

    private void addFormField(JPanel panel, int row, String label, Component field) {
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.gridx = 0;
        constraints.gridy = row * 2;
        constraints.weightx = 1;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.anchor = GridBagConstraints.WEST;
        constraints.insets = new Insets(6, 0, 4, 0);
        panel.add(new JLabel(label), constraints);
        constraints.gridy++;
        constraints.insets = new Insets(0, 0, 8, 0);
        panel.add(field, constraints);
    }

    private void addWide(JPanel panel, int row, Component component) {
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.gridx = 0;
        constraints.gridy = row * 2;
        constraints.weightx = 1;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.insets = new Insets(10, 0, 4, 0);
        panel.add(component, constraints);
    }

    private JPanel pageTitle(String title, String subtitle) {
        JPanel panel = new JPanel();
        panel.setOpaque(false);
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        JLabel titleLabel = new JLabel(title);
        titleLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 24));
        titleLabel.setForeground(TEXT);
        JLabel subtitleLabel = new JLabel(subtitle);
        subtitleLabel.setForeground(MUTED);
        panel.add(titleLabel);
        panel.add(Box.createVerticalStrut(4));
        panel.add(subtitleLabel);
        return panel;
    }

    private JPanel metric(String label, String value, Color color) {
        JPanel card = new JPanel(new BorderLayout(0, 5));
        card.setBackground(CARD);
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(218, 226, 235)), new EmptyBorder(16, 18, 16, 18)));
        JLabel valueLabel = new JLabel(value);
        valueLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 25));
        valueLabel.setForeground(color);
        JLabel labelText = new JLabel(label);
        labelText.setForeground(MUTED);
        card.add(valueLabel, BorderLayout.CENTER);
        card.add(labelText, BorderLayout.SOUTH);
        return card;
    }

    private JPanel emptyState(String title, String text) {
        JPanel card = new JPanel(new GridBagLayout());
        card.setBackground(CARD);
        card.setBorder(BorderFactory.createLineBorder(new Color(218, 226, 235)));
        JPanel copy = new JPanel();
        copy.setOpaque(false);
        copy.setLayout(new BoxLayout(copy, BoxLayout.Y_AXIS));
        JLabel heading = new JLabel(title);
        heading.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 20));
        heading.setForeground(TEXT);
        heading.setAlignmentX(Component.CENTER_ALIGNMENT);
        JLabel body = new JLabel(text);
        body.setForeground(MUTED);
        body.setAlignmentX(Component.CENTER_ALIGNMENT);
        copy.add(heading);
        copy.add(Box.createVerticalStrut(8));
        copy.add(body);
        card.add(copy);
        return card;
    }

    private JButton navButton(String text, Runnable action) {
        JButton button = new JButton(text);
        standardizeButton(button);
        button.setHorizontalAlignment(SwingConstants.LEFT);
        button.setBackground(CARD);
        button.setForeground(TEXT);
        button.setBorder(new EmptyBorder(10, 12, 10, 12));
        button.setAlignmentX(Component.LEFT_ALIGNMENT);
        button.setMaximumSize(new Dimension(Integer.MAX_VALUE, 42));
        button.setPreferredSize(new Dimension(180, 42));
        button.addActionListener(event -> action.run());
        return button;
    }

    static JButton primaryButton(String text) {
        JButton button = new JButton(text);
        standardizeButton(button);
        button.setBackground(PRIMARY);
        button.setForeground(Color.WHITE);
        button.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(PRIMARY_DARK), new EmptyBorder(9, 16, 9, 16)));
        return button;
    }

    static JButton secondaryButton(String text) {
        JButton button = new JButton(text);
        standardizeButton(button);
        button.setBackground(CARD);
        button.setForeground(TEXT);
        button.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(190, 202, 216)), new EmptyBorder(8, 14, 8, 14)));
        return button;
    }

    private static void standardizeButton(JButton button) {
        button.setUI(new BasicButtonUI());
        button.setOpaque(true);
        button.setContentAreaFilled(true);
        button.setBorderPainted(true);
        button.setFocusPainted(false);
        button.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 13));
        button.setPreferredSize(new Dimension(132, 40));
        button.setMinimumSize(new Dimension(132, 40));
    }

    static void styleField(JComponent field) {
        field.setPreferredSize(new Dimension(300, 40));
        field.setMinimumSize(new Dimension(180, 40));
        field.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(190, 202, 216)), new EmptyBorder(7, 10, 7, 10)));
    }

    private JButton dangerButton(String text) {
        JButton button = secondaryButton(text);
        button.setForeground(DANGER);
        return button;
    }

    private JLabel smallNote(String text) {
        JLabel label = new JLabel("<html>" + text + "</html>");
        label.setForeground(MUTED);
        return label;
    }

    private Color scoreColor(int score) {
        if (score >= 80) { return new Color(25, 125, 75); }
        if (score >= 50) { return new Color(190, 125, 15); }
        return DANGER;
    }

    static void message(Component parent, String text, boolean error) {
        JOptionPane.showMessageDialog(parent, text, error ? "Check input" : "SecureVault",
                error ? JOptionPane.ERROR_MESSAGE : JOptionPane.INFORMATION_MESSAGE);
    }
}
