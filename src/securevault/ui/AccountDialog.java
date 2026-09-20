package securevault.ui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.Arrays;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import securevault.enums.AccountType;
import securevault.model.Account;

/** Modal Swing form for creating or editing an account. */
final class AccountDialog extends JDialog {
    private static final long serialVersionUID = 1L;

    private final JTextField platformField = new JTextField(24);
    private final JTextField usernameField = new JTextField(24);
    private final JComboBox<AccountType> typeBox = new JComboBox<>(AccountType.values());
    private final JPasswordField passwordField = new JPasswordField(24);
    private final JPasswordField confirmField = new JPasswordField(24);
    private boolean accepted;

    AccountDialog(Component owner, Account existing) {
        super(javax.swing.SwingUtilities.getWindowAncestor(owner),
                existing == null ? "Add account" : "Update account", Dialog.ModalityType.APPLICATION_MODAL);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setResizable(false);
        build(existing);
        pack();
        setMinimumSize(new Dimension(460, getHeight()));
        setLocationRelativeTo(owner);
    }

    private void build(Account existing) {
        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(BorderFactory.createEmptyBorder(22, 24, 14, 24));
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.insets = new Insets(7, 4, 7, 4);
        constraints.anchor = GridBagConstraints.WEST;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.weightx = 1;

        addRow(form, constraints, 0, "Platform", platformField);
        addRow(form, constraints, 1, "Username / email", usernameField);
        addRow(form, constraints, 2, "Category", typeBox);
        addRow(form, constraints, 3, existing == null ? "Password" : "New password (optional)", passwordField);
        addRow(form, constraints, 4, "Confirm password", confirmField);

        if (existing != null) {
            platformField.setText(existing.getPlatform());
            usernameField.setText(existing.getUsername());
            typeBox.setSelectedItem(existing.getType());
        }

        JLabel note = new JLabel(existing == null
                ? "The password is encrypted before it is saved."
                : "Leave both password fields empty to keep the current password.");
        note.setForeground(SwingUI.MUTED);
        constraints.gridx = 0;
        constraints.gridy = 5;
        constraints.gridwidth = 2;
        form.add(note, constraints);

        JButton cancel = SwingUI.secondaryButton("Cancel");
        cancel.addActionListener(event -> dispose());
        JButton save = SwingUI.primaryButton(existing == null ? "Add account" : "Save changes");
        save.addActionListener(event -> accept(existing != null));
        JPanel actions = new JPanel();
        actions.setBorder(BorderFactory.createEmptyBorder(0, 16, 14, 16));
        actions.add(cancel);
        actions.add(save);

        add(form, BorderLayout.CENTER);
        add(actions, BorderLayout.SOUTH);
        getRootPane().setDefaultButton(save);
    }

    private void addRow(JPanel panel, GridBagConstraints constraints, int row, String label, Component field) {
        constraints.gridx = 0;
        constraints.gridy = row;
        constraints.gridwidth = 1;
        constraints.weightx = 0;
        panel.add(new JLabel(label), constraints);
        constraints.gridx = 1;
        constraints.weightx = 1;
        panel.add(field, constraints);
    }

    private void accept(boolean editing) {
        char[] password = passwordField.getPassword();
        char[] confirmation = confirmField.getPassword();
        try {
            if (platformField.getText().isBlank() || usernameField.getText().isBlank()) {
                SwingUI.message(this, "Platform and username/email are required.", true);
                return;
            }
            if (!editing && password.length == 0) {
                SwingUI.message(this, "Enter an account password.", true);
                return;
            }
            if (!Arrays.equals(password, confirmation)) {
                SwingUI.message(this, "The password confirmation does not match.", true);
                return;
            }
            accepted = true;
            dispose();
        } finally {
            Arrays.fill(password, '\0');
            Arrays.fill(confirmation, '\0');
        }
    }

    boolean open() {
        setVisible(true);
        return accepted;
    }

    String getPlatform() { return platformField.getText(); }
    String getUsername() { return usernameField.getText(); }
    AccountType getAccountType() { return (AccountType) typeBox.getSelectedItem(); }
    char[] getPassword() { return passwordField.getPassword(); }
}
