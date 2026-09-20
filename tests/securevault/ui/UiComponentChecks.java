package securevault.ui;

import java.awt.Color;
import java.awt.Dimension;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JTextField;
import securevault.enums.AccountType;

/** Headless checks for the dimensions and contrast of reusable Swing controls. */
public final class UiComponentChecks {
    private UiComponentChecks() { }

    public static int run() {
        JButton login = SwingUI.primaryButton("Login securely");
        JButton register = SwingUI.primaryButton("Create account");
        JButton add = SwingUI.primaryButton("Add account");
        require(login.isOpaque() && login.isContentAreaFilled(), "Primary button must paint its background");
        require(login.getForeground().equals(Color.WHITE), "Primary button text must be visible");
        require(contrast(login.getForeground(), login.getBackground()) >= 4.5,
                "Primary button must meet readable contrast");
        require(login.getPreferredSize().equals(register.getPreferredSize())
                && login.getPreferredSize().equals(add.getPreferredSize()), "Primary buttons must use one size");

        JTextField text = new JTextField();
        JComboBox<AccountType> category = new JComboBox<>(AccountType.values());
        SwingUI.styleField(text);
        SwingUI.styleField(category);
        require(text.getPreferredSize().equals(new Dimension(300, 40)), "Text fields must use standard dimensions");
        require(text.getPreferredSize().equals(category.getPreferredSize()), "Form controls must align equally");
        return 6;
    }

    private static double contrast(Color first, Color second) {
        double brighter = Math.max(luminance(first), luminance(second));
        double darker = Math.min(luminance(first), luminance(second));
        return (brighter + 0.05) / (darker + 0.05);
    }

    private static double luminance(Color color) {
        return 0.2126 * channel(color.getRed()) + 0.7152 * channel(color.getGreen())
                + 0.0722 * channel(color.getBlue());
    }

    private static double channel(int value) {
        double normalized = value / 255.0;
        return normalized <= 0.03928 ? normalized / 12.92 : Math.pow((normalized + 0.055) / 1.055, 2.4);
    }

    private static void require(boolean condition, String message) {
        if (!condition) { throw new AssertionError(message); }
    }
}
