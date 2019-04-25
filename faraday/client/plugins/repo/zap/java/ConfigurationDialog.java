package org.zaproxy.zap.extension.faraday;


import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;

import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.util.ArrayList;
import java.util.Properties;
import java.util.ResourceBundle;

public class ConfigurationDialog extends JFrame {
    private static final Logger logger = Logger.getLogger(ConfigurationDialog.class);
    private ResourceBundle messages = null;
    private FaradayClient faradayClient;

    private static String LOGIN_BUTTON = "Login";
    private static String LOGOUT_BUTTON = "Logout";
    private static String WORKSPACES_FIELD = "Select faraday workspace";
    private static String IMPORT_NEW_VULNS_FIELD = "Import new vulnerabilities";
    private static String SET_CONFIG_AS_DEFAULT = "Set this configuration as default";
    private static String IMPORT_BUTTON = "Import vulnerabilities";
    private static String REFRESH_BUTTON = "Refresh";
    private static String RESTORE_BUTTON = "Restore";
    private static String SAVE_BUTTON = "Save";

    private JTabbedPane tabbedPane;
    private JPanel authPanel;
    private JPanel configPanel;

    private JTextField fldUser;
    private JTextField fldPass;
    private JTextField fldServer;

    private JComboBox cmbWorkspaces;
    private JCheckBox cboxSetConfigDefault;


    private JButton loginButton;
    private JButton logoutButton;
    private JButton refreshButton;
    private JButton restoreButton;
    private JButton importButton;
    private JButton saveButton;
    private JButton closeButton;


    public ConfigurationDialog(String s) throws HeadlessException {
        super(s);
    }


    public void init() {
        logger.debug("Init Faraday configuration dialog");
        messages = ResourceBundle.getBundle(
                this.getClass().getPackage().getName() +
                        ".Messages", Constant.getLocale());
        // Setup the content-pane of JFrame in BorderLayout
        Container cp = this.getContentPane();
        cp.setLayout(new BorderLayout(5, 5));
        Border padding = BorderFactory.createEmptyBorder(10, 10, 10, 10);


        String USERNAME_FIELD = messages.getString("faraday.config.dialog.auth.user");
        String PASS_FIELD = messages.getString("faraday.config.dialog.auth.pass");
        String SERVER_FIELD = messages.getString("faraday.config.dialog.server");
        LOGIN_BUTTON = messages.getString("faraday.config.dialog.auth.login");
        LOGOUT_BUTTON = messages.getString("faraday.config.dialog.auth.logout");
        WORKSPACES_FIELD = messages.getString("faraday.config.dialog.workspace");
        IMPORT_NEW_VULNS_FIELD = messages.getString("faraday.config.dialog.import.new");
        SET_CONFIG_AS_DEFAULT = messages.getString("faraday.config.dialog.default");
        IMPORT_BUTTON = messages.getString("faraday.config.dialog.import.new");
        REFRESH_BUTTON = messages.getString("faraday.config.dialog.refresh");
        RESTORE_BUTTON = messages.getString("faraday.config.dialog.restore");
        SAVE_BUTTON = messages.getString("faraday.config.dialog.save");
        tabbedPane = new JTabbedPane();

        JPanel buttonLoginPanel = new JPanel();
        buttonLoginPanel.setLayout(new FlowLayout(FlowLayout.RIGHT));

        JPanel buttonConfigPanel = new JPanel();
        buttonConfigPanel.setLayout(new FlowLayout(FlowLayout.RIGHT));

        authPanel = new JPanel(new GridLayout(4, 2, 10, 2));
        authPanel.setBorder(padding);
        configPanel = new JPanel(new GridLayout(3, 2, 10, 2));
        configPanel.setBorder(padding);


        Configuration configuration = Configuration.getSingleton();
        faradayClient = new FaradayClient(configuration.getServer());

        authPanel.add(new JLabel(USERNAME_FIELD));
        fldUser = new JTextField(10);
        authPanel.add(fldUser);

        authPanel.add(new JLabel(PASS_FIELD));
        fldPass = new JPasswordField(10);
        authPanel.add(fldPass);

        authPanel.add(new JLabel(SERVER_FIELD));
        fldServer = new JTextField(10);
        fldServer.setText(configuration.getServer());
        authPanel.add(fldServer);

        configPanel.add(getCBoxSetDefaultConfig());

        buttonConfigPanel.add(getCloseButton());
        buttonConfigPanel.add(getCloseButton());
        buttonConfigPanel.add(getRefreshButton());
        buttonConfigPanel.add(getRestoreButton());
        buttonConfigPanel.add(getSaveButton());
//        buttonConfigPanel.add(getImportButton());
        buttonConfigPanel.add(getLoginButton());
        buttonConfigPanel.add(getLogoutButton());


        authPanel.addComponentListener(new ComponentListener() {
            @Override
            public void componentResized(ComponentEvent componentEvent) {

            }

            @Override
            public void componentMoved(ComponentEvent componentEvent) {

            }

            @Override
            public void componentShown(ComponentEvent componentEvent) {

                refreshButton.setVisible(false);
                restoreButton.setVisible(false);
//                importButton.setVisible(false);
                saveButton.setVisible(false);
            }

            @Override
            public void componentHidden(ComponentEvent componentEvent) {
                refreshButton.setVisible(true);
                restoreButton.setVisible(true);
//                importButton.setVisible(true);
                saveButton.setVisible(true);
            }
        });

        configPanel.addComponentListener(new ComponentListener() {
            @Override
            public void componentResized(ComponentEvent componentEvent) {

            }

            @Override
            public void componentMoved(ComponentEvent componentEvent) {

            }

            @Override
            public void componentShown(ComponentEvent componentEvent) {
                loginButton.setVisible(false);
                logoutButton.setVisible(false);
            }

            @Override
            public void componentHidden(ComponentEvent componentEvent) {
                if (configuration.getSession().equals("")) {
                    loginButton.setVisible(true);
                } else {
                    logoutButton.setVisible(true);
                }
            }
        });

        tabbedPane.addTab(messages.getString("faraday.config.dialog.tab.auth"), null, authPanel, null);
        tabbedPane.setMnemonicAt(0, KeyEvent.VK_1);


        tabbedPane.addTab(messages.getString("faraday.config.dialog.tabs.conf"), null, configPanel, null);
        tabbedPane.setMnemonicAt(1, KeyEvent.VK_2);

        tabbedPane.setEnabledAt(1, false);

        cp.add(tabbedPane, BorderLayout.NORTH);
        cp.add(buttonConfigPanel, BorderLayout.SOUTH);

        if (configuration.getSession() != null && !configuration.getSession().equals("")) {
            logoutButton.setVisible(true);
            loginButton.setVisible(false);
        } else {
            loginButton.setVisible(true);
            logoutButton.setVisible(false);
        }


        if (!configuration.getUser().equals("") && !configuration.getPassword().equals("")) {
            if (faradayClient.Login(configuration.getUser(), configuration.getPassword(), configuration.getServer())) {
                fldUser.setText(configuration.getUser());
                fldPass.setText(configuration.getPassword());
                fldServer.setText(configuration.getServer());

                tabbedPane.setEnabledAt(1, true);
                tabbedPane.setSelectedIndex(1);

                cboxSetConfigDefault.setSelected(true);

                if (cmbWorkspaces == null) {
                    configPanel.add(new JLabel(WORKSPACES_FIELD));
                    configPanel.add(getWSComboBox());
                }
            }
        }

        this.setSize(550, 300);
        this.setResizable(false);
        this.setLocationRelativeTo(null);
        this.setVisible(true);
    }


    private JButton getLoginButton() {
        if (this.loginButton == null) {
            this.loginButton = new JButton();
            this.loginButton.setText(LOGIN_BUTTON);
            this.loginButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    if (fldUser.getText().equals("") || fldPass.getText().equals("") || fldServer.getText().equals("")) {
                        showMessage(messages.getString("faraday.message.invalid.check.credentials"), messages.getString("faraday.dialog.login.title"), JOptionPane.ERROR_MESSAGE);
                    } else {
                        if (faradayClient.Login(fldUser.getText(), fldPass.getText(), fldServer.getText())) {
                            logoutButton.setVisible(true);
                            loginButton.setVisible(false);
                            if (!tabbedPane.isEnabledAt(1)) {
                                tabbedPane.setEnabledAt(1, true);
                            }
                            tabbedPane.setSelectedIndex(1);
                            if (cmbWorkspaces == null) {
                                configPanel.add(new JLabel(WORKSPACES_FIELD));
                                configPanel.add(getWSComboBox());
                            } else {
                                configPanel.remove(cmbWorkspaces);
                                configPanel.add(getWSComboBox());
                            }
                        } else {
                            showMessage(messages.getString("faraday.message.invalid.credentials"), messages.getString("faraday.dialog.login.title"), JOptionPane.ERROR_MESSAGE);
                        }
                    }


                }
            });


        }

        return this.loginButton;
    }


    private JButton getLogoutButton() {
        if (this.logoutButton == null) {
            this.logoutButton = new JButton();
            this.logoutButton.setText(LOGOUT_BUTTON);
            this.logoutButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    Configuration configuration = Configuration.getSingleton();
                    String userTemp = configuration.getUser();
                    if (faradayClient.Logout()) {
                        logoutButton.setVisible(false);
                        loginButton.setVisible(true);

                        if (tabbedPane.isEnabledAt(1)) {
                            tabbedPane.setEnabledAt(1, false);
                        }
                        tabbedPane.setSelectedIndex(0);

                        Properties prop = new Properties();
                        InputStream input = null;
                        try {
                            String filePath = Constant.getZapHome() + "faraday" + File.separator + "default.properties";
                            input = new FileInputStream(filePath);
                            // load a properties file
                            prop.load(input);
                            // set the properties value
                            String fUser = prop.getProperty("default");
                            if (fUser.equals(userTemp)) {
                                removeDefaultConfig();
                            }

                        } catch (IOException io) {
                            System.out.println("We can't found default.properties file");
                        } finally {
                            if (input != null) {
                                try {
                                    input.close();
                                } catch (IOException er) {
                                    er.printStackTrace();
                                }
                            }
                        }


                        showMessage(messages.getString("faraday.dialog.logout.success"), messages.getString("faraday.dialog.logout.title"), JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        showMessage(messages.getString("faraday.dialog.logout.error"), messages.getString("faraday.dialog.logout.title"), JOptionPane.ERROR_MESSAGE);
                    }
                }
            });
        }

        return this.logoutButton;
    }


    private JButton getRefreshButton() {
        if (this.refreshButton == null) {
            this.refreshButton = new JButton();
            this.refreshButton.setText(REFRESH_BUTTON);
            this.refreshButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    refreshWorkspaces(true);
                }
            });
        }

        return this.refreshButton;
    }


    private JButton getCloseButton() {
        if (this.closeButton == null) {
            this.closeButton = new JButton();
            this.closeButton.setText(messages.getString("faraday.dialog.button.close"));
            this.closeButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    setVisible(false);
                    dispose();
                }
            });
        }

        return this.closeButton;
    }


    private JButton getRestoreButton() {
        if (this.restoreButton == null) {
            this.restoreButton = new JButton();
            this.restoreButton.setText(RESTORE_BUTTON);
            this.restoreButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    String fUser = JOptionPane.showInputDialog(messages.getString("faraday.config.dialog.restore"), messages.getString("faraday.dialog.enter.user"));
                    if (fUser != null) {
                        restoreConfiguration(fUser);
                    }
                }
            });
        }

        return this.restoreButton;
    }


    private JButton getImportButton() {
        if (this.importButton == null) {
            this.importButton = new JButton();
            this.importButton.setText(IMPORT_BUTTON);
            this.importButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {

                }
            });
        }

        return this.importButton;
    }


    private JButton getSaveButton() {
        if (this.saveButton == null) {
            this.saveButton = new JButton();
            this.saveButton.setText(SAVE_BUTTON);
            this.saveButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    saveConfiguration();
                }
            });
        }

        return this.saveButton;
    }


    private JComboBox getWSComboBox() {
        Configuration configuration = Configuration.getSingleton();

        ArrayList<String> wsList = faradayClient.GetWorkspaces();
        String[] workspaces = new String[wsList.size()];
        for (int i = 0; i < wsList.size(); i++) {
            workspaces[i] = wsList.get(i);
        }
        cmbWorkspaces = new JComboBox(workspaces);
        if (workspaces.length > 0) {
            if (configuration.getWorkspace() != null) {
                cmbWorkspaces.setSelectedItem(configuration.getWorkspace());
            } else {
                configuration.setWorkspace(workspaces[0]);
            }
        }
        cmbWorkspaces.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                Configuration.getSingleton().setWorkspace(cmbWorkspaces.getSelectedItem().toString());
            }
        });


        return cmbWorkspaces;
    }


    private JCheckBox getCBoxSetDefaultConfig() {
        if (this.cboxSetConfigDefault == null) {
            cboxSetConfigDefault = new JCheckBox(SET_CONFIG_AS_DEFAULT, false);

            cboxSetConfigDefault.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    if (cboxSetConfigDefault.isSelected()) {
                        setConfigAsDefault();
                    } else {
                        removeDefaultConfig();
                    }
                }
            });
        }

        return cboxSetConfigDefault;
    }


    private void showMessage(String message, String title, int icon) {
        JOptionPane.showMessageDialog(
                this,
                message,
                title,
                icon);
    }


    private void saveConfiguration() {
        try {
            if (Configuration.getSingleton().save()) {
                JOptionPane.showMessageDialog(
                        this,
                        messages.getString("faraday.save.config.success"),
                        messages.getString("faraday.config.dialog.title"),
                        JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(
                        this,
                        messages.getString("faraday.save.config.error"),
                        messages.getString("faraday.config.dialog.title"),
                        JOptionPane.ERROR_MESSAGE);

            }
        } catch (IOException io) {
            JOptionPane.showMessageDialog(
                    this,
                    messages.getString("faraday.save.config.error"),
                    messages.getString("faraday.config.dialog.title"),
                    JOptionPane.ERROR_MESSAGE);
            io.printStackTrace();

        }
    }


    private void restoreConfiguration(String fUser) {
        try {
            Configuration configuration = Configuration.getSingleton();
            configuration.restore(fUser);
            if (faradayClient.Login(configuration.getUser(), configuration.getPassword(), configuration.getServer())) {
                fldUser.setText(configuration.getUser());
                fldPass.setText(configuration.getPassword());
                fldServer.setText(configuration.getServer());

                tabbedPane.setEnabledAt(1, true);
                tabbedPane.setSelectedIndex(0);

                cboxSetConfigDefault.setSelected(false);
                refreshWorkspaces(false);
            } else {
                JOptionPane.showMessageDialog(
                        this,
                        messages.getString("faraday.restore.config.error.login"),
                        messages.getString("faraday.config.dialog.title"),
                        JOptionPane.ERROR_MESSAGE);
            }
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(
                    this,
                    messages.getString("faraday.restore.config.error"),
                    messages.getString("faraday.config.dialog.title"),
                    JOptionPane.ERROR_MESSAGE);
        }

    }


    private void setConfigAsDefault() {
        Configuration configuration = Configuration.getSingleton();

        Properties prop = new Properties();
        OutputStream output = null;

        try {
            String outputFolder = Constant.getZapHome() + "faraday";
            File folder = new File(outputFolder);
            if (!folder.exists()) {
                folder.mkdir();
            }

            String filePath = outputFolder + File.separator + "default.properties";
            output = new FileOutputStream(filePath);

            // set the properties value
            prop.setProperty("default", configuration.getUser());

            // save properties to project root folder
            prop.store(output, null);

        } catch (IOException io) {
            JOptionPane.showMessageDialog(
                    this,
                    messages.getString("faraday.set.default.config.error"),
                    messages.getString("faraday.config.dialog.title"),
                    JOptionPane.ERROR_MESSAGE);
            io.printStackTrace();
        } finally {
            if (output != null) {
                try {
                    output.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

        }
    }


    private void removeDefaultConfig() {
        try {

            String filePath = Constant.getZapHome() + "faraday" + File.separator + "default.properties";
            File file = new File(filePath);
            if (file.delete()) {
                System.out.println(file.getName() + " is deleted!");
            } else {
                System.out.println("Delete operation is failed.");
            }

        } catch (Exception e) {

            e.printStackTrace();

        }
    }


    private void refreshWorkspaces(boolean canShowAlert) {
        if (cmbWorkspaces != null) {
            configPanel.remove(cmbWorkspaces);
            configPanel.add(getWSComboBox());
            if (canShowAlert) {
                JOptionPane.showMessageDialog(
                        this,
                        messages.getString("faraday.refresh.workspace.done"),
                        messages.getString("faraday.config.dialog.title"),
                        JOptionPane.INFORMATION_MESSAGE);
            }
        }
    }

}
