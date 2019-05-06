/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.faraday;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.zaproxy.zap.view.ZapMenuItem;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.io.*;
import java.util.Properties;
import java.util.ResourceBundle;

public class FaradayExtension extends ExtensionAdaptor {
    private static final Logger logger = Logger.getLogger(FaradayExtension.class);
    private ZapMenuItem menuItemFaradayConfig;
    private ConfigurationDialog configurationDialog;
    private PopupMenuItemSendAlert popupMenuItemSendAlert;
    private PopupMenuItemSendRequest popupMenuItemSendRequest;
    private ResourceBundle messages = null;



    public FaradayExtension(String name) {
        super(name);
    }


    public FaradayExtension() {
        super();
        initialize();
    }


    private void initialize() {
        messages = ResourceBundle.getBundle(
                this.getClass().getPackage().getName() +
                        ".Messages", Constant.getLocale());
        this.setName(messages.getString("faraday.extension.name"));
        this.initConfiguration();
    }

    @Override
    public String getAuthor() {
        return messages.getString("faraday.extension.author");
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (getView() != null) {
            extensionHook.getHookMenu().addToolsMenuItem(getMenuItemFaradayConfig());
            extensionHook.getHookMenu().addPopupMenuItem(this.getPopupMenuItem());
            extensionHook.getHookMenu().addPopupMenuItem(this.getPopupMenuItemRequest());
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    private ZapMenuItem getMenuItemFaradayConfig() {
        if (menuItemFaradayConfig == null) {
            menuItemFaradayConfig = new ZapMenuItem(
                    "faraday.menu.tools.label",
                    KeyStroke.getKeyStroke(
                            KeyEvent.VK_F,
                            Toolkit.getDefaultToolkit().getMenuShortcutKeyMask() | KeyEvent.ALT_DOWN_MASK,
                            false));
            menuItemFaradayConfig.setEnabled(Control.getSingleton().getMode() != Control.Mode.safe);

            menuItemFaradayConfig.addActionListener(new java.awt.event.ActionListener() {

                @Override
                public void actionPerformed(java.awt.event.ActionEvent e) {
                    showConfigurationDialog();
                }
            });
        }
        return menuItemFaradayConfig;
    }


    private void showConfigurationDialog() {
        if (configurationDialog == null) {
            configurationDialog = new ConfigurationDialog(messages.getString("faraday.config.dialog.title"));
            configurationDialog.init();
        }
        configurationDialog.setVisible(true);
    }


    private ExtensionPopupMenuItem getPopupMenuItem() {
        if (popupMenuItemSendAlert == null) {
            popupMenuItemSendAlert = new PopupMenuItemSendAlert(messages.getString("faraday.button.send.alert"));
        }

        return popupMenuItemSendAlert;

    }


    private ExtensionPopupMenuItem getPopupMenuItemRequest() {
        if (popupMenuItemSendRequest == null) {
            popupMenuItemSendRequest = new PopupMenuItemSendRequest(messages.getString("faraday.button.send.request"));
        }

        return popupMenuItemSendRequest;

    }


    private void initConfiguration() {
        Configuration configuration = Configuration.getSingleton();

        Properties prop = new Properties();
        InputStream input = null;

        try {
            String filePath = Constant.getZapHome() + "faraday" + File.separator + "default.properties";
            input = new FileInputStream(filePath);

            // load a properties file
            prop.load(input);

            // set the properties value
            String fUser = prop.getProperty("default");
            configuration.restore(fUser);

        } catch (IOException io) {
            System.out.println("We can't found default.properties file");
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

        }
    }

}
