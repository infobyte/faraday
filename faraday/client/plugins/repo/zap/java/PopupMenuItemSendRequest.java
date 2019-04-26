package org.zaproxy.zap.extension.faraday;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.RecordAlert;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.alert.PopupMenuAlert;
import org.zaproxy.zap.view.messagecontainer.http.HttpMessageContainer;
import org.zaproxy.zap.view.popup.PopupMenuItemHistoryReferenceContainer;

import javax.swing.*;
import java.awt.*;
import java.util.Iterator;
import java.util.List;
import java.util.ResourceBundle;


public class PopupMenuItemSendRequest extends PopupMenuItemHistoryReferenceContainer {
    private FaradayClient faradayClient;
    private ResourceBundle messages = null;
    private int selectionCount = 0;
    private static final Logger logger = Logger.getLogger(PopupMenuItemSendRequest.class);


    public PopupMenuItemSendRequest(String label) {
        super(label, true);
        Configuration configuration = Configuration.getSingleton();
        faradayClient = new FaradayClient(configuration.getServer());
        messages = ResourceBundle.getBundle(
                this.getClass().getPackage().getName() +
                        ".Messages", Constant.getLocale());
    }

    @Override
    public void performAction(HistoryReference href) {
        try {
            Alert alert = new Alert(new RecordAlert(), href);
            alert.setName(href.getSiteNode().getName());
            alert.setUri(href.getURI().toString());
            alert.setMessage(href.getHttpMessage());
            alert.setDescription("");
            alert.setRiskConfidence(0, 0);

            Configuration configuration = Configuration.getSingleton();
            String workspace = configuration.getWorkspace();
            String session = configuration.getSession();
            if (workspace != null && session != null && !workspace.equals("") && !session.equals("")) {
                int responseCode = faradayClient.AddVulnerability(alert, configuration.getWorkspace(), session);
                String message = "";
                int iconMessage = 1;
                switch (responseCode) {
                    case 403:
                        message = messages.getString("faraday.send.alert.permissions.error");
                        iconMessage = JOptionPane.WARNING_MESSAGE;
                        break;
                    case 409:
                        message = messages.getString("faraday.send.request.conflict");
                        iconMessage = JOptionPane.WARNING_MESSAGE;
                        break;
                    case 500:
                        message = "Unable to send " + alert.getName() + " to Faraday";
                        iconMessage = JOptionPane.ERROR_MESSAGE;
                        break;
                    case 201:
                        message = messages.getString("faraday.send.request.success");
                        break;
                }

                if (this.selectionCount == 1) {
                    JOptionPane.showMessageDialog(
                            this,
                            message,
                            messages.getString("faraday.button.send.alert"),
                            iconMessage);
                }

                logger.error(message);
                if (View.isInitialised()) {
                    // Report info to the Output tab
                    View.getSingleton().getOutputPanel().append(message + "\n");
                }


            } else {
                JOptionPane.showMessageDialog(
                        this,
                        messages.getString("faraday.send.alert.permissions.error"),
                        messages.getString("faraday.button.send.request"),
                        JOptionPane.ERROR_MESSAGE);

                logger.error(messages.getString("faraday.send.alert.permissions.error"));
                if (View.isInitialised()) {
                    // Report info to the Output tab
                    View.getSingleton().getOutputPanel().append(messages.getString("faraday.send.alert.permissions.error") + "\n");
                }
            }


        } catch (HttpMalformedHeaderException e) {
            e.printStackTrace();
        } catch (DatabaseException e) {
            e.printStackTrace();
        }
    }


    @Override
    public void performHistoryReferenceActions(List<HistoryReference> hrefs) {
        this.selectionCount = hrefs.size();

        for (HistoryReference href : hrefs) {
            this.performAction(href);
        }
    }

    @Override
    public boolean isEnableForInvoker(Invoker invoker, HttpMessageContainer httpMessageContainer) {
        if (Configuration.getSingleton().getSession() == null || Configuration.getSingleton().getSession().equals("") ||
                invoker.name().equals("ALERTS_PANEL")) {
            return false;
        }
        return super.isEnableForInvoker(invoker, httpMessageContainer);
    }

    @Override
    public boolean isButtonEnabledForHistoryReference(HistoryReference href) {
        if (Configuration.getSingleton().getSession() == null || Configuration.getSingleton().getSession().equals("")) {
            return false;
        }

        return href.getSiteNode() != null && super.isButtonEnabledForHistoryReference(href);
    }
}