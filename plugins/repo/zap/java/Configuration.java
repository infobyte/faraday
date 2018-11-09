/*
 *  Zed Attack Proxy (ZAP) and its related class files.
 *
 *  ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 *  Copyright 2018 The ZAP Development Team
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.zaproxy.zap.extension.faraday;

import org.parosproxy.paros.Constant;

import javax.swing.*;
import java.io.*;
import java.util.Properties;

public class Configuration {
    private String server;
    private String user;
    private String password;
    private String session;
    private String workspace;
    private boolean autoImport;
    private static Configuration _instance;

    private Configuration() {
        this.user = "";
        this.password = "";
        this.server = "http://127.0.0.1:5985/";
        this.autoImport = false;
    }

    public static Configuration getSingleton() {
        if (_instance == null)
            _instance = new Configuration();
        return _instance;
    }

    public boolean save() throws IOException {

        Properties prop = new Properties();
        OutputStream output = null;

        String userHome = System.getProperty("user.home");
        String outputFolder = Constant.getZapHome() + "faraday";
        File folder = new File(outputFolder);
        if (!folder.exists()) {
            folder.mkdir();
        }


        String filePath = outputFolder + File.separator + this.getUser() + ".properties";
        output = new FileOutputStream(filePath);

        // set the properties value
        prop.setProperty("fuser", this.getUser());
        prop.setProperty("fpassword", this.getPassword());
        prop.setProperty("fserver", this.getServer());
        prop.setProperty("fworkspace", this.getWorkspace());
        prop.setProperty("fsession", this.getSession());

        // save properties to project root folder
        prop.store(output, null);

        if (output != null) {
            try {
                output.close();
            } catch (IOException e) {
                e.printStackTrace();
                return false;
            }
        }

        return true;
    }


    public void restore(String fUser) throws IOException {
        Properties prop = new Properties();
        InputStream input = null;

        String outputFolder = Constant.getZapHome() + "faraday";
        String filePath = outputFolder + File.separator + fUser + ".properties";
        input = new FileInputStream(filePath);

        // load a properties file
        prop.load(input);

        this.setUser(prop.getProperty("fuser"));
        this.setPassword(prop.getProperty("fpassword"));
        this.setServer(prop.getProperty("fserver"));
        this.setWorkspace(prop.getProperty("fworkspace"));

        if (input != null) {
            try {
                input.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getServer() {
        return server;
    }

    public void setServer(String server) {
        this.server = server;
    }

    public boolean isAutoImport() {
        return autoImport;
    }

    public void setAutoImport(boolean autoImport) {
        this.autoImport = autoImport;
    }

    public String getSession() {
        return session;
    }

    public void setSession(String session) {
        this.session = session;
    }

    public String getWorkspace() {
        return workspace;
    }

    public void setWorkspace(String workspace) {
        this.workspace = workspace;
    }
}
