package org.zaproxy.zap.extension.faraday;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;

import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.entity.StringEntity;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.HistoryReference;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.sql.Time;
import java.time.Instant;
import java.util.*;


public class FaradayClient {

    private String baseUrl;
    private ResourceBundle messages = null;

    public FaradayClient(String baseUrl) {
        this.baseUrl = baseUrl;
        messages = ResourceBundle.getBundle(
                this.getClass().getPackage().getName() +
                        ".Messages", Constant.getLocale());

    }

    public boolean Login(String username, String password, String server) {
        Logout();
        HttpClient httpClient = HttpClients.createDefault();
        String LOGIN_URL = "_api/login";
        HttpPost httpPost = new HttpPost(server + LOGIN_URL);

        // Request parameters and other properties.
        List<BasicNameValuePair> params = new ArrayList<>(2);
        params.add(new BasicNameValuePair("email", username));
        params.add(new BasicNameValuePair("password", password));

        try {
            httpPost.setEntity(new UrlEncodedFormEntity(params, "UTF-8"));
            HttpResponse response = httpClient.execute(httpPost);
            if (response.getFirstHeader("Set-Cookie") != null) {
                Configuration configuration = Configuration.getSingleton();
                configuration.setSession(response.getFirstHeader("Set-Cookie").getValue());
                configuration.setUser(username);
                configuration.setPassword(password);
                configuration.setServer(server);
                setBaseUrl(server);
                return true;
            } else if (response.getStatusLine().getStatusCode() == 302) {
                return true;
            }
            return false;
        } catch (UnsupportedEncodingException e) {
            // writing error to Log
            e.printStackTrace();
            return false;
        } catch (ClientProtocolException e) {
            e.printStackTrace();
            return false;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }

    }

    public boolean Logout() {
        String LOGOUT_URL = "_api/logout";
        HttpGet httpGet = new HttpGet(this.baseUrl + LOGOUT_URL);
        Configuration configuration = Configuration.getSingleton();

        if (!Objects.equals(configuration.getSession(), "")) {
            httpGet.setHeader("Cookie", configuration.getSession());

            //Execute and get the response.
            HttpResponse response = null;

            try {
                HttpClient httpClient = HttpClients.createDefault();
                response = httpClient.execute(httpGet);
                HttpEntity entity = response.getEntity();
                if (response.getStatusLine().getStatusCode() == 200) {
                    configuration.setSession("");
                    configuration.setUser("");
                    configuration.setPassword("");
                    return true;
                }
                return false;
            } catch (IOException e) {
                e.printStackTrace();
                return false;
            }
        }
        return true;
    }

    public ArrayList<String> GetWorkspaces() {
        ArrayList<String> workspaces = new ArrayList<>();
        String WORKSPACES_URL = "_api/v2/ws/";
        HttpGet httpGet = new HttpGet(this.baseUrl + WORKSPACES_URL);
        Configuration configuration = Configuration.getSingleton();

        if (configuration.getSession() != "") {
            httpGet.setHeader("Cookie", configuration.getSession());

            //Execute and get the response.
            HttpResponse response = null;
            InputStream instream = null;
            try {
                HttpClient httpClient = HttpClients.createDefault();
                response = httpClient.execute(httpGet);
                HttpEntity entity = response.getEntity();

                if (entity != null && response.getStatusLine().getStatusCode() == 200) {
                    instream = entity.getContent();

                    BufferedReader br = new BufferedReader(new InputStreamReader(instream));
                    String output;
                    JSONArray jsonArray = new JSONArray();
                    while ((output = br.readLine()) != null) {
                        System.out.println(output);
                        jsonArray = JSONArray.fromObject(output);
                    }

                    for (int i = 0; i < jsonArray.size(); i++) {
                        JSONObject jsonObject = jsonArray.getJSONObject(i);
                        workspaces.add(jsonObject.get("name").toString());
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                try {
                    instream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        return workspaces;
    }


    private int AddCommand(String commandName, String workspace, String session) {
        String COMMAND_URL = "_api/v2/ws/" + workspace + "/commands/";
        HttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost(this.baseUrl + COMMAND_URL);

        try {
            StringEntity stringEntity = new StringEntity(ConvertCommandToParams(commandName).toString());
            httpPost.setHeader("Cookie", session);
            httpPost.setHeader("Content-Type", "application/json");
            httpPost.setEntity(stringEntity);
            HttpResponse response = httpClient.execute(httpPost);
            HttpEntity entity = response.getEntity();

            if (response.getStatusLine().getStatusCode() == 200 || response.getStatusLine().getStatusCode() == 201 || response.getStatusLine().getStatusCode() == 409) {
                BufferedReader br = new BufferedReader(new InputStreamReader(entity.getContent()));
                String output;
                JSONObject json;
                String commandStr = "-1";
                while ((output = br.readLine()) != null) {
                    json = JSONObject.fromObject(output);
                    if (response.getStatusLine().getStatusCode() == 409) {
                        JSONObject jsonObject = JSONObject.fromObject(json.get("object"));
                        commandStr = jsonObject.get("_id").toString();
                    } else {
                        commandStr = json.get("_id").toString();
                    }
                }
                return Integer.parseInt(commandStr);
            }
            return -1;
        } catch (UnsupportedEncodingException e) {
            // writing error to Log
            e.printStackTrace();
            return -1;
        } catch (ClientProtocolException e) {
            e.printStackTrace();
            return -1;
        } catch (IOException e) {
            e.printStackTrace();
            return -1;
        }
    }

    private int AddHost(Alert alert, String workspace, String session) {
        String VULN_URL = "_api/v2/ws/" + workspace + "/hosts/";
        HttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost(this.baseUrl + VULN_URL);

        try {
            StringEntity stringEntity = new StringEntity(ConvertHostToParams(alert).toString());
            httpPost.setHeader("Cookie", session);
            httpPost.setHeader("Content-Type", "application/json");
            httpPost.setEntity(stringEntity);
            HttpResponse response = httpClient.execute(httpPost);
            HttpEntity entity = response.getEntity();

            if (response.getStatusLine().getStatusCode() == 200 || response.getStatusLine().getStatusCode() == 201 || response.getStatusLine().getStatusCode() == 409) {
                BufferedReader br = new BufferedReader(new InputStreamReader(entity.getContent()));
                String output;
                JSONObject json;
                String hostStr = "-1";
                while ((output = br.readLine()) != null) {
                    json = JSONObject.fromObject(output);
                    if (response.getStatusLine().getStatusCode() == 409) {
                        JSONObject jsonObject = JSONObject.fromObject(json.get("object"));
                        hostStr = jsonObject.get("id").toString();
                    } else {
                        hostStr = json.get("id").toString();
                    }
                }
                return Integer.parseInt(hostStr);
            }
            return -1;
        } catch (UnsupportedEncodingException e) {
            // writing error to Log
            e.printStackTrace();
            return -1;
        } catch (ClientProtocolException e) {
            e.printStackTrace();
            return -1;
        } catch (IOException e) {
            e.printStackTrace();
            return -1;
        }
    }

    private int AddService(Alert alert, String workspace, String session, int hostId) {
        String VULN_URL = "_api/v2/ws/" + workspace + "/services/";
        HttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost(this.baseUrl + VULN_URL);

        try {
            StringEntity stringEntity = new StringEntity(ConvertServiceToParams(alert, hostId).toString());
            httpPost.setHeader("Cookie", session);
            httpPost.setHeader("Content-Type", "application/json");
            httpPost.setEntity(stringEntity);
            HttpResponse response = httpClient.execute(httpPost);
            HttpEntity entity = response.getEntity();

            BufferedReader br = new BufferedReader(new InputStreamReader(entity.getContent()));
            String output;
            if (response.getStatusLine().getStatusCode() == 200 || response.getStatusLine().getStatusCode() == 201 || response.getStatusLine().getStatusCode() == 409) {
                JSONObject json;
                String serviceStr = "-1";
                while ((output = br.readLine()) != null) {
                    json = JSONObject.fromObject(output);
                    if (response.getStatusLine().getStatusCode() == 409) {
                        JSONObject jsonObject = JSONObject.fromObject(json.get("object"));
                        serviceStr = jsonObject.get("id").toString();
                    } else {
                        serviceStr = json.get("id").toString();
                    }
                }
                return Integer.parseInt(serviceStr);
            } else {
                while ((output = br.readLine()) != null) {
                    System.out.println(output);
                }

                return -1;
            }

        } catch (UnsupportedEncodingException e) {
            // writing error to Log
            e.printStackTrace();
            return -1;
        } catch (ClientProtocolException e) {
            e.printStackTrace();
            return -1;
        } catch (IOException e) {
            e.printStackTrace();
            return -1;
        }
    }

    public int AddVulnerability(Alert alert, String workspace, String session) {
        int hostId = AddHost(alert, workspace, session);
        if (hostId == -1) {
            return 500;
        }

        String parentType = "Service";
        int serviceId = AddService(alert, workspace, session, hostId);
        if (serviceId == -1) {
            return 500;
        }


        String commandName = messages.getString("faraday.tool.command.name");
        int commandId = AddCommand(commandName, workspace, session);
        if (commandId == -1) {
            return 500;
        }


        String VULN_URL = "_api/v2/ws/" + workspace + "/vulns/?command_id=" + commandId;
        HttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost(this.baseUrl + VULN_URL);
        try {

            StringEntity stringEntity = new StringEntity(ConvertAlertToParams(alert, workspace, parentType, serviceId).toString());
            httpPost.setHeader("Cookie", session);
            httpPost.setHeader("Content-Type", "application/json");
            httpPost.setEntity(stringEntity);
            HttpResponse response = httpClient.execute(httpPost);
            return response.getStatusLine().getStatusCode();

        } catch (UnsupportedEncodingException e) {
            // writing error to Log
            e.printStackTrace();
            return 402;
        } catch (ClientProtocolException e) {
            e.printStackTrace();
            return 402;
        } catch (IOException e) {
            e.printStackTrace();
            return 402;
        }
    }

    private JSONObject ConvertAlertToParams(Alert alert, String workspace, String parentType, int parentId) {
        // Request parameters and other properties.
        JSONObject params = new JSONObject();

        params.put("name", alert.getName());
        params.put("ws", workspace);
        params.put("request", alert.getMessage().getRequestHeader().toString());
        params.put("response", alert.getMessage().getResponseHeader().toString());
        String desc = !alert.getParam().equals("") ? alert.getDescription() + "\nWith parameter: '" + alert.getParam() + "'" :
                alert.getDescription();
        params.put("desc", desc);
        params.put("resolution", alert.getSolution());
        params.put("type", "VulnerabilityWeb");
        params.put("data", alert.getPostData());
        params.put("policyviolations", "[]");
        params.put("parent_type", parentType);
        params.put("parent", parentId);
        params.put("params", alert.getParam());

        JSONObject metadata = new JSONObject();
        metadata.put("creator", "OWASP");
        params.put("metadata", metadata);

        String hostname = alert.getMessage().getRequestHeader().getHostName();
        String IpAddres = GetIPFromHostname(hostname);
        JSONArray hostNamesArray = new JSONArray();
        hostNamesArray.add(hostname);
        hostNamesArray.add(IpAddres);
        params.put("hostnames", hostNamesArray);
        params.put("target", IpAddres);
        params.put("website", hostname);

        JSONArray refsJsonArray = new JSONArray();
        String[] resfArray = alert.getReference().split("\n");
        Collections.addAll(refsJsonArray, resfArray);
        params.put("refs", refsJsonArray);

        try {
            params.put("path", alert.getMsgUri().getPath());
        } catch (URIException e) {
            e.printStackTrace();
        }

        if (alert.getConfidence() == 4) {
            params.put("confirmed", true);
        }

        switch (alert.getRisk()) {
            case 0:
                params.put("severity", "informational");
                break;
            case 1:
                params.put("severity", "low");
                break;
            case 2:
                params.put("severity", "medium");
                break;
            case 3:
                params.put("severity", "high");
                break;
        }
        return params;

    }

    private JSONObject ConvertHostToParams(Alert alert) {
        // Request parameters and other properties.
        JSONObject params = new JSONObject();

        try {
            String ipAddress = GetIPFromHostname(alert.getMsgUri().getHost());
            params.put("ip", ipAddress);
            params.put("name", alert.getMsgUri().getName());
            params.put("os", "Unknown");
            params.put("description", "");
            JSONObject metadata = new JSONObject();
            metadata.put("creator", "Zap");
            params.put("metadata", metadata);

            String hostname = alert.getMessage().getRequestHeader().getHostName();
            JSONArray hostNamesArray = new JSONArray();
            hostNamesArray.add(hostname);
            params.put("hostnames", hostNamesArray);

        } catch (URIException e) {
            e.printStackTrace();
        }
        return params;
    }

    private JSONObject ConvertServiceToParams(Alert alert, int parentId) {
        // Request parameters and other properties.
        JSONObject params = new JSONObject();
        JSONArray portsJson = new JSONArray();
        portsJson.add(alert.getMessage().getRequestHeader().getHostPort());
        params.put("ports", portsJson);
        params.put("parent", parentId);
        params.put("status", "open");
        params.put("type", "Service");
        params.put("description", "");
        JSONObject metadata = new JSONObject();
        metadata.put("creator", "OWASP");
        params.put("metadata", metadata);

        switch (alert.getMessage().getRequestHeader().getHostPort()) {
            case 21:
                params.put("name", "FTP");
                params.put("protocol", "tcp");
                break;
            case 22:
                params.put("name", "SSH");
                params.put("protocol", "tcp");
                break;
            case 23:
                params.put("name", "TELNET");
                params.put("protocol", "tcp");
                break;
            case 25:
                params.put("name", "SMTP");
                params.put("protocol", "tcp");
                break;
            case 80:
                params.put("name", "HTTP");
                params.put("protocol", "tcp");
                break;
            case 110:
                params.put("name", "POP");
                params.put("protocol", "tcp");
                break;
            case 443:
                params.put("name", "SSL");
                params.put("protocol", "tcp");
                break;
            default:
                params.put("name", "unknown");
                params.put("protocol", "unknown");
                break;
        }

        return params;
    }

    private JSONObject ConvertCommandToParams(String commandName) {
        // Request parameters and other properties.
        JSONObject params = new JSONObject();
        params.put("itime", Instant.EPOCH.getEpochSecond());
        params.put("import_source", "shell");
        params.put("duration", "");
        params.put("command", "Zap");
        params.put("tool", commandName);
        return params;
    }

    private String GetIPFromHostname(String hostname) {
        try {
            InetAddress inetAddr = InetAddress.getByName(hostname);
            byte[] addr = inetAddr.getAddress();

            // Convert to dot representation
            String ipAddr = "";
            for (int i = 0; i < addr.length; i++) {
                if (i > 0) {
                    ipAddr += ".";
                }

                ipAddr += addr[i] & 0xFF;
            }

            System.out.println("IP Address: " + ipAddr);
            return ipAddr;
        } catch (UnknownHostException e) {
            System.out.println("Host not found: " + e.getMessage());
            return "";
        }
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }
}



