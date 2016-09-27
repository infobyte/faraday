// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file "doc/LICENSE" for the license information

// "use strict";  // Elm? Where we"re going we don"t need Elm.

// TODO: handle errors
angular.module("faradayApp")
    .factory("ServerAPI", ["BASEURL", "$http", "$q",
        function(BASEURL, $http, $q) {
            var ServerAPI = {};
            var APIURL = BASEURL + "_api/";

            var createGetUrl = function(wsName, objectName) {
                var objectName = ((objectName) ? "/" + objectName : "");
                var get_url = APIURL + "ws/" + wsName + objectName;
                return get_url;
            };

            var createPostUrl = function(wsName, objectId, rev) {
                if (rev === undefined) {
                    return APIURL + "ws/" + wsName + "/doc/" + objectId;
                }
                else {
                    return APIURL + "ws/" + wsName + "/doc/" + objectId + "?rev=" + rev;
                }
            };

            var createDeleteUrl = createPostUrl; 

            var serverComm = function(method, url, data) {
                var success = function (response) {
                    return response;
                };
                var error = function(response) {
                    return {};
                };
                // return a promise :)
                return $http({method: method, url: url, data: data}).then(success, error);
            };

            var get = function(url, data) {
                return serverComm("GET", url, data);
            };

            var put = function(url, data, is_update) {
                // undefined is just evil...
                if (typeof is_update === "undefined") {var is_update = false;}
                if (is_update) {
                    // ok, undefined, you win
                    var last_rev = get(url).then(function s(r) {return r.data._rev;},
                                                 function e(r) {return undefined})
                    data._rev = last_rev;
                }
                return serverComm("PUT", url, data);
            };

            // delete is a reserved keyword
            var _delete = function(url, is_database, rev_provided) {
                // never let undefined win
                var is_database = typeof is_database === "undefined" ? false: is_database;
                var rev_provided = typeof is_database === "undefined" ? false: rev_provided;
                var data = {};
                if (is_database === false || rev_provided === false ) {
                    var last_rev = get(url).then(function s(r) {return r.data._rev;},
                                                 function e(r) {return undefined});
                    data.rev = last_rev;
                }
                return serverComm("DELETE", url, data);
            };

            var modHost = function(createOrUpdate, wsName, host) {
                if (typeof host.description === "undefined") {host.description = ""};
                if (typeof host.owner === "undefined") {host.owner = ""};
                if (typeof host.owned === "undefined") {host.owned = false};
                return createOrUpdate(wsName, host._id, host);
            }

            var modInterface = function(createOrUpdate, wsName, _interface) {
                if (typeof _interface.owned === "undefined") {_interface.owned = false};
                if (typeof _interface.owner === "undefined") {_interface.owner = ""};
                return createOrUpdate(wsName, _interface._id, _interface);
            }

            var modService = function(createOrUpdate, wsName, service) {
                if (typeof service.owned === "undefined") {service.owned = false};
                if (typeof service.owner === "undefined") {service.owner = ""};
                if (typeof service.protocol === "undefined") {service.protocol = ""};
                if (typeof service.status === "undefined") {service.status = ""};
                if (typeof service.version === "undefined") {service.version = ""};
                return createOrUpdate(wsName, service._id, service);
            }

            var modVuln = function(createOrUpdate, wsName, vuln) {
                if (typeof vuln.owner === "undefined") {vuln.owner = ""};
                if (typeof vuln.description === "undefined") {vuln.description = ""};
                if (typeof vuln.protocol === "undefined") {vuln.protocol = ""};
                if (typeof vuln.status === "undefined") {vuln.status = ""};
                if (typeof vuln.version === "undefined") {vuln.version = ""};
                if (typeof vuln.confirmed === "undefined") {vuln.confirmed = false};
                if (typeof vuln.data === "undefined") {vuln.data = ""};
                if (typeof vuln.severity === "undefined") {vuln.severity = "info"};
                if (typeof vuln.resolution === "undefined") {vuln.resolution = ""};
                vuln.desc = vuln.description;
                return createOrUpdate(wsName, vuln._id, vuln);
            }

            var modVulnWeb = function(createOrUpdate, wsName, vulnWeb) {
                if (typeof vulnWeb.owner === "undefined") {vuln.owner = ""};
                if (typeof vuln.description === "undefined") {vuln.description = ""};
                if (typeof vulnWeb.protocol === "undefined") {vuln.protocol = ""};
                if (typeof vulnWeb.status === "undefined") {vuln.status = ""};
                if (typeof vulnWeb.version === "undefined") {vuln.version = ""};
                if (typeof vulnWeb.confirmed === "undefined") {vuln.confirmed = false};
                if (typeof vulnWeb.data === "undefined") {vuln.data = ""};
                if (typeof vulnWeb.severity === "undefined") {vuln.severity = "info"};
                if (typeof vulnWeb.resolution === "undefined") {vuln.resolution = ""};
                if (typeof vulnWeb.params === "undefined") {vuln.parmas = ""};
                vuln.desc = vuln.description;
                return createOrUpdate(wsName, vulnWeb._id, vulnWeb);
            }

            var modNote = function(createOrUpdate, wsName, note) {
                if (typeof note.owner === "undefined") {note.owner = ""};
                if (typeof note.description === "undefined") {note.description = ""};
                return createOrUpdate(weName, note._id, note);
            }

            var modCredential = function(createOrUpdate, wsName, credential) {
                if (typeof credential.owner === "undefined") {credential.owner = ""};
                if (typeof credential.description === "undefined") {credential.description = ""};
                return createOrUpdate(wsName, credential._id, credential); 
            }

            var modCommand = function(createOrUpdate, wsName, command) {
                    return createOrUpdate(wsName, command._id, command);
            }

            var createObject = function(wsName, id, data) {
                var postUrl = createPostUrl(wsName, id);
                return put(postUrl, data, false);
            }

            var updateObject = function(wsName, id, data) {
                var postUrl = createPostUrl(wsName, id);
                return put(postUrl, data, true);
            }

            var saveInServer = function(wsName, objectId, data) {
                var postUrl = createPostUrl(wsName, objectId);
                return put(postUrl, data, false);
            }

            var updateInServer = function(wsName, objectId, data) {
                var postUrl = createPostUrl(wsName, objectId);
                return put(postUrl, objectId, true);
            }

            ServerAPI.getHosts = function(wsName, data) {
                var url = createGetUrl(wsName, 'hosts');
                return get(url, data);
            }
            
            ServerAPI.getVulns = function(wsName, data) {
                var getUrl = createGetUrl(wsName, 'vulns');
                return get(getUrl, data);
            }

            ServerAPI.getInterfaces = function(wsName, data) {
                var getUrl = createGetUrl(wsName, 'interfaces');
                return get(getUrl, data);
            }

            ServerAPI.getServices = function(wsName, data) {
                var getUrl = createGetUrl(wsName, 'services');
                return get(getUrl, data);
            }

            ServerAPI.getNotes = function(wsName, data) {
                var getUrl = createGetUrl(wsName, 'notes');
                return get(getUrl, data);
            }

            ServerAPI.getCredentials = function(wsName, data) {
                var getUrl = createGetUrl(wsName, 'credentials');
                return get(getUrl, data);
            }

            ServerAPI.getCommands = function(wsName, data) {
                var getUrl = createGetUrl(wsName, 'commands');
                return get(getUrl, data);
            }

            ServerAPI.getWorkspacesNames = function() {
                return get(APIURL + "ws");
            }

            ServerAPI.getWorkspace = function(wsName) {
                getUrl = BASEURL + wsName + "/" + wsName;
                return get(getUrl);
            }

            ServerAPI.getWorkspaceSummary = function(wsName) {
                var getUrl = createGetUrl(wsName, "summary");
                return get(getUrl);
            }


            ServerAPI.createHost = function(wsName, host) {
                    return modHost(createObject, wsName, host);
            }

            ServerAPI.updateHost = function(wsName, host) {
                    return modHost(updateObject, wsName, host);
            }

            ServerAPI.createInterface = function(wsName, interface) {
                    return modInterface(createObject, wsName, interface);
            }

            ServerAPI.updateInterface = function(wsName, interface) {
                    return modInterface(updateObject, wsName, interface);
            }

            ServerAPI.createService = function(wsName, service) {
                    return modService(createObject, wsName, service);
            }

            ServerAPI.updateService = function(wsName, service) {
                    return modService(updateObject, wsName, service);
            }

            ServerAPI.createVuln = function(wsName, vuln) {
                return modVuln(createObject, wsName, vuln)
            }

            ServerAPI.updateVuln = function(wsName, vuln) {
                    return modVuln(updateObject, wsName, vuln);
            }

            ServerAPI.createVulnWeb = function(wsName, vulnWeb) {
                    return modVulnWeb(createObject, wsName, vulnWeb);
            }

            ServerAPI.updateVulnWeb = function(wsName, vulnWeb) {
                    return modVulnWeb(updateObject, wsName, vulnWeb);
            }

            ServerAPI.createNote = function(wsName, note) {
                    return modNote(createObject, wsName, note);
            }

            ServerAPI.updateNote = function(wsName, note) {
                    return modNote(updateObject, wsName, note);
            }

            ServerAPI.createCredential = function(wsName, credential) {
                    return modCredential(createObject, wsName, credential);
            }

            ServerAPI.updateCredential = function(wsName, credential) {
                    return modCredential(updateObject, wsName, credential);
            }

            ServerAPI.createCommand = function(wsName, command) {
                    return modCommand(createObject, wsName, command);
            }

            ServerAPI.updateCommand = function(wsName, command) {
                    return modCommand(updateObject, wsName, command);
            }

            ServerAPI.createDB = function(wsName) {
                var dbUrl = BASEURL + wsName;
                return put(dbUrl);
            }

            ServerAPI.uploadWsDoc = function(workspace) {
                var putUrl = BASEURL + workspace.name + "/" + workspace.name;
                return put(putUrl, workspace);
            }

            ServerAPI.updateWsDoc = function(workspace) {
                var putUrl = BASEURL + workspace.name + "/" + workspace.name;
                return put(putUrl, workspace, true)
            }

            ServerAPI.deleteHost = function(wsName, hostId, rev) {
                var deleteUrl = createDeleteUrl(wsName, hostId, rev);
                if (typeof rev === "undefined") {
                    return _delete(deleteUrl, false, false)
                }
                else {
                    return _delete(deleteUrl, false, true);
                }
            }

            ServerAPI.deleteInterface = function(wsName, interfaceId, rev) {
                var deleteUrl = createDeleteUrl(wsName, interfaceId, rev);
                if (typeof rev === "undefined") {
                    return _delete(deleteUrl, false, false)
                }
                else {
                    return _delete(deleteUrl, false, true);
                }
            }

            ServerAPI.deleteService = function(wsName, serviceId, rev) {
                var deleteUrl = createDeleteUrl(wsName, serviceId, rev);
                if (typeof rev === "undefined") {
                    return _delete(deleteUrl, false, false)
                }
                else {
                    return _delete(deleteUrl, false, true);
                }
            }

            ServerAPI.deleteVuln = function(wsName, vulnId, rev) {
                var deleteUrl = createDeleteUrl(wsName, vulnId, rev);
                if (typeof rev === "undefined") {
                    return _delete(deleteUrl, false, false)
                }
                else {
                    return _delete(deleteUrl, false, true);
                }
            }

            ServerAPI.deleteNote = function(wsName, noteId, rev) {
                var deleteUrl = createDeleteUrl(wsName, noteId, rev);
                if (typeof rev === "undefined") {
                    return _delete(deleteUrl, false, false)
                }
                else {
                    return _delete(deleteUrl, false, true);
                }
            }

            ServerAPI.deleteCredential = function(wsName, credentialId, rev) {
                var deleteUrl = createDeleteUrl(wsName, credentialid, rev);
                if (typeof rev === "undefined") {
                    return _delete(deleteUrl, false, false)
                }
                else {
                    return _delete(deleteUrl, false, true);
                }
            }

            ServerAPI.deleteCommand = function(wsName, commandId, rev) {
                var deleteUrl = createDeleteUrl(wsName, commandId, rev);
                if (typeof rev === "undefined") {
                    return _delete(deleteUrl, false, false)
                }
                else {
                    return _delete(deleteUrl, false, true);
                }
            }

            ServerAPI.deleteWorkspace = function(wsName) {
                var deleteUrl = BASEURL + wsName 
                return _delete(deleteUrl, true)
            }

        return ServerAPI;
    }]);
