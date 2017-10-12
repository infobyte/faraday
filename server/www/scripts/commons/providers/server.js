// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file "doc/LICENSE" for the license information

// "use strict";  // Elm? Where we"re going we don"t need Elm.

// TODO: handle errors
angular.module("faradayApp")
    .factory("ServerAPI", ["BASEURL", "$http", "$q",
        function(BASEURL, $http, $q) {
            var ServerAPI = {};
            var APIURL = BASEURL + "_api/v2/";

            var createGetRelatedUrl = function(wsName, objectType, objectId, relatedObjectType) {
                var objectName = ((objectName) ? "/" + objectType : "");
                return get_url = APIURL + "ws/" + wsName + "/" + objectType + "/" + objectId + "/" + relatedObjectType + "/";
            };

            var createGetUrl = function(wsName, objectName, objectId) {
                var objectName = ((objectName) ? "/" + objectName : "");
                if (typeof objectId == 'string' || typeof objectId ==  "number") {
                    objectName = objectName + "/" + objectId;
                }

                return APIURL + "ws/" + wsName + objectName + "/";
            };

            var createNewGetUrl = function(wsName, objectId, objectType) {
                return APIURL + "ws/" + wsName + "/" + objectType + "/" + objectId;
            }

            var createPostUrl = function(wsName, objectId, objectType) {
                return APIURL + "ws/" + wsName + "/" + objectType + "/";
            };

            var createPutUrl = function(wsName, objectId, objectType) {
                return APIURL + "ws/" + wsName + "/" + objectType + "/" + objectId + "/";
            };

            var createDbUrl = function(wsName) {
                return APIURL + "ws/" + wsName;
            }

            var createDeleteUrl = createPutUrl;

            var serverComm = function(method, url, data) {
                var success = function (response) {
                    return response;
                };
                var error = function(err) {
                    return $q.reject(err);
                };

                // return a promise :)
                if (method === 'GET' || method === 'DELETE') {
                    return $http({method: method, url: url, params: data}).then(success).catch(error);
                } else { 
                    return $http({method: method, url: url, data: data}).then(success).catch(error);
                }
            };

            var get = function(url, data) {
                return serverComm("GET", url, data);
            };

            var send_data = function(url, data, is_update, method) {
                // undefined is just evil...
                if (typeof is_update === "undefined") {var is_update = false;}
                if (is_update && !data._rev) {
                    // ok, undefined, you win
                    console.log('ok, undefined, you win');
                    return get(url).then(function s(r) {
                        data._rev = r.data._rev;
                        return serverComm(method, url, data);
                    }).catch(function e(r) {$q.reject(r)});
                }
                return serverComm(method, url, data);
            };

            // delete is a reserved keyword
            // just set rev_provided to false if you're deleting a database :)
            var _delete = function(url, rev_provided) {
                // never let undefined win
                if (typeof rev_provided === "undefined") {var rev_provided = false;}
                var deferred = $q.defer();
                var data = {};
                return serverComm("DELETE", url, data);
            };

            var modHost = function(createOrUpdate, wsName, host) {
                if (typeof host.description === "undefined") {host.description = ""};
                if (typeof host.owner === "undefined") {host.owner = ""};
                if (typeof host.owned === "undefined") {host.owned = false};
                if (typeof host.os === "undefined") {host.os = ""};
                return createOrUpdate(wsName, host._id, host, 'hosts');
            }

            var modService = function(createOrUpdate, wsName, service) {
                if (typeof service.owned === "undefined") {service.owned = false};
                if (typeof service.owner === "undefined") {service.owner = ""};
                if (typeof service.protocol === "undefined") {service.protocol = ""};
                if (typeof service.status === "undefined") {service.status = ""};
                if (typeof service.version === "undefined") {service.version = ""};
                return createOrUpdate(wsName, service._id, service, 'services');
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

            var createObject = function(wsName, id, data, collectionName) {
                var postUrl = createPostUrl(wsName, id, collectionName);
                return send_data(postUrl, data, false, "POST");
            }

            var updateObject = function(wsName, id, data, collectionName) {
                var postUrl = createPostUrl(wsName, id, collectionName);
                return send_data(postUrl, data, true, "PUT");
            }

            var saveInServer = function(wsName, objectId, data, collectionName) {
                var postUrl = createPostUrl(wsName, objectId, collectionName);
                return send_data(postUrl, data, false, "PUT");
            }

            var updateInServer = function(wsName, objectId, data, collectionName) {
                var postUrl = createPostUrl(wsName, objectId, collectionName);
                return send_data(postUrl, objectId, true, "PUT");
            }

            ServerAPI.getHost = function(wsName, objId) {
                var url = createGetUrl(wsName, 'hosts', objId);
                return get(url);
            }

            ServerAPI.getHosts = function(wsName, data) {
                var url = createGetUrl(wsName, 'hosts');
                return get(url, data);
            }
            
            ServerAPI.getVulns = function(wsName, data) {
                var getUrl = createGetUrl(wsName, 'vulns');
                return get(getUrl, data);
            }

            ServerAPI.getService = function(wsName, data, objId) {
                var getUrl = createGetUrl(wsName, 'services', objId);
                return get(getUrl);
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
                return get(APIURL + "ws/");
            }

            ServerAPI.getWorkspaces = function() {
                return get(APIURL + "ws/");
            }

            ServerAPI.getWorkspace = function(wsName) {
                var getUrl = createDbUrl(wsName);
                return get(getUrl);
            }

            ServerAPI.getWorkspaceSummary = function(wsName, confirmed) {

                var getUrl = createGetUrl(wsName);
                var payload = {};

                if (confirmed !== undefined) {
                    payload.confirmed = confirmed;
                }
                
                return get(getUrl, payload);
            }

            ServerAPI.getObj = function(wsName, objID) {
                var getUrl = createNewGetUrl(wsName, objID)
                return get(getUrl);
            }

            var getCount = function(wsName, object) {
                var deferred = $q.defer();
                ServerAPI.getWorkspaceSummary(wsName).then(
                    function(response) {
                        deferred.resolve(response.data.stats[object]);
                        }, function(error) {
                        deferred.reject(error);
                    })
                return deferred.promise;
            }

            ServerAPI.getHostCount = function(wsName) {
                return getCount(wsName, 'hosts');
            }

            ServerAPI.getServiceCount = function(wsName) {
                return getCount(wsName, 'services');
            }

            ServerAPI.getServicesBy = function(wsName, what) {
                var url = createGetUrl(wsName, 'services') + '/count/';
                return get(url, {"group_by": what})
            }

            ServerAPI.getServicesByName = function(wsName) {
                return ServerAPI.getServicesBy(wsName, 'name');
            }

            ServerAPI.getServicesByHost = function(wsName, hostId) {
                var url = createGetRelatedUrl(wsName, 'hosts', hostId, 'services');
                return get(url);
            }

            ServerAPI.getVulnsBySeverity = function(wsName, confirmed) {

                var url = createGetUrl(wsName, 'vulns') + '/count/';
                var payload = {'group_by': 'severity'}
                
                if (confirmed !== undefined) {
                    payload.confirmed = confirmed;
                }
                
                return get(url, payload)
            }

            ServerAPI.createHost = function(wsName, host) {
                return modHost(createObject, wsName, host);
            }

            ServerAPI.updateHost = function(wsName, host) {
                    return modHost(updateObject, wsName, host);
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

            ServerAPI.deleteHost = function(wsName, hostId, rev) {
                var deleteUrl = createDeleteUrl(wsName, hostId, rev);
                if (typeof rev === "undefined") {
                    return _delete(deleteUrl, false)
                }
                else {
                    return _delete(deleteUrl, true);
                }
            }

            ServerAPI.deleteService = function(wsName, serviceId) {
                var deleteUrl = createDeleteUrl(wsName, serviceId, 'services');
                if (typeof rev === "undefined") {
                    return _delete(deleteUrl, false)
                }
                else {
                    return _delete(deleteUrl, true);
                }
            }

            ServerAPI.deleteVuln = function(wsName, vulnId, rev) {
                var deleteUrl = createDeleteUrl(wsName, vulnId, rev);
                if (typeof rev === "undefined") {
                    return _delete(deleteUrl, false)
                }
                else {
                    return _delete(deleteUrl, true);
                }
            }

            ServerAPI.deleteNote = function(wsName, noteId, rev) {
                var deleteUrl = createDeleteUrl(wsName, noteId, rev);
                if (typeof rev === "undefined") {
                    return _delete(deleteUrl, false)
                }
                else {
                    return _delete(deleteUrl, true);
                }
            }

            ServerAPI.deleteCredential = function(wsName, credentialId, rev) {
                var deleteUrl = createDeleteUrl(wsName, credentialId, rev);
                if (typeof rev === "undefined") {
                    return _delete(deleteUrl, false)
                }
                else {
                    return _delete(deleteUrl, true);
                }
            }

            ServerAPI.deleteCommand = function(wsName, commandId, rev) {
                var deleteUrl = createDeleteUrl(wsName, commandId, rev);
                if (typeof rev === "undefined") {
                    return _delete(deleteUrl, false)
                }
                else {
                    return _delete(deleteUrl, true);
                }
            }

            ServerAPI.createWorkspace = function(wsName, data) {
                var dbUrl = createDbUrl(wsName);
                return put(dbUrl, data, false)
            }

            ServerAPI.updateWorkspace = function(workspace) {
                var putUrl = createDbUrl(workspace.name);
                return put(putUrl, workspace, true)
            }

            ServerAPI.deleteWorkspace = function(wsName) {
                var dbUrl = createDbUrl(wsName);
                return _delete(dbUrl, false);
            }

        return ServerAPI;
    }]);
