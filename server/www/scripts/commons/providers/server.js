// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file "doc/LICENSE" for the license information

"use strict";  // Elm? Where we"re going we don"t need Elm.

// TODO: handle errors
angular.module("faradayApp")
    .factory("ServerAPI", ["BASEURL", "$http", "$q",
        function(BASEURL, $http, $q) {
            var ServerAPI = {};
            var APIURL = BASEURL + "_api/";

            var getUrl = function(wsName, objectName) {
                var objectName = ((objectName) ? "/" + objectName : "");
                var get_url = APIURL + "ws/" + wsName + objectName;
                return get_url;
            };

            var postUrl = function(wsName, objectId) {
                return APIURL + "ws/" + wsName + "/doc/" + objectId;
            };

            var deleteUrl = postUrl; 

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
                var is_update = typeof is_update === "undefined" ? false : true;
                if (is_update) {
                    var last_rev = get(url)._rev;
                    data._rev = last_rev;
                }
                return serverComm("PUT", url, data);
            };

            // delete is a reserved keyword
            var _delete = function(url, is_database) {
                // never let undefined win
                var is_database = typeof is_database === "undefined" ? false: true;
                var data = {};
                if (is_database === true) {
                    var last_rev = get(url)._rev;
                    data.rev = last_rev;
                }
                return serverComm("DELETE", url, data);
            };

            var modHost = function(createOrUpdate, wsName, id, name, os,
                defaultGateway, description, metadata, owned, owner, objParent) {
                    var description = typeof description !== "undefined" ? description : "";
                    var owner = typeof owner !== 'undefined' ? owner : "";
                    var owned = typeof owned !== 'undefined' ? owned : false;
                    var data = {};
                    data.id = id;
                    data.name = name;
                    data.os = os;
                    data.defaulGateway = defaultGateway;
                    data.description = description;
                    data.metadata = metadata;
                    data.owned = owned;
                    data.owner = owner;
                    data.objParent = objParent;
                    data.type = "Host";
                    return createOrUpdate(wsName, id, data);
            }

            var modInterface = function(createOrUpdate, wsName, id, name, description,
                mac, owned, owner, hostnames, networkSegment, ipv4, ipv6, metadata) {
                    var owned = typeof owned !== "undefined" ? owned : false;
                    var owner = typeof owner !== 'undefined' ? owner : "";
                    var data = {};
                    data.id = id;
                    data.name = name;
                    data.description = description;
                    data.mac = mac;
                    data.owned = owned;
                    data.hostnames = hostnames;
                    data.networkSegment = networkSegment;
                    data.ipv4 = ipv4;
                    data.ipv6 = ipv6;
                    data.metadata = metadata;
                    data.type = "Interface"
                    return createOrUpdate(wsName, id, data);
            }

            var modService = function(createOrUpdate, wsName, id, name, description,
                ports, owned, owner, protocol, status, version, metadata) {
                    var owned = typeof owned !== "undefined" ? owned : false;
                    var owner = typeof owner !== 'undefined' ? owner : "";
                    var protocol = typeof protocol !== 'undefined' ? protocol : "";
                    var status = typeof status !== 'undefined' ? status : "";
                    var version = typeof version !== 'undefined' ? version : "";
                    var data = {};
                    data.id = id;
                    data.name = name;
                    data.description = description;
                    data.ports = ports;
                    data.owned = owned;
                    data.owner = owner;
                    data.protocol = protocol;
                    data.status = status;
                    data.version = version;
                    data.metadata = metadata;
                    data.type = "Service"
                    return createOrUpdate(wsName, id, data);
            }

            var modVuln = function(createOrUpdate, wsName, id, name, description,
                owned, owner, confirmed, data, refs, severity, resolution, desc,
                metadata) {
                    var owner = typeof owner !== 'undefined' ? owner : "";
                    var protocol = typeof protocol !== 'undefined' ? protocol : "";
                    var status = typeof status !== 'undefined' ? status : "";
                    var version = typeof version !== 'undefined' ? version : "";
                    var confirmed = typeof confirmed !== 'undefined' ? confirmed : false;
                    var data = typeof data !== 'undefined' ? data : "";
                    var serverity = typeof serverity !== 'undefined' ? serverity : "info";
                    var resolution = typeof resolution !== 'undefined' ? resolution : "";
                    var desc = typeof desc !== 'undefined' ? desc : "";
                    var data_ = {};
                    data_.id = id;
                    data_.name = name;
                    data_.description = description;
                    data_.owned = owned;
                    data_.owner = owner;
                    data_.confirmed = confirmed;
                    data_.data = data;
                    data_.refs = refs;
                    data_.severity = severity;
                    data_.resolution = resolution;
                    data_.desc = desc;
                    data_.metadata = metadata;
                    data_.type = "Vulnerability"
                    return createOrUpdate(wsName, id, data_);
            }

            var modVulnWeb = function(createOrUpdate, wsName, id, name, description,
                owned, owner, confirmed, data, refs, severity, resolution,
                desc, metadata, method, params, path, pname, query, request,
                response, category, website) {
                    var owner = typeof owner !== 'undefined' ? owner : "";
                    var protocol = typeof protocol !== 'undefined' ? protocol : "";
                    var status = typeof status !== 'undefined' ? status : "";
                    var version = typeof version !== 'undefined' ? version : "";
                    var confirmed = typeof confirmed !== 'undefined' ? confirmed : false;
                    var data = typeof data !== 'undefined' ? data : "";
                    var serverity = typeof serverity !== 'undefined' ? serverity : "info";
                    var resolution = typeof resolution !== 'undefined' ? resolution : "";
                    var desc = typeof desc !== 'undefined' ? desc : "";
                    var params = typeof desc !== 'undefined' ? desc : "";
                    var data_ = {};
                    data_.id = id;
                    data_.name = name;
                    data_.description = description;
                    data_.owned = owned;
                    data_.owner = owner;
                    data_.confirmed = confirmed;
                    data_.data = data;
                    data_.refs = refs;
                    data_.severity = severity;
                    data_.resolution = resolution;
                    data_.desc = desc;
                    data_.metadata = metadata;
                    data_.method = method;
                    data_.params = params;
                    data_.path = path;
                    data_.pname = pname;
                    data_.query = query;
                    data_.request = request;
                    data_.response = response;
                    data_.category = category;
                    data_.website = website;
                    data_.type = "VulnerabilityWeb"
                    return createOrUpdate(wsName, id, data_);
            }

            var modNote = function(createOrUpdate, wsName, id, name, text, owned,
                owner, description, metadata) {
                    var owner = typeof owner !== 'undefined' ? owner : "";
                    var description = typeof description !== 'undefined' ? description : "";
                    var data = {};
                    data.id = id;
                    data.name = name;
                    data.text = text;
                    data.owned = owned;
                    data.owner = owner;
                    data.description = description;
                    data.metadata = metadata;
                    data.type = "Note"
                    return createOrUpdate(weName, id, data);
            }

            var modCredential = function(createOrUpdate, wsName, id, name,
                username, password, owned, owner, description, metadata) {
                    var owner = typeof owner !== 'undefined' ? owner : "";
                    var description = typeof description !== 'undefined' ? description : "";
                    var data = {};
                    data.id = id;
                    data.name = name;
                    data.username = username;
                    data.password = password;
                    data.owned = owned;
                    data.owner = owner;
                    data.description = description;
                    data.metadata = metadata;
                    data.type = "Credential"
                    return createOrUpdate(wsName, id, data); 
            }

            var modCommand = function(createOrUpdate, wsName, id,
                command, duration, hostname, ip, itime, params, user) {
                    var data = {};
                    data.id = id;
                    data.command = command;
                    data.duration = duration;
                    data.hostname = hostname;
                    data.ip = ip;
                    data.itime = itime;
                    data.params = params;
                    data.user = user;
                    data.type = "CommandRunInformation"
                    return createOrUpdate(wsName, id, data);
            }
            var saveInServer = function(wsName, objectId, data) {
                var postUrl = postUrl(wsName, objectId);
                return put(postUrl, data, false);
            }

            var updateInServer = function(wsName, objectId, data) {
                var postUrl = postUrl(wsName, objectId);
                return put(postUrl, objectId, true);
            }

            ServerAPI.getHosts = function(wsName, data) {
                var url = getUrl(wsName, 'hosts');
                return get(url, data);
            }
            
            ServerAPI.getVulns = function(wsName, data) {
                var getUrl = getUrl(wsName, 'vulns');
                return get(getUrl, data);
            }

            ServerAPI.getInterfaces = function(wsName, data) {
                var getUrl = getUrl(wsName, 'interfaces');
                return get(getUrl, data);
            }

            ServerAPI.getServices = function(wsName, data) {
                var getUrl = getUrl(wsName, 'services');
                return get(getUrl, data);
            }

            ServerAPI.getNotes = function(wsName, data) {
                var getUrl = getUrl(wsName, 'notes');
                return get(getUrl, data);
            }

            ServerAPI.getCredentials = function(wsName, data) {
                var getUrl = getUrl(wsName, 'credentials');
                return get(getUrl, data);
            }

            ServerAPI.getCommands = function(wsName, data) {
                var getUrl = getUrl(wsName, 'commands');
                return get(getUrl, data);
            }

            ServerAPI.getWorkspacesNames = function() {
                return get(APIURL + "ws");
            }

            ServerAPI.getWorkspaceSummary = function() {
                var getUrl = getUrl(wsName, "summary");
                return get(getUrl);
            }

            var createObject = function(wsName, id, data) {
                var _postUrl = postUrl(wsName, id);
                return put(_postUrl, data, false);
            }

            var updateObject = function(wsName, id, data) {
                var postUrl = postUrl(wsName, id);
                return put(postUrl, data, true);
            }

            ServerAPI.createHost = function(wsName, id, name, os, defaultGateway,
                description, metadata, owned, owner, objParent) {
                    return modHost(createObject, wsName, id, name, os,
                        defaultGateway, description, metadata, owned, owner,
                        objParent);
            }

            ServerAPI.updateHost = function(wsName, id, name, os, defaultGateway,
                description, metadata, owned, owner, objParent) {
                    return modHost(updateObject, wsName, id, name, os, defaulGateway,
                        description, metadata, owned, owner, objParent);
            }

            ServerAPI.createInterface = function(wsName, id, name, description,
                mac, owned, owner, hostnames, networkSegment, ipv4, ipv6, metadata) {
                    return modInterface(createObject, wsName, id, name, description,
                        mac, owned, owner, hostnames, networkSegment, ipv4, ipv6, 
                        metadata);
            }

            ServerAPI.updateInterface = function(wsName, id, name, description,
                mac, owned, owner, hostnames, networkSegment, ipv4, ipv6, metadata) {
                    return modInterface(updateObject, wsName, id, name, description,
                        mac, owned, owner, hostnames, networkSegment, ipv4, ivp6, 
                        metadata);
            }

            ServerAPI.createService = function(wsName, id, name, description,
                ports, owned, owner, protocol, status, version, metadata) {
                    return modService(createObject, wsName, id, name, description,
                        ports, owned, owner, protocol, status, version, metadata);
            }

            ServerAPI.updateService = function(wsName, id, name, description,
                ports, owned, owner, protocol, status, version, metadata) {
                    return modService(updateObject, wsName, id, name, description,
                        ports, owned, owner, protocol, status, version, metadata);
            }

            ServerAPI.createVuln = function(wsName, id, name, description,
                owned, owner, confirmed, data, refs, severity, resolution,
                desc, metadata) {
                    return modVuln(createObject, wsName, id, name, description,
                        owned, owner, confirmed, data, refs, severity, resolution,
                        desc, metadata);
            }

            ServerAPI.updateVuln = function(wsName, id, name, description,
                owned, owner, confirmed, data, refs, severity, resolution,
                desc, metadata) {
                    return modVuln(updateObject, wsName, id, name, description,
                        owned, owner, confirmed, data, refs, severity, resolution,
                        desc, metadata);
            }

            ServerAPI.createVulnWeb = function(wsName, id, name, description, owned,
                owner, confirmed, data, refs, severity, resolution, desc,
                metadata, method, params, path, pname, query, request, response,
                category, website) {
                    return modVulnWeb(createObject, wsName, id, name, description, owned,
                        owner, confirmed, data, refs, severity, resolution, desc,
                        metadata, method, params, path, pname, query, request, response,
                        category, website);
            }

            ServerAPI.updateVulnWeb = function(wsName, id, name, description, owned,
                owner, confirmed, data, refs, severity, resolution, desc,
                metadata, method, params, path, pname, query, request, response,
                category, website) {
                    return modVulnWeb(updateObject, wsName, id, name, description, owned,
                        owner, confirmed, data, refs, severity, resolution, desc,
                        metadata, method, params, path, pname, query, request, response,
                        category, website);
            }

            ServerAPI.createNote = function(wsName, id, name, text, owned,
                owner, description, metadata) {
                    return modNote(createObject, wsName, id, name, text, owned,
                        owner, description, metadata);
            }

            ServerAPI.updateNote = function(wsName, id, name, text, owned,
                owner, description, metadata) {
                    return modNote(updateObject, wsName, id, name, text, owned,
                        owner, description, metadata);
            }

            ServerAPI.createCredential = function(wsName, id, name, username,
                password, owned, owner, descritpion, metadata) {
                    return modCredential(createObject, wsName, id, name, username,
                        password, owned, owner, description, metadata);
            }

            ServerAPI.updateCredential = function(wsName, id, name, username,
                password, owned, owner, descritpion, metadata) {
                    return modCredential(updateObject, wsName, id, name, username,
                        password, owned, owner, description, metadata);
            }

            ServerAPI.createCommand = function(wsName, id, command, duration, hostname,
                ip, itime, params, user) {
                    return modCommand(createObject, wsName, id, command, duration,
                        hostname, ip, itime, params, user);
            }

            ServerAPI.updateCommand = function(wsName, id, command, duration, hostname,
                ip, itime, params, user) {
                    return modCommand(updateObject, wsName, id, command, duration,
                        hostname, ip, itime, params, user);
            }

            ServerAPI.createWorkspace = function(wsName, description, startDate, finishDate,
                customer) {
                    var createDB = function(wsName) {
                        var dbUrl = BASEURL + wsName
                        return put(dbUrl)
                    }
                    createDB(wsName);
                    var wsDoc = {};
                    wsDoc.description = description;
                    wsDoc.startDate = startDate;
                    wsDoc.finishDate = finishDate;
                    wsDoc.customer = customer;
                    var putUrl = BASEURL + wsName + "/" + wsName;
                    return put(putUrl, wsDoc)
            }

            ServerAPI.deleteHost = function(wsName, hostId) {
                deleteUrl = deleteUrl(wsName, hostId);
                return _delete(deleteUrl);
            }

            ServerAPI.deleteInterface = function(wsName, interfaceId) {
                deleteUrl = deleteUrl(wsName, interfaceId);
                return _delete(interfaceId);
            }

            ServerAPI.deleteService = function(wsName, serviceId) {
                deleteUrl = deleteUrl(wsName, serviceId);
                return _delete(deleteUrl);
            }

            ServerAPI.deleteVuln = function(wsName, vulnId) {
                deleteUrl = deleteUrl(wsName, vulnId);
                return _delete(deleteUrl);
            }

            ServerAPI.deleteNote = function(wsName, noteId) {
                deleteUrl = deleteUrl(wsName, noteId);
                return _delete(deleteUrl);
            }

            ServerAPI.deleteCredential = function(wsName, credentialId) {
                deleteUrl = deleteUrl(wsName, credentialid);
                return _delete(deleteUrl);
            }

            ServerAPI.deleteCommand = function(wsName, commandId) {
                deleteUrl = deleteUrl(wsName, commandId);
                return _delete(deleteUrl);
            }

            ServerAPI.deleteWorkspace = function(wsName) {
                deleteUrl = BASEURL + wsName 
                return _delete(deleteUrl, true)
            }

        return ServerAPI;
    }]);
