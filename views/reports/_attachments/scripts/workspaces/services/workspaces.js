// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('workspacesFact', ['BASEURL', '$http', '$q', function(BASEURL, $http, $q) {
        var workspacesFact = {};

        workspacesFact.list = function(callback) { 
            var url = BASEURL + "_all_dbs";
            $http.get(url).success(function(d, s, h, c) {
                var wss = d.filter(function(ws) {
                    return ws.search(/^_/) < 0 && ws.search("cwe") < 0 && ws.search("reports") < 0;
                });
                callback(wss);
            });
        };

        workspacesFact.get = function(workspace_name, onSuccess) {
            return $http.get(BASEURL + workspace_name + '/' + workspace_name).
                success(function(data, status, headers, config) {
                onSuccess(data);
            });
        };

        workspacesFact.exists = function(workspace_name) {
            var request = {
                method: 'HEAD',
                url: BASEURL + workspace_name
            };
            var exists_workspace = false;
            return $http(request).success(function(data) {
                exists_workspace = true;
            });
            return exists_workspace;
        };

        errorHandler = function(response) {
            return $q.reject(response.data.reason.replace("file", "workspace")); 
        };

        workspacesFact.put = function(workspace) {
            return createDatabase(workspace).
                then(function(resp) { createWorkspaceDoc(resp, workspace); }, errorHandler).
                then(function(resp) { uploadViews(workspace.name); }, errorHandler);
        };

        createDatabase = function(workspace){
            return $http.put(BASEURL + workspace.name, workspace);
        };

        createWorkspaceDoc = function(response, workspace){
            $http.put(BASEURL + workspace.name + '/' + workspace.name, workspace).
                success(function(data){ 
                    workspace._rev = response.data.rev;
                }).
                error(function(data) {
                    errorHandler;
                });
        };

        uploadViews = function(workspace) {
            var bulk = {docs:[]},
            paths = {},
            reports = BASEURL + 'reports/_design/reports';
            $http.get(reports).
                success(function(data) {
                    var attachments = data._attachments;
                    if(Object.keys(attachments).length > 0) {
                        for(var prop in attachments) {
                            if(attachments.hasOwnProperty(prop)) {
                                if(prop.indexOf("views/") > -1) {
                                    paths[prop] = $http.get(reports + "/" + prop);
                                }
                            }
                        }
                    }
                    $q.all(paths).then(function(resp) {
                        for(var path in paths) {
                            if(paths.hasOwnProperty(path)) {
                                var parts = path.split("/"), 
                                component = parts[1], 
                                name = parts[3], 
                                file = parts[4].split(".")[0],
                                docIndex = indexOfDocument(bulk.docs, "_design/"+component);

                                if(docIndex == -1) {
                                    bulk.docs.push({
                                        _id: "_design/"+component,
                                        language: "javascript",
                                        views: {}
                                    });
                                    docIndex = bulk.docs.length - 1;
                                }

                                if(!bulk["docs"][docIndex]["views"].hasOwnProperty(name)) {
                                    bulk["docs"][docIndex]["views"][name] = {};
                                }

                                bulk["docs"][docIndex]["views"][name][file] = resp[path]["data"];
                            }
                        }
                        $http.post(BASEURL + workspace + "/_bulk_docs", JSON.stringify(bulk));
                    }, errorHandler);
                }).
                error(function(data) {
                    errorHandler;
                });
        };

        indexOfDocument = function(list, name) {
            var ret = -1;
            list.forEach(function(item, index) {
                if(item._id == name) {
                    ret = index;
                }
            });
            return ret;
        };

        workspacesFact.update = function(workspace, onSuccess) {
            document_url = BASEURL + workspace.name + '/' + workspace.name + '?rev=' + workspace._rev;
            return $http.put(document_url, workspace).success(function(data){
                workspace._rev = data.rev;
                onSuccess(workspace);
            });
        };

        workspacesFact.delete = function(workspace_name, onSuccess) {
            var request = {
                method: 'DELETE',
                url: BASEURL + workspace_name,
            };
            return $http(request).success(function(data) {
                onSuccess(workspace_name);
            });
        };
        return workspacesFact;
    }]);
