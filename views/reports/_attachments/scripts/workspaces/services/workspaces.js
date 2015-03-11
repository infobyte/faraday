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
                then(function(resp) { uploadViews(workspace); }, errorHandler);
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
            $http.get(BASEURL + 'reports/_design/reports').
                success(function(data) {
                    var views = {},
                    attachments = data._attachments;
                    if(Object.keys(attachments).length > 0) {
                        for(var prop in attachments) {
                            if(attachments.hasOwnProperty(prop)) {
                                if(prop.indexOf("views/") > -1) {
                                    views[prop] = attachments[prop];
                                }
                            }
                        }
                    }
                }).
                error(function(data) {
                    errorHandler;
                });
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
