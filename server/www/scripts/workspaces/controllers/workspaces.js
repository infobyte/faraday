// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('workspacesCtrl', ['$uibModal', '$scope', '$q', 'workspacesFact', 'dashboardSrv', '$location',
            function($uibModal, $scope, $q, workspacesFact, dashboardSrv, $location) {
        $scope.hash;
        $scope.objects;
        $scope.workspaces;
        $scope.wss;
        $scope.search;

        $scope.init = function() {
            $scope.objects = [];
            $scope.workspaces = [];
            $scope.wss = [];
            // $scope.newworkspace = {};
            
            var hash_tmp = window.location.hash.split("/")[1];
            switch (hash_tmp){
                case "status":
                    $scope.hash = "status";
                    break;
                case "dashboard":
                    $scope.hash = "dashboard";
                    break;
                case "hosts":
                    $scope.hash = "hosts";
                    break;
                default:
                    $scope.hash = "";
            }

            workspacesFact.getWorkspaces().then(function(wss) {

                $scope.wss = []; // Store workspace names
                wss.forEach(function(ws){
                    $scope.wss.push(ws.name);
                    $scope.onSuccessGet(ws);
                    $scope.objects[ws.name] = {
                        "total_vulns": "-",
                        "hosts": "-",
                        "services": "-"
                    };
                    for (var stat in ws.stats) {
                        if (ws.stats.hasOwnProperty(stat)) {
                            if ($scope.objects[ws.name].hasOwnProperty(stat))
                                $scope.objects[ws.name][stat] = ws.stats[stat];
                        }
                    };
                });
            });
        };

        $scope.onSuccessGet = function(workspace){
            workspace.selected = false;
            $scope.workspaces.push(workspace);
        };

        $scope.onSuccessInsert = function(workspace){
            $scope.wss.push(workspace.name); 
            $scope.workspaces.push(workspace); 
        };
        
        $scope.onFailInsert = function(error){
            var modal = $uibModal.open({
                templateUrl: 'scripts/commons/partials/modalKO.html',
                controller: 'commonsModalKoCtrl',
                resolve: {
                    msg: function() {
                        return error;
                    }
                }
            }); 
        };

        $scope.onSuccessEdit = function(workspace){
            for(var i = 0; i < $scope.workspaces.length; i++) {
                if($scope.workspaces[i]._id == workspace._id){
                    $scope.workspaces[i].name = workspace.name;
                    $scope.workspaces[i]._rev = workspace._rev;
                    $scope.workspaces[i].description = workspace.description;
                    if ($scope.workspaces[i].duration === undefined)
                        $scope.workspaces[i].duration = {};
                    $scope.workspaces[i].duration.start_date = workspace.duration.start_date;
                    $scope.workspaces[i].duration.end_date = workspace.duration.end_date;
                    $scope.workspaces[i].scope = workspace.scope;
                    break;
                }
            };
        };

        $scope.onSuccessDelete = function(workspace_name){ 
            remove =  function(arr, item) {
                for(var i = arr.length; i--;) {
                    if(arr[i] === item) {
                        arr.splice(i, 1);
                    }
                }
                return arr;
            };

            $scope.wss = remove($scope.wss, workspace_name); 
            for(var i = 0; i < $scope.workspaces.length; i++) {
                if($scope.workspaces[i].name == workspace_name){
                    $scope.workspaces.splice(i, 1);
                    break;
                }
            };
        };
      
        $scope.insert = function(workspace){
            delete workspace.selected;
            workspacesFact.put(workspace).then(function(resp){
                $scope.onSuccessInsert(workspace)
            },
            $scope.onFailInsert);
        };

        $scope.update = function(ws, wsName){
            if(typeof(ws.duration.start_date) == "number") {
                start_date = ws.duration.start_date;
            } else if(ws.duration.start_date) {
                start_date = ws.duration.start_date.getTime();
            } else {start_date = "";}
            if(typeof(ws.duration.end_date) == "number") {
                end_date = ws.duration.end_date;
            } else if(ws.duration.end_date) {
                end_date = ws.duration.end_date.getTime();
            } else {end_date = "";}
            duration = {'start_date': start_date, 'end_date': end_date};
            workspace = {
                "_id":          ws._id,
                "_rev":         ws._rev,
                "children":     ws.children,
                "customer":     ws.customer,
                "description":  ws.description,
                "duration":     duration,
                "name":         ws.name,
                "scope":        ws.scope,
                "type":         ws.type
            };
            workspacesFact.update(workspace, wsName).then(function(workspace) {
                $scope.onSuccessEdit(workspace);
            });
        };

        $scope.remove = function(workspace_name){
            workspacesFact.delete(workspace_name).then(function(resp) {
                $scope.onSuccessDelete(resp);
            });
        };

        // Modals methods
        $scope.new = function(){ 
            $scope.modal = $uibModal.open({
                templateUrl: 'scripts/workspaces/partials/modalNew.html',
                controller: 'workspacesModalNew',
                size: 'lg'
            });

            $scope.modal.result.then(function(workspace) {
                workspace = $scope.create(workspace.name, workspace.description, workspace.start_date, workspace.end_date, workspace.scope);
                $scope.insert(workspace); 
            });

        };

        $scope.edit = function(){ 
            var workspace;
            $scope.workspaces.forEach(function(w) {
                if(w.selected) {
                    workspace = w;
                }
            });

            if(workspace){
                var oldName = workspace.name;
                var modal = $uibModal.open({
                    templateUrl: 'scripts/workspaces/partials/modalEdit.html',
                    controller: 'workspacesModalEdit',
                    size: 'lg',
                    resolve: {
                        ws: function() {
                            return workspace;
                        }
                    }
                });

                modal.result.then(function(workspace) {
                    if(workspace != undefined){
                        $scope.update(workspace, oldName); 
                    }
                });
            } else {
                var modal = $uibModal.open({
                    templateUrl: 'scripts/commons/partials/modalKO.html',
                    controller: 'commonsModalKoCtrl',
                    resolve: {
                        msg: function() {
                            return 'No workspaces were selected to edit';
                        }
                    }
                });
            }

        };

        $scope.delete = function() {
            var selected = false;

            $scope.workspaces.forEach(function(w) {
                if(w.selected) {
                    selected = true;
                    return;
                }
            });

            if(selected) {
                $scope.modal = $uibModal.open({
                    templateUrl: 'scripts/commons/partials/modalDelete.html',
                    controller: 'commonsModalDelete',
                    size: 'lg',
                    resolve: {
                        msg: function() {
                            var msg = "A workspace will be deleted. This action cannot be undone. Are you sure you want to proceed?";
                            return msg;
                        }
                    }
                });

                $scope.modal.result.then(function() {
                    $scope.workspaces.forEach(function(w) {
                        if(w.selected == true)
                            $scope.remove(w.name); 
                    });
                });
            } else {
                var modal = $uibModal.open({
                    templateUrl: 'scripts/commons/partials/modalKO.html',
                    controller: 'commonsModalKoCtrl',
                    resolve: {
                        msg: function() {
                            return 'No workspaces were selected to delete';
                        }
                    }
                });
            }
        };
        // This is in the modal context only
        $scope.okDelete = function(){
            $scope.modal.close();
        };
        // end of modal context

        $scope.create = function(wname, wdesc, start_date, end_date, scope){
            if(end_date) end_date = end_date.getTime(); else end_date = "";
            if(start_date) start_date = start_date.getTime(); else start_date = "";
            workspace = {
                "_id": wname,
                "customer": "",
                "name": wname,
                "type": "Workspace",
                "children": [
                ],
                "duration": {"start_date": start_date, "end_date": end_date},
                "scope": scope,
                "description": wdesc
            };
            return(workspace);

        };

        $scope.redirect = function(path){
            $location.path("/"+($location.path().split('/')[1] || 'dashboard')+ "/ws/"+path);
        };
        $scope.dashboardRedirect = function(path){
            $location.path("/dashboard/ws/"+path);
        };

        $scope.init();
    }]);
