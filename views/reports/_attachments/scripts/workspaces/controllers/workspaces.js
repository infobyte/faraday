// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('workspacesCtrl', ['$modal', '$scope', '$q', 'workspacesFact', 'dashboardSrv',
            function($modal, $scope, $q, workspacesFact, dashboardSrv) {
        $scope.dateOptions;
        $scope.hash;
        $scope.minDate;
        $scope.objects;
        $scope.workspaces;
        $scope.wss;

        $scope.init = function() {
            $scope.objects = [];
            $scope.workspaces = [];
            $scope.wss = [];
            // $scope.newworkspace = {};
            $scope.minDate = new Date();
            $scope.dateOptions = {
                formatYear: 'yy',
                startingDay: 1
            };
            
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

            // todo: refactor the following code
            workspacesFact.list().then(function(wss) {
                $scope.wss = wss;
                var objects = {};
                $scope.wss.forEach(function(ws){
                    workspacesFact.get(ws).then(function(resp) {
                        $scope.onSuccessGet(resp);
                    });
                    objects[ws] = dashboardSrv.getObjectsCount(ws);
                });
                $q.all(objects).then(function(os) {
                    for(var workspace in os) {
                        if(os.hasOwnProperty(workspace)) {
                            $scope.objects[workspace] = {
                                "total vulns": "-",
                                "hosts": "-",
                                "services": "-"
                            };
                            os[workspace].forEach(function(o) {
                                $scope.objects[workspace][o.key] = o.value;
                            });
                        }
                    }
                });
            });
        };

        $scope.onSuccessGet = function(workspace){
            if(workspace.sdate.toString().indexOf(".") != -1) workspace.sdate = workspace.sdate * 1000;
            workspace.selected = false;
            $scope.workspaces.push(workspace);
        };

        $scope.onSuccessInsert = function(workspace){
            workspace.sdate = workspace.sdate;
            $scope.wss.push(workspace.name); 
            $scope.workspaces.push(workspace); 
        };
        
        $scope.onFailInsert = function(error){
            var modal = $modal.open({
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
                if($scope.workspaces[i].name == workspace.name){
                    $scope.workspaces[i]._rev = workspace._rev;
                    $scope.workspaces[i].description = workspace.description;
                    $scope.workspaces[i].duration.start = workspace.duration.start;
                    $scope.workspaces[i].duration.end = workspace.duration.end;
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

        $scope.update = function(workspace){
            if(typeof(workspace.duration.startDate) == "number") {
                start = workspace.duration.startDate;
            } else if(workspace.duration.startDate) {
                start = workspace.duration.startDate.getTime(); 
            } else {start = "";}
            if(typeof(workspace.duration.endDate) == "number") {
                end = workspace.duration.endDate;
            } else if(workspace.duration.endDate) {
                end = workspace.duration.endDate.getTime();
            } else {end = "";}
            duration = {'start': start, 'end': end};
            workspace = {
                "_id":          workspace._id,
                "_rev":         workspace._rev,
                "children":     workspace.children,
                "customer":     workspace.customer,
                "description":  workspace.description,
                "duration":     duration,
                "name":         workspace.name,
                "scope":        workspace.scope,
                "sdate":        workspace.sdate,
                "selected":     workspace.selected,
                "type":         workspace.type
            };
            workspacesFact.update(workspace).then(function(resp) {
                $scope.onSuccessEdit(resp);
            });
        };

        $scope.remove = function(workspace_name){
            workspacesFact.delete(workspace_name, $scope.onSuccessDelete);
        };

        // Modals methods
        $scope.new = function(){ 
            $scope.newworkspace = {};

            $scope.modal = $modal.open({
                templateUrl: 'scripts/workspaces/partials/modalNew.html',
                controller: 'workspacesCtrl',
                scope: $scope,
                size: 'lg'
            });

            $scope.modal.result.then(function(workspace) {
                workspace = $scope.create(workspace.name, workspace.description, workspace.start, workspace.end, workspace.scope);
                $scope.insert(workspace); 
            });

        };

        $scope.okNew = function(){
            $scope.modal.close($scope.newworkspace);
        };

        $scope.edit = function(){ 
            var selected = false;
            $scope.workspaces.forEach(function(w) {
                if(w.selected) {
                    selected = true;
                    return;
                }
            });

            if(selected){
                $scope.workspaces.forEach(function(w){
                    if(w.selected){
                        $scope.newworkspace = w;
                        if($scope.newworkspace.duration){
                            $scope.newworkspace.duration.startDate = w.duration.start;
                            $scope.newworkspace.duration.endDate = w.duration.end;
                        }
                    } 
                });
                $scope.modal = $modal.open({
                    templateUrl: 'scripts/workspaces/partials/modalEdit.html',
                    controller: 'workspacesCtrl',
                    scope: $scope,
                    size: 'lg'
                });

                $scope.modal.result.then(function(workspace) {
                    $scope.update(workspace); 
                });
            } else {
                var modal = $modal.open({
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

        $scope.okEdit = function() {
            $scope.modal.close($scope.newworkspace);
        };


        $scope.cancel = function() {
            $scope.modal.close();
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
                $scope.modal = $modal.open({
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
                var modal = $modal.open({
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

        $scope.create = function(wname, wdesc, start, end, scope){
            if(end) end = end.getTime(); else end = "";
            if(start) start = start.getTime(); else start = "";
            workspace = {
                "_id": wname,
                "_rev": "2-bd88abf79cf2b7e8b419cd4387c64bef",
                "customer": "",
                "sdate": (new Date).getTime(),
                "name": wname,
                "fdate": undefined,
                "type": "Workspace",
                "children": [
                ],
                "duration": {"start": start, "end": end},
                "scope": scope,
                "description": wdesc
            };
            return(workspace);

        };

        //DATE PICKER        
        $scope.today = function() {
            $scope.dt = new Date();
        };
        $scope.today();

        $scope.clear = function () {
            $scope.dt = null;
        };

        $scope.open = function($event, isStart) {
            $event.preventDefault();
            $event.stopPropagation();

            if(isStart) $scope.openedStart = true; else $scope.openedEnd = true;
        };

        $scope.init();
    }]);
