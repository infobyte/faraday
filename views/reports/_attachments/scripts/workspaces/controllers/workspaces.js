// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('workspacesCtrl', ['$modal', '$scope', '$q', 'workspacesFact', 'dashboardSrv',
            function($modal, $scope, $q, workspacesFact, dashboardSrv) {
        $scope.workspaces = [];
        $scope.wss = [];
        $scope.objects = {};
        // $scope.newworkspace = {};

        $scope.onSuccessGet = function(workspace){
            if(workspace.sdate.toString().indexOf(".") != -1) workspace.sdate = workspace.sdate * 1000;
            $scope.workspaces.push(workspace);
        };

        $scope.onSuccessInsert = function(workspace){
            workspace.sdate = workspace.sdate;
            $scope.wss.push(workspace.name); 
            $scope.workspaces.push(workspace); 
        };
        
        $scope.onFailInsert = function(error){
            var modal = $modal.open({
                templateUrl: 'scripts/partials/modal-ko.html',
                controller: 'modalKoCtrl',
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
                    $scope.workspaces[i].description = workspace.description;
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

        // todo: refactor the following code
        workspacesFact.list().then(function(wss) {
            $scope.wss = wss;
            var objects = {};
            $scope.wss.forEach(function(ws){
                workspacesFact.get(ws, $scope.onSuccessGet);
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

        var hash_tmp = window.location.hash.split("/")[1];
        switch (hash_tmp){
            case "status":
                $scope.hash = "status";
                break;
            case "dashboard":
                $scope.hash = "dashboard";
                break;
            default:
                $scope.hash = "";
        }

        
        $scope.insert = function(workspace){
            delete workspace.selected;
            workspacesFact.put(workspace).then(function(resp){
                $scope.onSuccessInsert(workspace)
            },
            $scope.onFailInsert);
        };

        $scope.update = function(workspace){
            workspacesFact.update(workspace, $scope.onSuccessEdit);
        };

        $scope.remove = function(workspace_name){
            workspacesFact.delete(workspace_name, $scope.onSuccessDelete);
        };

        // Modals methods
        $scope.new = function(){ 
            $scope.newworkspace = {};

            $scope.modal = $modal.open({
                templateUrl: 'scripts/workspaces/partials/modal-new.html',
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
                    } 
                });
                $scope.modal = $modal.open({
                    templateUrl: 'scripts/workspaces/partials/modal-edit.html',
                    controller: 'workspacesCtrl',
                    scope: $scope,
                    size: 'lg'
                });

                $scope.modal.result.then(function(workspace) {
                    $scope.update(workspace); 
                });
            } else {
                var modal = $modal.open({
                    templateUrl: 'scripts/partials/modal-ko.html',
                    controller: 'modalKoCtrl',
                    resolve: {
                        msg: function() {
                            return 'No workspaces were selected to edit';
                        }
                    }
                });
            }

        };

        $scope.okEdit = function(){
            $scope.modal.close($scope.newworkspace);
        };


        $scope.cancel = function(){
            $scope.modal.close();
        };

        $scope.delete = function(){ 
            var selected = false;

            $scope.workspaces.forEach(function(w) {
                if(w.selected) {
                    selected = true;
                    return;
                }
            });

            if(selected){
                $scope.modal = $modal.open({
                    templateUrl: 'scripts/workspaces/partials/modal-delete.html',
                    controller: 'workspacesCtrl',
                    scope: $scope,
                    size: 'lg'
                });

                $scope.modal.result.then(function() {
                    $scope.workspaces.forEach(function(w){
                        if(w.selected == true)
                            $scope.remove(w.name); 
                    });
                });
            } else {
                var modal = $modal.open({
                    templateUrl: 'scripts/partials/modal-ko.html',
                    controller: 'modalKoCtrl',
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
            if(end) end = end.getTime();
            if(start) start = start.getTime();
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

        // Disable weekend selection
        $scope.disabled = function(date, mode) {
            return ( mode === 'day' && ( date.getDay() === 0 || date.getDay() === 6 ) );
        };

        $scope.minDate = new Date();

        $scope.open = function($event, isStart) {
            $event.preventDefault();
            $event.stopPropagation();

            if(isStart) $scope.openedStart = true; else $scope.openedEnd = true;
        };

        $scope.dateOptions = {
            formatYear: 'yy',
            startingDay: 1
        };

    }]);
