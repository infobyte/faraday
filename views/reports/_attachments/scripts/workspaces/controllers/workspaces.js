angular.module('faradayApp')
    .controller('workspacesCtrl', ['$modal', '$scope', 'workspacesFact',
            function($modal, $scope, workspacesFact) {
        $scope.workspaces = [];
        $scope.wss = [];
        // $scope.newworkspace = {};

        $scope.onSuccessGet = function(workspace){
            $scope.workspaces.push(workspace);
        };

        $scope.onSuccessInsert = function(workspace){
            $scope.wss.push(workspace.name); 
            $scope.workspaces.push(workspace); 
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


        workspacesFact.list(function(wss) {
            $scope.wss = wss;
            $scope.wss.forEach(function(w){
                workspacesFact.get(w, $scope.onSuccessGet);
            });
        });
        var hash_tmp = window.location.hash.split("/")[1];
        switch (hash_tmp){
            case "status":
                $scope.hash = "status";
                break;
            default:
                $scope.hash = "";
        }

        
        $scope.insert = function(workspace){
            delete workspace.selected;
            workspacesFact.put(workspace, $scope.onSuccessInsert);
        };

        $scope.update = function(workspace){
            workspacesFact.update(workspace, $scope.onSuccessEdit);
        };

        $scope.remove = function(workspace_name){
            workspacesFact.delete(workspace_name, $scope.onSuccessDelete);
        };

        // Modals methods
        $scope.new = function(){ 

            $scope.modal = $modal.open({
                templateUrl: 'scripts/workspaces/partials/modal-new.html',
                controller: 'workspacesCtrl',
                scope: $scope,
                size: 'lg'
            });

            $scope.modal.result.then(function(workspace) {
                workspace = $scope.create(workspace.name, workspace.description);
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

        $scope.create = function(wname, wdesc){
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
                "description": wdesc
            };
            return(workspace);

        };
    }]);
