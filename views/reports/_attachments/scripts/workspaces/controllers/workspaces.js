angular.module('faradayApp')
    .controller('workspacesCtrl', ['$modal', '$scope', 'workspacesFact',
            function($modal, $scope, workspacesFact) {
        $scope.workspaces = [];
        $scope.wss = [];
        $scope.newworkspace = {};

        $scope.onSuccessGet = function(workspace){
            $scope.workspaces.push(workspace);
        };

        $scope.onSuccessInsert = function(workspace){
            $scope.wss.push(workspace.name); 
            $scope.workspaces.push(workspace); 
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
            console.log($scope.workspaces);
        };


        workspacesFact.list(function(wss) {
            $scope.wss = wss;
            $scope.wss.forEach(function(w){
                workspacesFact.get(w, $scope.onSuccessGet);
            });
        });

        
        $scope.insert = function(workspace){
            workspacesFact.put(workspace, $scope.onSuccessInsert);
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

        $scope.cancel = function(){
            $scope.modal.close();
        };

        $scope.delete = function(){ 
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
