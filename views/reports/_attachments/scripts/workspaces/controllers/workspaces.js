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
            };

            $scope.wss = remove($scope.wss, workspace_name); 

            delete $scope.workspaces[workspace]; 
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

        $scope.new = function(){ 
            $scope.modal = $modal.open({
                templateUrl: 'scripts/workspaces/partials/modal-new.html',
                controller: 'workspacesCtrl',
                scope: $scope,
                size: 'lg'
            });

            // modal.then = 
            $scope.modal.result.then(function(workspace) {
                workspace = $scope.create(workspace.name, workspace.description);
                $scope.insert(workspace); 
            });

        };

        // This is in the modal context only
        $scope.okNew = function(){
            $scope.modal.close($scope.newworkspace);
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
