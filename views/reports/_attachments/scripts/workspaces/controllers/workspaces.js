angular.module('faradayApp')
    .controller('workspacesCtrl', ['$scope', 'workspacesFact',
            function($scope, workspacesFact) {
        workspacesFact.get(function(wss) {
            $scope.wss = wss;
        });
        
        $scope.insert = function(workspace){
            dump('Existe el workspace?' + workspacesFact.exists(workspace.name));
            if(workspacesFact.exists(workspace.name) == false){
                workspacesFact.put(workspace);
                $scope.wss.push(workspace.name);
            };
        };

        $scope.remove = function(workspace_name){
            workspacesFact.delete(workspace_name);
            delete $scope.wss[$scope.wss.indexOf(workspace_name)]; 
        };
    }]);
