angular.module('faradayApp')
    .controller('workspacesCtrl', ['$scope', 'workspacesFact',
            function($scope, workspacesFact) {
        $scope.workspaces = [];
        $scope.wss = [];

        $scope.onSuccessGet = function(workspace){
            $scope.workspaces.push(workspace);
        };

        workspacesFact.list(function(wss) {
            $scope.wss = wss;
            $scope.wss.forEach(function(w){
                console.log('GET' + w);
                workspacesFact.get(w, $scope.onSuccessGet);
            });
        });

        
        $scope.insert = function(workspace){
            workspacesFact.put(workspace, $scope.onSuccessInsert);
        };

        $scope.remove = function(workspace_name){
            workspacesFact.delete(workspace_name);
            delete $scope.wss[$scope.wss.indexOf(workspace_name)]; 
        };

        $scope.onSuccessInsert = function(name){
            $scope.wss.push(name); 
        };
    }]);
