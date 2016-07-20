// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('summarizedCtrlHostsModal',
        ['$scope', '$modalInstance', 'dashboardSrv', 'workspace', 'srv_name',
        function($scope, $modalInstance, dashboardSrv, workspace, srv_name) {

            $scope.sortField = 'name';
            $scope.sortReverse = false;
            $scope.clipText = "Copy to Clipboard";

            // toggles sort field and order
            $scope.toggleSort = function(field) {
                $scope.toggleSortField(field);
                $scope.toggleReverse();
            };

            // toggles column sort field
            $scope.toggleSortField = function(field) {
                $scope.sortField = field;
            };

            // toggle column sort order
            $scope.toggleReverse = function() {
                $scope.sortReverse = !$scope.sortReverse;
            }

            dashboardSrv.getHostsByServicesName(workspace, srv_name).then(function(hosts){
                $scope.name = srv_name;
                $scope.hosts = hosts;
                $scope.clip = "";
                $scope.hosts.forEach(function(h){
                    $scope.clip += h.name + "\n";
                });
            });

            $scope.messageCopied = function(){
                $scope.clipText = "Copied!";
            }

            $scope.ok = function(){
                $modalInstance.close();
            }
    }]);
