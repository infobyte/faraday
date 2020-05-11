// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('summarizedCtrlHostsModal',
        ['$scope', '$modalInstance', 'dashboardSrv', 'workspace', 'srv_name', 'osint',
        function($scope, $modalInstance, dashboardSrv, workspace, srv_name, osint) {

            $scope.osint = osint;
            $scope.sortField = 'name';
            $scope.sortReverse = false;
            $scope.clipText = "Copy names to Clipboard";
            $scope.workspace = workspace

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
                $scope.hosts.forEach(function(h, index, array){
                    let port = $scope.getPort(h.service_summaries);
                    $scope.hosts[index].port = port;
                    if(index === array.length -1)
                        $scope.clip += h.name + ":" + port;
                    else
                        $scope.clip += h.name + ":" + port + " - ";
                });
            });

            $scope.messageCopied = function(){
                $scope.clipText = "Copied!";
            }

            $scope.ok = function(){
                $modalInstance.close();
            }

            $scope.getPort = function(summaries){

                let port = "";

                summaries.forEach(function(summarie){
                    let summarieSplited = summarie.split(" ");

                    if(summarieSplited[1] == $scope.name){
                        let index = summarieSplited[0].indexOf("/");

                        port = summarieSplited[0].substring(1, index);
                    }
                })

                return port;
            }
    }]);
