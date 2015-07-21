// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('workspaceProgressCtrl', 
        ['$scope', '$route', '$routeParams', 'workspacesFact',
        function($scope, $route, $routeParams, workspacesFact) {
            $scope.duration;
            $scope.end;
            $scope.start;
            $scope.progress;
            $scope.workspace;

            init = function() {
                $scope.workspace = $routeParams.wsId;
                workspacesFact.getDuration($scope.workspace).then(function(duration) {
                    $scope.duration = duration;
                    $scope.progress = $scope.calculateProgress($scope.duration);
                    $scope.start = $scope.duration.start;
                    $scope.end = $scope.duration.end;
                });
            };

            $scope.calculateProgress = function(duration) {
                var partial = 0,
                progress = 0,
                today = new Date(),
                total = 0;

                if(duration.start == "" || duration.end == "") {
                    progress = null;
                } else {
                    today = today.getTime();
                    partial = today - duration.start;
                    total = duration.end - duration.start;

                    if(today > duration.end) {
                        progress = 100;
                    } else if(duration.start < today && today <= duration.end && total > 0) {
                        progress = Math.round(partial * 100 / total);
                    }
                }

                return progress;
            };

            init();
        }]);
