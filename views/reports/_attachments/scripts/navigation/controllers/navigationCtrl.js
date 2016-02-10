// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('navigationCtrl', ['$scope', '$http', '$route', '$routeParams', '$cookies', '$location', '$interval', 'configSrv', 'workspacesFact',
        function($scope, $http, $route, $routeParams, $cookies, $location, $interval, configSrv, workspacesFact) {

        $scope.workspace = "";
        $scope.component = "";
        var componentsNeedsWS = ["dashboard","status","hosts"];

        $scope.checkCwe = function() {
            $http.get("https://www.faradaysec.com/scripts/updatedb.php?version=" + configSrv.faraday_version).then(function() {
            }, function() {
                console.log("CWE database couldn't be updated");
            });
        };

        workspacesFact.list().then(function(wss) {
            $scope.wss = wss;
        });

        configSrv.promise.then(function() {
            var timer = $interval($scope.checkCwe, 43200000);
            $scope.checkCwe();
        });

        $scope.$on('$destroy', function() {
            $interval.cancel(timer);
        });

        $scope.$on('$routeChangeSuccess', function() {
            if(componentsNeedsWS.indexOf($location.path().split("/")[1]) != -1 && $routeParams.wsId !== undefined) {
                workspacesFact.exists($routeParams.wsId).then(function(resp){
                    console.log(resp);
                    if(resp === true) {
                        $scope.workspaceExists = true;
                    } else {
                        $scope.workspaceExists = false;
                    }
                });
            } else {
                $scope.workspaceExists = null;
            }
            $scope.updateWorkspace();
            $scope.updateComponent();
        });

        $scope.updateWorkspace = function() {
            if($routeParams.wsId != undefined) {
                $scope.workspace = $routeParams.wsId;
                $cookies.put('currentUrl', $location.path());
            }
        };

        $scope.updateComponent = function() {
            if($location.path() == "") {
                $scope.component = "home";
            } else {
                $scope.component = $location.path().split("/")[1];
            }
            $cookies.put('currentComponent', $scope.component);
        };

        $scope.showNavigation = function() {
            var noNav = ["home", "index", ""];
            return noNav.indexOf($scope.component) < 0;
        };

        $scope.loadCurrentWorkspace = function() {
            var pos = -1;

            if($cookies.get('currentUrl') != undefined) {
                pos = $cookies.get('currentUrl').indexOf('ws/');
            }

            if($routeParams.wsId != undefined) {
                $scope.workspace = $routeParams.wsId;
            } else if(pos >= 0) {
                $scope.workspace = $cookies.get('currentUrl').slice(pos+3);
            }
        };

        $scope.loadCurrentWorkspace();

        // if(navigator.userAgent.toLowerCase().indexOf('iceweasel') > -1) {
        //      $scope.isIceweasel = "Your browser is not supported, please use Firefox or Chrome";
        // }
	}]);
