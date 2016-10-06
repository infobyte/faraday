// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('navigationCtrl', ['$scope', '$http', '$route', '$routeParams', '$cookies', '$location', '$interval', '$uibModal', 'configSrv', 'workspacesFact', 'Notification',
        function($scope, $http, $route, $routeParams, $cookies, $location, $interval, $uibModal, configSrv, workspacesFact, Notification) {

        $scope.workspace = "";
        $scope.component = "";
        var componentsNeedsWS = ["dashboard","status","hosts"];

        $scope.checkNews = function() {
             $http.get("https://www.faradaysec.com/scripts/updatedb.php?version=" + configSrv.faraday_version).then(function(response) {
                response.data['news'].forEach(function(element) {
                    Notification.info({message: '<a href="' + element['url']  + '">' + element['description']  + '</a>', title: 'Faraday News', delay: 'NO'});
                }, this);
                
            }, function() {
                console.log("Can't connect to faradaysec.com");
            });
        };

        configSrv.promise.then(function() {
            var timer = $interval($scope.checkNews, 43200000);
            $scope.checkNews();
        });

        $scope.$on('$destroy', function() {
            $interval.cancel(timer);
        });

        $scope.$on('$routeChangeSuccess', function() {
            if(componentsNeedsWS.indexOf($location.path().split("/")[1]) != -1 && $routeParams.wsId !== undefined) {
                workspacesFact.list().then(function(wss) {
                    $scope.wss = wss;
                });

                workspacesFact.exists($routeParams.wsId).then(function(resp){
                    if(resp !== true) {
                        $scope.modalWsNoExist();
                    }
                });
            }
            $scope.updateWorkspace();
            $scope.updateComponent();
        });

        $scope.modalWsNoExist = function() {
            $scope.modalInstance = $uibModal.open({
                templateUrl: 'scripts/navigation/partials/wsNo-exist.html',
                scope: $scope,
                backdrop: 'static',
                keyboard: false
            });
        };

        $scope.cancel = function() {
            $scope.modalInstance.dismiss('cancel');
        };

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