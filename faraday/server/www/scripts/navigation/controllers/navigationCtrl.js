// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('navigationCtrl', [
        '$scope',
        '$http',
        '$route',
        '$routeParams',
        '$cookies',
        '$location',
        '$interval',
        '$uibModal',
        'configSrv',
        'workspacesFact',
        'Notification',
        '$rootScope',
        function ($scope,
                  $http,
                  $route,
                  $routeParams,
                  $cookies,
                  $location,
                  $interval,
                  $uibModal,
                  configSrv,
                  workspacesFact,
                  Notification,
                  $rootScope) {

        $scope.workspace = "";

        if(!$scope.component)
            $scope.component = "";

        if(!$scope.timer)
            $scope.timer;

        var componentsNeedsWS = ["dashboard","status","hosts"];

        $scope.checkNews = function() {
             $http.get('https://portal.faradaysec.com/api/v1/license_check?version=' + configSrv.faraday_version + '&key=white').then(function(response) {
                 try{
                     response.data['news'].forEach(function(element) {

                         var childScope = $scope.$new();
                         childScope.url = element['url'];

                         Notification.info({
                             message: element['description'],
                             title: 'x',
                             scope: childScope,
                             delay: 'ALWAYS',
                             templateUrl: 'scripts/navigation/partials/notification.html'});
                      }, this);
                 }
                 catch(error){
                     console.log("Can't connect to faradaysec.com");
                 }

            }, function() {
                console.log("Can't connect to faradaysec.com");
            });
        };

        configSrv.promise.then(function() {
            $scope.timer = $interval($scope.checkNews, 43200000);
            $scope.checkNews();
        });

        $scope.$on('$destroy', function() {
            $interval.cancel($scope.timer);
        });

        $rootScope.$on('$routeChangeSuccess', function() {
            if(componentsNeedsWS.indexOf($location.path().split("/")[1]) != -1 && $routeParams.wsId !== undefined) {
                workspacesFact.list().then(function(wss) {
                    $scope.wss = wss;
                });

                workspacesFact.exists($routeParams.wsId).then(function(response){
                       // ok! workspace was found.
                }, function(response){
                    if(response.status === 404) {
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
            var noNav = ["", "home", "login", "index"];
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

        $scope.$on('handleChangeWSBroadcast', function () {
            $scope.workspace = workspacesFact.workspace;
        });

        $scope.loadCurrentWorkspace();

        // if(navigator.userAgent.toLowerCase().indexOf('iceweasel') > -1) {
        //      $scope.isIceweasel = "Your browser is not supported, please use Firefox or Chrome";
        // }
	}]);
