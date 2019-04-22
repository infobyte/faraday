// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('adminCtrl',
        ['$scope', '$location', '$routeParams', function($scope, $location, $routeParams) {

        var init  = function () {
            if ($routeParams.item !== undefined){
                 $scope.on = $routeParams.item;
            }else{
                $scope.on = "custom_fields";
            }
        };

        $scope.setItemPanel = function (menuItem) {
            $scope.on = menuItem;
            var url = "/admin/" + menuItem;
            $location.path(url);
        };

	    init();
    }]);
