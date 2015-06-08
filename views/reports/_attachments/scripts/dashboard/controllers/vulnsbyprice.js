// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('vulnsbypriceCtrl', 
        ['$scope', '$route', '$routeParams', 'dashboardSrv',
        function($scope, $route, $routeParams, dashboardSrv) {
            $scope.data = [
                {
                    color: '#932ebe',
                    count: 345,
                    name: 'critical'
                }, {
                    color: '#DF3936',
                    count: 111,
                    name: 'high'
                }, {
                    color: '#DFBF35',
                    count: 300,
                    name: 'med'
                }, {
                    color: '#A1CE31',
                    count: 573,
                    name: 'low'
                }
            ];
        }]);
