// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('commercialCtrl', 
        ['$scope', '$location',
        function($scope, $location) {
        	$scope.header = $location.path().split("/")[1];
        }]);