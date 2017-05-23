// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('commercialCtrl', 
        ['$scope', '$location',
        function($scope, $location) {
        	if ($location.path().split("/")[1] === "executive") {
        		$scope.header = "executive report";
        	} else if ($location.path().split("/")[1] === "comparison") {
        		$scope.header = "workspace comparison";
        	} else if ($location.path().split("/")[1] === "communication") {
        		$scope.header = "chat";
            } else if ($location.path().split("/")[1] === "data_analysis") {
                $scope.header = "data analysis";
        	} else {
        		$scope.header = $location.path().split("/")[1];
        	}
        }]);