// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('indexCtrl', 
        ['$scope', 'indexFact',
        function($scope, indexFact) {
        	indexFact.getConf().then(function(conf) {
        		$scope.version = conf.data.ver;
			    $scope.osint = conf.data.osint;
        	});

        }]);
