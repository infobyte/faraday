// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('indexCtrl', 
        ['$scope', '$http', 'BASEURL',
        function($scope, $http, BASEURL) {

			$http.get('/reports/_design/reports/scripts/config/config.json').then(function(conf){
				$scope.version = conf.data.ver;
			});

        }]);