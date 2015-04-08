angular.module('faradayApp')
    .controller('indexCtrl', 
        ['$scope', '$http', 'BASEURL',
        function($scope, $http, BASEURL) {

			$http.get('/reports/_design/reports/scripts/config/config.json').then(function(conf){
				$scope.version = conf.data.ver;
			});

        }]);