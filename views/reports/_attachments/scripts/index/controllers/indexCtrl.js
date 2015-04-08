angular.module('faradayApp')
    .controller('indexCtrl', 
        ['$scope', '$http', 'BASEURL',
        function($scope, $http, BASEURL) {
        	$scope.isIceweasel = undefined;
        	if(navigator.userAgent.toLowerCase().indexOf('iceweasel') > -1) {
        		$scope.isIceweasel = true;
			}

        }]);