// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('customFieldsCtrl',
        ['$scope', 'ServerAPI', function($scope, ServerAPI) {

        $scope.customFields = [];
        var init  = function () {
            loadCustomFields();
        };


        var loadCustomFields = function () {
            ServerAPI.getCustomFields().then(
                function(response){
                    $scope.customFields = response.data;
                });
        };

	    init();
    }]);
