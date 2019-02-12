// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('customFieldsCtrl',
        ['$scope', 'ServerAPI', function($scope, ServerAPI) {

        $scope.customFields = [];
        $scope.selected_cf = {};
        var init  = function () {
            loadCustomFields();
        };


        var loadCustomFields = function () {
            ServerAPI.getCustomFields().then(
                function(response){
                    $scope.customFields = response.data;
                });
        };


        $scope.setCustomField = function (cf) {
            $scope.selected_cf = angular.copy(cf);
            $scope.changeType(cf.field_type);
        };

        $scope.updateBtnTypeColor = function (type) {
            var color = undefined;
            switch (type) {
                case "str":
                    color = '#2e97bd';
                    break;
                case "list":
                    color = '#a1ce31';
                    break;
                case "int":
                    color = '#932ebe';
                    break;
                default:
                    color = '#AAAAAA';
                    break;
            }

            angular.element('#btn-chg-type').css('background-color', color);
            angular.element('#caret-chg-type').css('background-color', color);
        };

        $scope.changeType = function (type) {
            $scope.selected_cf.field_type = type;
            $scope.updateBtnTypeColor(type);
        };

        $scope.clearSelection = function () {
            $scope.selected_cf = undefined;
            $scope.updateBtnTypeColor(null);

        };

	    init();
    }]);
