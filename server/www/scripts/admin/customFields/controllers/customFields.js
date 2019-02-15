// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('customFieldsCtrl',
        ['$scope', 'customFieldFact', function ($scope, customFieldFact) {

            $scope.customFields = [];
            $scope.selected_cf = {
                field_display_name: "",
                field_name: "",
                field_order: null,
                field_type: null
            };
            $scope.isEditable = false;


            $scope.models = {
                selected: null
            };

            var init = function () {
                loadCustomFields();
            };


            $scope.insertCallback = function () {
                for (var i = 0; i < $scope.customFields.length; i++) {
                    $scope.customFields[i].field_order = i;
                }

                $scope.clearSelection();
                console.log($scope.customFields);
            };


            var loadCustomFields = function () {
                customFieldFact.getCustomFields().then(
                    function (response) {
                        $scope.customFields = response.data;
                        console.log($scope.customFields);
                    });
            };

            var getMaxOrder = function () {
                var orders = [];
                $scope.customFields.forEach(function (customField) {
                    orders.push(customField.field_order);
                });

                return Math.max.apply(null, orders) || 0;
            };

            $scope.createCustomCustomField = function () {
                if ($scope.selected_cf.field_order === undefined)
                    $scope.selected_cf.field_order = getMaxOrder() + 1;

                customFieldFact.createCustomField($scope.selected_cf).then(
                    function (response) {
                        $scope.customFields.push(response.data);
                    });
            };


            $scope.setCustomField = function (cf) {
                $scope.selected_cf = angular.copy(cf);
                $scope.isEditable = true;
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
                $scope.selected_cf = {
                    field_display_name: "",
                    field_name: "",
                    field_order: null,
                    field_type: null
                };
                $scope.updateBtnTypeColor(null);
                $scope.isEditable = false;

            };

            init();
        }]);
