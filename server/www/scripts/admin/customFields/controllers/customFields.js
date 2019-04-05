// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('customFieldsCtrl',
        ['$scope', 'customFieldFact', '$uibModal', function ($scope, customFieldFact, $uibModal) {

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
                var ids = [];
                for (var i = 0; i < $scope.customFields.length; i++) {
                    if (ids.indexOf($scope.customFields[i].id) === -1) {
                        $scope.customFields[i].field_order = i;
                        customFieldFact.updateCustomField($scope.customFields[i]);
                        ids.push($scope.customFields[i].id);
                    }
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
                if ($scope.customFields.length === 0) {
                    return -1;
                }

                var orders = [];
                $scope.customFields.forEach(function (customField) {
                    orders.push(customField.field_order);
                });

                return Math.max.apply(null, orders) || 0;
            };

            $scope.normalizeDisplayName = function () {
                if ($scope.selected_cf.field_name !== null) {
                    $scope.selected_cf.field_name = $scope.selected_cf.field_name.toLowerCase().replace(' ', '_');
                }
            };

            $scope.createCustomCustomField = function () {
                if ($scope.selected_cf.field_order === null)
                    $scope.selected_cf.field_order = getMaxOrder() + 1;

                customFieldFact.createCustomField($scope.selected_cf).then(
                    function (response) {
                        $scope.customFields.push(response.data);
                        $scope.clearSelection();
                    });
            };


            $scope.updateCustomCustomField = function () {
                customFieldFact.updateCustomField($scope.selected_cf).then(
                    function (response) {
                        if (response) {
                            $scope.clearSelection();
                            loadCustomFields();
                        }
                    });
            };

            $scope._delete = function (customField) {
                var modal = $uibModal.open({
                    templateUrl: 'scripts/commons/partials/modalDelete.html',
                    controller: 'commonsModalDelete',
                    size: 'lg',
                    resolve: {
                        msg: function () {
                            var msg = "A custom field will be deleted.";
                            msg += " This action cannot be undone. Are you sure you want to proceed?";
                            return msg;
                        }
                    }
                });

                modal.result.then(function () {
                    $scope.deleteCustomCustomField(customField.id);
                });
            };


            $scope.deleteCustomCustomField = function (customFieldId) {
                customFieldFact.deleteCustomField(customFieldId).then(
                    function (response) {
                        removeCustomField(customFieldId);
                    });
            };

            var removeCustomField = function (customFieldId) {
                for (var i = 0; i < $scope.customFields.length; i++) {
                    if ($scope.customFields[i].id === customFieldId) {
                        $scope.customFields.splice(i, 1);
                        break;
                    }
                }
            };

            $scope.setCustomField = function (cf) {
                $scope.selected_cf = angular.copy(cf);
                $scope.isEditable = true;
                $scope.changeType(cf.field_type);

                $scope.showSidePanel();
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

            $scope.showSidePanel = function () {
                angular.element('#slide').addClass('show-slide');
                angular.element('#main-panel').addClass('slice-main-panel');
            };

            $scope.hideSidePanel = function () {
                angular.element('#slide').removeClass('show-slide');
                angular.element('#main-panel').removeClass('slice-main-panel');
                $scope.clearSelection();
            };

            $scope.new = function () {
                $scope.clearSelection();
                $scope.showSidePanel();
            };

            init();
        }]);
