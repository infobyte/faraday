// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('customFieldsCtrl',
        ['$scope', 'customFieldFact', '$uibModal', 'commonsFact', function ($scope, customFieldFact, $uibModal, commonsFact) {

            $scope.customFields = [];
            $scope.selected_cf = {
                field_display_name: "",
                field_name: "",
                field_metadata: [],
                field_order: null,
                field_type: null,
                table_name: 'vulnerability'
            };
            $scope.isEditable = false;
            $scope.data = {
                newOption : ''
            };

            $scope.models = {
                selected: null
            };

            var init = function () {
                loadCustomFields();
            };

            var compareFunction = function (cf1, cf2) {
                return cf1.field_order - cf2.field_order;
            };


            var errorHandler = function (error) {
                if (typeof(error) === "object") {
                    if (error.status=== 409)
                        commonsFact.showMessage(error.data.object.field_display_name + " has the same field name: '" +
                            error.data.object.field_name + "'");
                }
                else if (typeof(error) === "string")
                    commonsFact.showMessage(error);
                else
                    commonsFact.showMessage('Something bad happened');
            };


            $scope.insertCallback = function () {
                var ids = [];
                for (var i = 0; i < $scope.customFields.length; i++) {
                    if (ids.indexOf($scope.customFields[i].id) === -1) {
                        $scope.customFields[i].field_order = i;
                        customFieldFact.updateCustomField($scope.customFields[i]).then(function(){
                            if (i < $scope.customFields.length ) {
                                ids.push($scope.customFields[i].id);
                            }

                            $scope.clearSelection();
                        });
                    }
                }
            };


            var loadCustomFields = function () {
                customFieldFact.getCustomFields().then(
                    function (response) {
                        $scope.customFields = response.data.sort(compareFunction);
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

            $scope.normalizeName = function () {
                if ($scope.selected_cf.field_name !== null) {
                    $scope.selected_cf.field_name = $scope.selected_cf.field_name.toLowerCase().replace(' ', '_');
                }
            };

            $scope.addOption = function(){
                if ( $scope.data.newOption !== ''){
                    $scope.selected_cf.field_metadata.push($scope.data.newOption);
                    $scope.data.newOption = '';
                }
            };

            $scope.createCustomCustomField = function () {
                $scope.selected_cf.table_name = 'vulnerability';

                if ($scope.selected_cf.field_order === null)
                    $scope.selected_cf.field_order = getMaxOrder() + 1;

                if(!$scope.selected_cf.field_metadata || $scope.selected_cf.field_metadata.length === 0){
                    $scope.selected_cf.field_metadata = null;
                }

                if ($scope.selected_cf.field_type === 'choice'){
                    $scope.selected_cf.field_metadata = JSON.stringify($scope.selected_cf.field_metadata)
                }
                customFieldFact.createCustomField($scope.selected_cf).then(
                    function (response) {
                        $scope.customFields.push(response.data);
                        $scope.clearSelection();
                    }, errorHandler);
            };


            $scope.updateCustomCustomField = function () {
                 if(!$scope.selected_cf.field_metadata || $scope.selected_cf.field_metadata.length === 0){
                    $scope.selected_cf.field_metadata = null;
                }

                if ($scope.selected_cf.field_type === 'choice'){
                    $scope.selected_cf.field_metadata = JSON.stringify($scope.selected_cf.field_metadata)
                }

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
                if (cf.field_type === 'choice'){
                    $scope.selected_cf.field_metadata  = cf.field_metadata === null ? [] : JSON.parse(cf.field_metadata);
                }
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
                    case "choice":
                        color = '#be2743';
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
                    field_metadata: [],
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
