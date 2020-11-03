// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('vulndDbModalEdit',
                ['$scope', '$modalInstance', 'VulnModel', 'model', 'EXPLOITATIONS', 'EASEOFRESOLUTION', 'customFields',
                 function($scope, $modalInstance, VulnModel, model, EXPLOITATIONS, EASEOFRESOLUTION, customFields) {

        $scope.data;
        $scope.openedStart;
        $scope.openedEnd;
        var EXCLUDED_TOKENS = [""];

        var init = function() {
            $scope.exploitations = EXPLOITATIONS;
            $scope.easeofresolution = EASEOFRESOLUTION;
            $scope.data = new VulnModel;
            $scope.data.set(model);
            $scope.impact =  {
                accountability: false,
                availability: false,
                confidentiality: false,
                integrity: false
            }
            for (var [key, value] of Object.entries(angular.copy($scope.data.impact))) {
                $scope.impact[key] = value
            }
            $scope.policyviolations = clearList(angular.copy($scope.data.policyviolations), EXCLUDED_TOKENS);
            $scope.references = clearList(angular.copy($scope.data.refs), EXCLUDED_TOKENS);
            $scope.new_policyviolation = "";
            $scope.new_reference = "";
            $scope.customFields = customFields;

            for (var key in $scope.data.customfields) {
                $scope.customFields.forEach(function(cf){
                    if(cf.field_name == key)
                        cf.value = $scope.data.customfields[key];
                })
            }
        };

        $scope.ok = function() {
            $scope.data.impact = angular.copy($scope.impact);
            $scope.data.policyviolations = angular.copy($scope.policyviolations);
            $scope.data.refs = angular.copy($scope.references);
            $scope.data.references = $scope.data.refs.join(',');
            for (const fieldName in $scope.data.customfields) {
                $scope.customFields.forEach(function(cf){
                    if(cf.field_name === fieldName){
                        cf.value = $scope.data.customfields[fieldName];
                    }
                })
            }

            $modalInstance.close($scope.data);
        };

        $scope.open = function($event, isStart) {
            $event.preventDefault();
            $event.stopPropagation();

            if(isStart) $scope.openedStart = true; else $scope.openedEnd = true;
        };

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };

        $scope.toggleImpact = function(key) {
            $scope.impact[key] = !$scope.impact[key];
        };

        $scope.newPolicyViolation = function() {
            if ($scope.new_policyviolation !== "") {
                // we need to check if the policy violation already exists
                if ($scope.policyviolations.filter(function(policyviolation) {return policyviolation === $scope.new_policyviolation}).length === 0) {
                    $scope.policyviolations.push($scope.new_policyviolation);
                    $scope.new_policyviolation = "";
                }
            }
        };

         $scope.newReference = function() {
            if ($scope.new_reference !== "") {
                // we need to check if the reference already exists
                if ($scope.references.filter(function(reference) {return reference === $scope.new_reference}).length === 0) {
                    $scope.references.push($scope.new_reference);
                    $scope.new_reference = "";
                }
            }
        };

         var clearList = function (list, excludedTokens) {
           for (var i = 0; i< list.length ; i++){
               if (excludedTokens.indexOf(list[i]) > -1){
                   list.splice(i, 1);
               }
           }
           return list;
         };

        init();
    }]);
