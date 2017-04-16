// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('modalTagsCtrl',
        ['$scope', '$modalInstance', 'models', 'workspace', 'tagsFact',
        function($scope, $modalInstance, models, workspace, tagsFact ) {
        $scope.models = models;
        $scope.currentTags = [];
        $scope.result = {
            "tags": [],
            "objs": []
        };

        $scope.addTag = function(tag){
            if($scope.currentTags.indexOf(tag.toLowerCase()) < 0){
                $scope.currentTags.push(tag.toLowerCase());
            }
        };

        for(vuln in $scope.models) {
            if($scope.models[vuln].tags != undefined ) {
    		    $scope.models[vuln].tags.forEach(function(tag){
                    if($scope.currentTags.indexOf(tag) < 0){
                        $scope.currentTags.push(tag);
                    }
    		    });
            }
            $scope.result.objs.push($scope.models[vuln]);
        }

        $scope.ok = function(){
            $scope.result.tags = $scope.currentTags;
        	$modalInstance.close($scope.result);
        };

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };
    }]);
