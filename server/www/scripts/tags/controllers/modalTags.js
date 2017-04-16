// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('modalTagsCtrl',
        ['$scope', '$modalInstance', 'vulns', 'workspace', 'tagsFact',
        function($scope, $modalInstance, vulns, workspace, tagsFact ) {
        $scope.vulns = vulns;      
        $scope.tags = tagsFact.get(workspace);
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

        for(vuln in $scope.vulns) {
            if($scope.vulns[vuln].tags != undefined ) {
    		    $scope.vulns[vuln].tags.forEach(function(tag){
                    if($scope.currentTags.indexOf(tag) < 0){
                        $scope.currentTags.push(tag);
                    }
    		    });
            }
            $scope.result.objs.push($scope.vulns[vuln]);
        }

        $scope.ok = function(){
            $scope.result.tags = $scope.currentTags;
        	$modalInstance.close($scope.result);
        };

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };
    }]);
