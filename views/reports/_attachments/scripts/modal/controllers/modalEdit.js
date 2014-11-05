angular.module('faradayApp')
    .controller('modalEditCtrl', function($scope, $modalInstance, severities, vulns) {
        $scope.severities = severities;
        $scope.vulns = vulns;
        $scope.web = false;

        $scope.vulns.forEach(function(v) {
            if(v.selected && v.type === "VulnerabilityWeb") $scope.web = true; 
        });

        $scope.isChecked = function(i) {
            return i.selected;
        };

        $scope.ok = function() {
            var res = {};

            if($scope.web) { 
                res = {
                    "data":     $scope.data,
                    "desc":     $scope.desc,
                    "method":   $scope.method,
                    "name":     $scope.name, 
                    "params":   $scope.params,
                    "path":     $scope.path,
                    "pname":    $scope.pname,
                    "query":    $scope.query,
                    "request":  $scope.request,
                    "response": $scope.response,
                    "severity": $scope.severitySelection, 
                    "vulns":    $scope.vulns, 
                    "website":  $scope.website
                };    
            } else {
                res = {
                    "data":     $scope.data,
                    "desc":     $scope.desc,
                    "name":     $scope.name, 
                    "severity": $scope.severitySelection, 
                    "vulns":    $scope.vulns 
                };
            }

            $modalInstance.close(res);
        };

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };

    });
