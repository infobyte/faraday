angular.module('faradayApp')
    .controller('modalNewCtrl',
        ['$scope', '$modalInstance','targetFact', 'severities', 'vulns', 'workspace',
        function($scope, $modalInstance,targetFact, severities, vulns, workspace) {
        
        $scope.type = ['Vulnerability','VulnerabilityWeb'];
        $scope.selection = $scope.type[0];
        $scope.severities = severities;
        $scope.vulns = vulns;
        $scope.workspace = workspace;

        var myDate = new Date();
        var myEpoch = myDate.getTime()/1000.0;
        $scope.date = myEpoch;

        var d = {};
        var hosts = targetFact.getTarget($scope.workspace, true);
        hosts.forEach(function(h) {
            h.services = [];  
            d[h._id] = h;
        });
        var services = targetFact.getTarget($scope.workspace, false);
        for(var i = 0; i < services.length; i++){
            var host = [];
            var parent = services[i].hid.split(".")[0];
            host = d[services[i].hid];
            host.services.push(services[i]);
        }
        hosts.push(host);
        $scope.servicesByHost = hosts;

        $scope.ok = function() {
            var res = {};
            var id = $scope.target + "." + CryptoJS.SHA1($scope.name + "." + $scope.desc).toString();
            var sha = CryptoJS.SHA1($scope.name + "." + $scope.desc).toString();

            if($scope.selection == "VulnerabilityWeb") {
                res = {
                    "id":           id,
                    "data":         $scope.data,
                    "desc":         $scope.desc,
                    "meta":         {'create_time': $scope.date},
                    "method":       $scope.method,
                    "name":         $scope.name, 
                    "now":          $scope.date,
                    "oid":          sha,
                    "owned":        false,
                    "owner":        "",
                    "params":       $scope.params,
                    "couch_parent": $scope.target,
                    "path":         $scope.path,
                    "pname":        $scope.pname,
                    "query":        $scope.query,
                    "refs":         [],
                    "request":      $scope.request,
                    "response":     $scope.response,
                    "severity":     $scope.severitySelection,
                    "status":       $scope.selection,
                    "type":         $scope.selection,
                    "web":          true, 
                    "website":      $scope.website
                };
            } else {
                res = {
                    "id":           id,
                    "data":         $scope.data,
                    "desc":         $scope.desc,
                    "meta":         {"create_time": $scope.date},
                    "name":         $scope.name,
                    "now":          $scope.date,
                    "oid":          sha,
                    "owned":        false,
                    "owner":        "",
                    "couch_parent": $scope.target,
                    "refs":         [],
                    "status":       $scope.selection,
                    "severity":     $scope.severitySelection,
                    "type":         $scope.selection,
                    "web":          false
                };
            }

            $modalInstance.close(res);
        };

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };

        $scope.$parent.isopen = ($scope.$parent.default === $scope.item);
 
        $scope.$watch('isopen', function (newvalue, oldvalue, $scope) {
            $scope.$parent.isopen = newvalue;
        });

        $scope.selectedClick = function(id){
            $scope.target = id;
        }
    }]);