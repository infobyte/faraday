angular.module('faradayApp')
    .controller('modalNewCtrl',
        ['$scope', '$modalInstance','targetFact', 'severities', 'workspace',
        function($scope, $modalInstance,targetFact, severities, workspace) {
        
        $scope.type = ['Vulnerability','VulnerabilityWeb'];
        $scope.selection = $scope.type[0];
        $scope.severities = severities;
        $scope.workspace = workspace;
        $scope.target_selected = null;

        var d = {};
        var hosts = targetFact.getTarget($scope.workspace, true);
        hosts.forEach(function(h) {
            h.services = [];  
            d[h._id] = h;
        });
        var services = targetFact.getTarget($scope.workspace, false);
        for(var i = 0; i < services.length; i++){
            var host = [];
            services[i].selected = false;
            host = d[services[i].hid];
            host.services.push(services[i]);
        }
        $scope.hosts_with_services = hosts;

        $scope.ok = function() {
            var res = {};
            var id = $scope.target_selected._id + "." + CryptoJS.SHA1($scope.name + "." + $scope.desc).toString();
            var sha = CryptoJS.SHA1($scope.name + "." + $scope.desc).toString();

            var myDate = new Date();
            var myEpoch = myDate.getTime()/1000.0;

            if($scope.selection == "VulnerabilityWeb") {
                res = {
                    "id":           id,
                    "data":         $scope.data,
                    "desc":         $scope.desc,
                    "meta":         {'create_time': myEpoch},
                    "method":       $scope.method,
                    "name":         $scope.name, 
                    "oid":          sha,
                    "owned":        false,
                    "owner":        "",
                    "params":       $scope.params,
                    "couch_parent": $scope.target_selected._id,
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
                    "meta":         {"create_time": myEpoch},
                    "name":         $scope.name,
                    "oid":          sha,
                    "owned":        false,
                    "owner":        "",
                    "couch_parent": $scope.target_selected._id,
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

        $scope.selected = function(i, j){
            if($scope.target_selected){
                $scope.target_selected.selected = false;
            }
            if(j != null){
                $scope.target_selected = $scope.hosts_with_services[i].services[j];
            }else{
                $scope.target_selected = $scope.hosts_with_services[i];
            }
            $scope.target_selected.selected = true;
        }
    }]);