angular.module('faradayApp')
    .controller('modalNewCtrl',
        ['$scope', '$modalInstance', '$upload', 'targetFact', 'commonsFact', 'severities', 'workspace',
        function($scope, $modalInstance, $upload, targetFact, commons, severities, workspace) {
        
        $scope.typeOptions = [
            {name:'Vulnerability', value:'Vulnerability'},
            {name:'VulnerabilityWeb',value:'VulnerabilityWeb'}
        ];

        $scope.vuln_type = $scope.typeOptions[0].value;
        $scope.severities = severities;
        $scope.workspace = workspace;
        $scope.target_selected = null;
        $scope.not_target_selected = false;
        $scope.incompatible_vulnWeb = false;
        $scope.evidence = {};
        $scope.icons = {};

        var name_selected,
        host_selected,
        services = targetFact.getTarget($scope.workspace, false),
        d = {},
        hosts = targetFact.getTarget($scope.workspace, true);

        hosts.forEach(function(h) {
            h.services = [];  
            d[h._id] = h;
        });
        $scope.hosts_with_services = hosts;

        for(var i = 0; i < services.length; i++){
            var host = [];
            services[i].selected = false;
            host = d[services[i].hid];
            host.services.push(services[i]);
        }

        $scope.selectedFiles = function(files, e) {
            files.forEach(function(file) {
                if(!$scope.evidence.hasOwnProperty(file)) $scope.evidence[file.name] = file;
            });
            $scope.icons = commons.loadIcons($scope.evidence); 
        }

        $scope.removeEvidence = function(name) {
            delete $scope.evidence[name];
            delete $scope.icons[name];
        }

        $scope.ok = function() {
            if($scope.vuln_type == "VulnerabilityWeb" && host_selected == true){
                $scope.incompatible_vulnWeb = true;
            } else {
                var res = {},
                id = $scope.target_selected._id + "." + CryptoJS.SHA1($scope.name + "." + $scope.desc).toString(),
                sha = CryptoJS.SHA1($scope.name + "." + $scope.desc).toString(),
                myDate = new Date(),
                myEpoch = myDate.getTime()/1000.0,
                extra_vulns_prop = {},
                res = {
                    "id":           id,
                    "data":         $scope.data,
                    "date":         myEpoch,
                    "desc":         $scope.desc,
                    "evidence":     $scope.evidence,
                    "meta":         {
                        'create_time': myEpoch,
                        "update_time": myEpoch,
                        "update_user":  'UI Web',
                        'update_action': 0,
                        'creator': 'UI Web', 
                        'create_time': myEpoch,
                        'update_controller_action': 'UI Web New',
                        'owner': 'anonymous'
                    },
                    "name":         $scope.name,
                    "oid":          sha,
                    "owned":        false,
                    "owner":        "",
                    "couch_parent": $scope.target_selected._id,
                    "refs":         [],
                    "status":       $scope.vuln_type,
                    "severity":     $scope.severitySelection,
                    "target":       name_selected,
                    "type":         $scope.vuln_type
                };

                if($scope.vuln_type == "VulnerabilityWeb") {
                    extra_vulns_prop = {
                        "path":         $scope.path,
                        "pname":        $scope.pname,
                        "query":        $scope.query,
                        "request":      $scope.request,
                        "response":     $scope.response,
                        "web":          true, 
                        "website":      $scope.website
                    };
                } else {
                    extra_vulns_prop = {
                        "web":          false
                    };
                }

                for(var key in extra_vulns_prop) {
                    res[key] = extra_vulns_prop[key];
                }

                $modalInstance.close(res);
            }
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
                host_selected = false;
                $scope.target_selected = $scope.hosts_with_services[i].services[j];
                name_selected = $scope.hosts_with_services[i].name;
            }else{
                host_selected = true;
                $scope.target_selected = $scope.hosts_with_services[i];
                name_selected = $scope.hosts_with_services[i].name;
            }
            $scope.target_selected.selected = true;
            $scope.not_target_selected = true;
        }
    }]);
