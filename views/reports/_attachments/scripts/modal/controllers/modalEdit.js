angular.module('faradayApp')
    .controller('modalEditCtrl', 
        ['$scope', '$modalInstance', 'severities', 'vulns', 'commons',
        function($scope, $modalInstance, severities, vulns, commons) {

        $scope.pickVuln = function(v) {
            $scope.p_name = v.name;
            $scope.p_desc = v.desc;
            $scope.p_data = v.data;
            $scope.severitySelection = v.severity;
            $scope.p_method = v.method;
            $scope.p_pname = v.pname;
            $scope.p_params = v.params;
            $scope.p_path = v.path;
            $scope.p_query = v.query;
            $scope.p_website = v.website;
            $scope.p_refs = v.refs;
            $scope.p_request = v.request;
            $scope.p_response = v.response;
            $scope.p_resolution = v.resolution;
            
            $scope.name = $scope.p_name;
            $scope.data = $scope.p_data;
            $scope.desc = $scope.p_desc;
            $scope.method = $scope.p_method;
            $scope.params = $scope.p_params;
            $scope.path = $scope.p_path;
            $scope.pname = $scope.p_pname;
            $scope.query = $scope.p_query;
            $scope.refs = $scope.p_refs;
            $scope.request = $scope.p_request;
            $scope.response = $scope.p_response;
            $scope.resolution = $scope.p_resolution;
            $scope.website = $scope.p_website;
        };

        $scope.call = function(){
            $scope.refs = commons.arrayToObject($scope.refs);
        }

        $scope.severities = severities;
        $scope.vulns = vulns;
        $scope.web = false;
        $scope.mixed = 0x00;

        $scope.vulnc = 0;
        var vuln_mask = {"VulnerabilityWeb": 0x01, "Vulnerability": 0x10};

        $scope.vulns.forEach(function(v) {
            if(v.selected) {
                $scope.mixed = $scope.mixed | vuln_mask[v.type];
                $scope.vulnc++;
                $scope.pickVuln(v);
                if (v.type === "VulnerabilityWeb") {
                    $scope.web = true;
                    //web
                }
                
            }
        });
        
        $scope.unit = $scope.vulnc == 1;
        
        if ($scope.vulnc > 1) {
            $scope.p_name = "";
            $scope.p_desc = "";
            $scope.p_data = "";
            $scope.p_method = "";
            $scope.p_pname = "";
            $scope.p_params = "";
            $scope.p_path = "";
            $scope.p_query = "";
            $scope.p_website = "";
            $scope.p_refs = "";
            $scope.p_request = "";
            $scope.p_response = "";
            $scope.p_resolution = "";
        }

        if($scope.mixed == 0x11) {
            $scope.mixed = true;
        } else {
            $scope.mixed = false;
        }

        $scope.isChecked = function(i) {
            return i.selected;
        };

        $scope.ok = function() {
            $scope.refs = commons.objectToArray($scope.refs);
            if($scope.web) { 
                res = {
                    "data":         $scope.data,
                    "desc":         $scope.desc,
                    "method":       $scope.method,
                    "name":         $scope.name, 
                    "params":       $scope.params,
                    "path":         $scope.path,
                    "pname":        $scope.pname,
                    "query":        $scope.query,
                    "refs":         $scope.refs,
                    "request":      $scope.request,
                    "response":     $scope.response,
                    "resolution":   $scope.resolution,
                    "severity":     $scope.severitySelection, 
                    "vulns":        $scope.vulns, 
                    "website":      $scope.website
                };    
            } else {
                res = {
                    "data":         $scope.data,
                    "desc":         $scope.desc,
                    "name":         $scope.name, 
                    "refs":         $scope.refs,
                    "resolution":   $scope.resolution,
                    "severity":     $scope.severitySelection, 
                    "vulns":        $scope.vulns 
                };
            }

            $modalInstance.close(res);
        };

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };
        
        $scope.refs = commons.arrayToObject($scope.refs);

        $scope.newReference = function($event){
            $scope.refs.push({ref:''});
        };
    }]);
