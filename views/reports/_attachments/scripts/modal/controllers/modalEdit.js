angular.module('faradayApp')
    .controller('modalEditCtrl', ['$scope', '$modalInstance', 'commonsFact', 'severities', 'vulns', 
        function($scope, $modalInstance, commons, severities, vulns) {

        $scope.evidence = [];
        $scope.icons = [];
        $scope.severities = severities;
        $scope.vulns = vulns;
        $scope.web = false;
        $scope.mixed = 0x00;
        $scope.vulnc = 0;
        var vuln_mask = {"VulnerabilityWeb": 0x01, "Vulnerability": 0x10};

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
            $scope.p_request = v.request;
            $scope.p_response = v.response;
            
            $scope.name = $scope.p_name;
            $scope.data = $scope.p_data;
            $scope.desc = $scope.p_desc;
            $scope.method = $scope.p_method;
            $scope.params = $scope.p_params;
            $scope.path = $scope.p_path;
            $scope.pname = $scope.p_pname;
            $scope.query = $scope.p_query;
            $scope.request = $scope.p_request;
            $scope.response = $scope.p_response;
            $scope.website = $scope.p_website;
        };

        $scope.vulns.forEach(function(v) {
            if(v.selected) {
                if(typeof(v.attachments) != undefined && v.attachments != undefined) {
                    $scope.evidence = v.attachments;
                    $scope.icons = commons.loadIcons($scope.evidence); 
                }
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
            $scope.p_request = "";
            $scope.p_response = "";
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
            var res = {};

            if($scope.web) { 
                res = {
                    "data":     $scope.data,
                    "desc":     $scope.desc,
                    "evidence": $scope.evidence,
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
                    "evidence": $scope.evidence,
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

        $scope.selectedFiles = function(files, e) {
            $scope.evidence = $scope.evidence.concat(files);
            $scope.icons = commons.loadIcons($scope.evidence); 
        }

        $scope.removeEvidence = function(index) {
            $scope.evidence.splice(index, 1);
            $scope.icons.splice(index, 1);
        }
    }]);
