// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('modalEditCtrl', ['$modalInstance', 'EASEOFRESOLUTION', 'commonsFact', 'severities', 'vulns', 
        function($modalInstance, EASEOFRESOLUTION, commons, severities, vulns) {
        
        var vm = this;

        vm.easeofresolution;
        vm.new_ref;
        vm.icons;
        vm.cweList;
        vm.cweLimit;
        vm.cwe_filter;

        vm.file_name_error;

        vm.data;
        vm.vulns;
        vm.mixed;

        init = function() {
            vm.easeofresolution = EASEOFRESOLUTION;
            vm.severities = severities;
            vm.new_ref = "";
            vm.icons = {};

            vm.cweList = [];
            cweFact.get().then(function(data) {
                vm.cweList = data;
            });
            vm.cweLimit = 5;
            vm.cwe_filter = "";

            vm.file_name_error = false;
 
            vm.data = {
                data: "",
                desc: "",
                easeofresolution: undefined,
                evidence: {},
                impact: {
                    accountability: false,
                    availability: false,
                    confidentiality: false,
                    integrity: false
                },
                name: "",
                refs: [],
                resolution: "",
                severity: undefined,
                method: "", 
                path: "", 
                pname: "", 
                query: "", 
                request: "",
                response: "",
                website: ""
            };

            vm.vulns = vulns;

            vm.mixed = false;
            var mask = 0x00;
            var vuln_mask = {"VulnerabilityWeb": 0x01, "Vulnerability": 0x10};

            vm.vulns.forEach(function(v) {
                if (typeof(v.attachments) != undefined && v.attachments != undefined) {
                    v.attachments.forEach(function(name) {
                        vm.data.evidence[name] = {"name": name};
                    });
                    vm.icons = commons.loadIcons(vm.data.evidence); 
                    vm.mask = vm.mask | vuln_mask[v.type];
                }
            });

            vm.mixed = mask == 0x11;

            if (vm.vulns.length == 1) {
                vm.populate(vm.vulns[0]);
            } 
        };
        
        vm.selectedFiles = function(files, e) {
            files.forEach(function(file) {
                if(file.name.charAt(0) != "_") {
                    if(!vm.evidence.hasOwnProperty(file)) vm.evidence[file.name] = file;
                } else {
                    vm.file_name_error = true;
                }
            });
            vm.icons = commons.loadIcons(vm.evidence); 
        }

        vm.removeEvidence = function(name) {
            delete vm.evidence[name];
            delete vm.icons[name];
        }

        vm.toggleImpact = function(key) {
            vm.impact[key] = !vm.impact[key];
        };
        
        vm.ok = function() {
           if(vm.web) { 
                res = {
                    "data":             vm.data,
                    "desc":             vm.desc,
                    "easeofresolution": vm.easeOfResolutionSelection,
                    "evidence":         vm.evidence,
                    "impact":           vm.impact,
                    "method":           vm.method,
                    "name":             vm.name, 
                    "params":           vm.params,
                    "path":             vm.path,
                    "pname":            vm.pname,
                    "query":            vm.query,
                    "refs":             vm.refs,
                    "request":          vm.request,
                    "response":         vm.response,
                    "resolution":       vm.resolution,
                    "severity":         vm.severitySelection, 
                    "vulns":            vm.vulns, 
                    "website":          vm.website
                };    
            } else {
                res = {
                    "data":         vm.data,
                    "desc":         vm.desc,
                    "easeofresolution": vm.easeOfResolutionSelection,
                    "evidence":     vm.evidence,
                    "impact":       vm.impact,
                    "name":         vm.name, 
                    "refs":         vm.refs,
                    "resolution":   vm.resolution,
                    "severity":     vm.severitySelection, 
                    "vulns":        vm.vulns 
                };
            }

            $modalInstance.close(res);
        };

        vm.cancel = function() {
            $modalInstance.dismiss('cancel');
        };

        vm.newReference = function() {
            vm.data.refs.push(vm.new_ref);
            vm.new_ref = "";
        }

       vm.populate = function(item) {
            for (var key in data) {
                if (item.hasOwnProperty(key)) {
                    vm.data[key] = item[key];
                }
            }
        }
    }]);
