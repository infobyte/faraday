// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('modalEditCtrl', ['$modalInstance', 'EASEOFRESOLUTION', 'STATUSES', 'commonsFact', 'severities', 'vuln', 'vulnModelsManager',
        function($modalInstance, EASEOFRESOLUTION, STATUSES, commons, severities, vuln, vulnModelsManager) {
        
        var vm = this;

        vm.saveAsModelDisabled = false;
        vm.easeofresolution;
        vm.new_ref;
        vm.new_policyviolation;
        vm.icons;
        vm.cweList;
        vm.cweLimit;
        vm.cwe_filter;

        vm.file_name_error;

        vm.data;
        vm.vuln;

        init = function() {
            vm.modelMessage = "Click here."
            vm.easeofresolution = EASEOFRESOLUTION;
            vm.severities = severities;
            vm.statuses = STATUSES;
            vm.new_ref = "";
            vm.new_policyviolation = "";
            vm.icons = {};

            vm.cweList = [];
            vulnModelsManager.get().then(function(data) {
                vm.cweList = data;
            });
            vm.cweLimit = 5;
            vm.cwe_filter = "";

            vm.file_name_error = false;
 
            vm.data = {
                _attachments: {},
                confirmed: false,
                data: "",
                desc: "",
                easeofresolution: undefined,
                impact: {
                    accountability: false,
                    availability: false,
                    confidentiality: false,
                    integrity: false
                },
                name: "",
                refs: {},
                resolution: "",
                severity: undefined,
                method: "", 
                path: "", 
                pname: "", 
                params: "",
                query: "", 
                request: "",
                response: "",
                website: "",
                status: "opened",
                policyviolations: []
            };

            vm.vuln = angular.copy(vuln);

            vm.populate(vm.vuln);

            // TODO: EVIDENCE SHOUD BE LOADED ALREADY?    
            if(vm.vuln._attachments !== undefined) {
                vm.data._attachments = vm.vuln._attachments;
                vm.icons = commons.loadIcons(vm.data._attachments); 
            }
        };

        vm.saveAsModel = function() {
            vm.modelMessage = "Done."
            vm.vulnModelsManager.create(vm.data);
            vm.saveAsModelDisabled = true;
        }
        
        vm.selectedFiles = function(files, e) {
            files.forEach(function(file) {
                if(file.name.charAt(0) != "_") {
                    if(!vm.data._attachments.hasOwnProperty(file)) vm.data._attachments[file.name] = file;
                } else {
                    vm.file_name_error = true;
                }
            });
            vm.icons = commons.loadIcons(vm._attachments);
        }

        vm.removeEvidence = function(name) {
            delete vm.data._attachments[name];
            delete vm.icons[name];
        }

        vm.toggleImpact = function(key) {
            vm.data.impact[key] = !vm.data.impact[key];
        };

        vm.ok = function() {
            // add the ref in new_ref, if there's any
            vm.newReference();
            // convert refs to an array of strings
            var refs = [];
            vm.data.refs.forEach(function(ref) {
                refs.push(ref.value);
            });
            vm.data.refs = refs;

            // add the policy violation in new_policyviolation, if there's any
            vm.newPolicyViolation();
            // convert policy violations to an array of strings
            var policyviolations = [];
            vm.data.policyviolations.forEach(function(policyviolation) {
                policyviolations.push(policyviolation.value);
            });
            vm.data.policyviolations = policyviolations;
            $modalInstance.close(vm.data);
        };

        vm.cancel = function() {
            $modalInstance.dismiss('cancel');
        };

        vm.newReference = function() {
            if (vm.new_ref != "") {
                // we need to check if the ref already exists
                if (vm.data.refs.filter(function(ref) {return ref.value === vm.new_ref}).length == 0) {
                    vm.data.refs.push({value: vm.new_ref});
                    vm.new_ref = "";
                }
            }
        }

        vm.newPolicyViolation = function() {
            if (vm.new_policyviolation != "") {
                // we need to check if the policy violation already exists
                if (vm.data.policyviolations.filter(function(policyviolation) {return policyviolation.value === vm.new_policyviolation}).length == 0) {
                    vm.data.policyviolations.push({value: vm.new_policyviolation});
                    vm.new_policyviolation = "";
                }
            }
        }

        vm.populate = function(item) {
            for (var key in vm.data) {
                if (key != "refs" && key != "policyviolations" && item.hasOwnProperty(key) && vm.data.hasOwnProperty(key)) {
                    vm.data[key] = item[key];
                }
            }
            // convert refs to an array of objects
            var refs = [];
            item.refs.forEach(function(ref) {
                refs.push({value: ref});
            });
            vm.data.refs = refs;

            // convert policyviolations to an array of objects
            var policyviolations = [];
            item.policyviolations.forEach(function(policyviolation) {
                policyviolations.push({value: policyviolation});
            });
            vm.data.policyviolations = policyviolations;
        }

        init();
    }]);
