// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('modalEditCtrl', ['$modalInstance', 'EASEOFRESOLUTION', 'commonsFact', 'severities', 'vuln', 'cweFact', 
        function($modalInstance, EASEOFRESOLUTION, commons, severities, vuln, cweFact) {
        
        var vm = this;

        vm.easeofresolution;
        vm.new_ref;
        vm.icons;
        vm.cweList;
        vm.cweLimit;
        vm.cwe_filter;

        vm.file_name_error;

        vm.data;
        vm.vuln;

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
                website: ""
            };

            vm.vuln = angular.copy(vuln);

            vm.populate(vm.vuln);

            // TODO: EVIDENCE SHOUD BE LOADED ALREADY?    
            if(vm.vuln._attachments !== undefined) {
                vm.data._attachments = vm.vuln._attachments;
                vm.icons = commons.loadIcons(vm.data._attachments); 
            }
        };
        
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

        vm.populate = function(item) {
            for (var key in vm.data) {
                if (key != "refs" && item.hasOwnProperty(key) && vm.data.hasOwnProperty(key)) {
                    vm.data[key] = item[key];
                }
            }
            // convert refs to an array of objects
            var refs = [];
            item.refs.forEach(function(ref) {
                refs.push({value: ref});
            });
            vm.data.refs = refs;
        }

        init();
    }]);
