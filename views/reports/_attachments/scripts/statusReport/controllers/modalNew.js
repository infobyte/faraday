// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('modalNewVulnCtrl',
        ['$modalInstance', '$filter', '$upload', 'EASEOFRESOLUTION', 'commonsFact', 'severities', 'workspace', 'targetFact', 'cweFact',
        function($modalInstance, $filter, $upload, EASEOFRESOLUTION, commons, severities, workspace, targetFact, cweFact) {

        var vm = this;

        vm.vuln_types;
        vm.easeofresolution;
        vm.workspace;
        vm.new_ref;
        vm.icons;
        vm.cweList;
        vm.cweLimit;
        vm.cwe_filter;

        vm.file_name_error;

        vm.currentPage;
        vm.newCurrentPage;
        vm.pageSize;

        vm.targets; 
        vm.target_filter;

        vm.data;

        init = function() {
            vm.vuln_types = [
                {name:'Vulnerability', value:'Vulnerability'},
                {name:'Vulnerability Web', value:'VulnerabilityWeb'}
            ];
            vm.easeofresolution = EASEOFRESOLUTION;
            vm.severities = severities;
            vm.workspace = workspace;
            vm.new_ref = "";
            vm.icons = {};

            vm.cweList = [];
            cweFact.get().then(function(data) {
                vm.cweList = data;
            });
            vm.cweLimit = 5;
            vm.cwe_filter = "";

            vm.file_name_error = false;
 
            vm.pageSize = 5;
            vm.currentPage = 0;
            vm.newCurrentPage = 0;

            vm.data = {
                _attachments: {},
                type: "Vulnerability",
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
                owned: false,
                parent: undefined,
                refs: [],
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

            vm.targets = [];
            vm.target_filter = "";

            targetFact.getTargets(workspace).then(function(targets){
                vm.targets = targets;
            });
        };

        vm.selectedFiles = function(files, e) {
            files.forEach(function(file) {
                if(file.name.charAt(0) != "_") {
                    if(!vm.data._attachments.hasOwnProperty(file)) vm.data._attachments[file.name] = file;
                    vm.file_name_error = false;
                } else {
                    vm.file_name_error = true;
                }
            });
            vm.icons = commons.loadIcons(vm.data._attachments);
        };

        vm.removeEvidence = function(name) {
            delete vm.data._attachments[name];
            delete vm.icons[name];
        };

        vm.toggleImpact = function(key) {
            vm.data.impact[key] = !vm.data.impact[key];
        };

        vm.ok = function() {
            if (!(vm.data.type === "VulnerabilityWeb" && vm.data.parent.type === "Host")) {
                // add the ref in new_ref, if there's any
                vm.newReference();

                // convert refs to an array of strings
                var refs = [];
                vm.data.refs.forEach(function(ref) {
                    refs.push(ref.value);
                });
                vm.data.refs = refs;
                vm.data.confirmed = true;

                // delete selection
                delete vm.data.parent.selected_modalNewCtrl;

                vm.data.parent = vm.data.parent._id;

                $modalInstance.close(vm.data);
            }
        };

        vm.cancel = function() {
            $modalInstance.dismiss('cancel');
        };

        vm.setTarget = function(target) {
            if (vm.data.parent != undefined) {
                delete vm.data.parent.selected_modalNewCtrl;
            }
            target.selected_modalNewCtrl = true;
            vm.data.parent = target;
        }

        vm.go = function() {
            vm.currentPage = 0;
            if(vm.newCurrentPage <= parseInt(vm.targets.length/vm.pageSize)
                    && vm.newCurrentPage > -1) {
                vm.currentPage = vm.newCurrentPage;
            }
        }

        vm.newReference = function() {
            if (vm.new_ref != "") {
                // we need to check if the ref already exists
                if (vm.data.refs.filter(function(ref) {return ref.value === vm.new_ref}).length == 0) {
                    vm.data.refs.push({value: vm.new_ref});
                    vm.new_ref = "";
                }
            }
        }

        vm.populate = function(item, model, label) {

            for (var key in item) {
                if (key != "refs" && vm.data.hasOwnProperty(key)) {
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
