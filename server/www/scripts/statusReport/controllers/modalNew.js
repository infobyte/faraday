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

        // true if all the parents in data.parents are type Host
        vm.host_parents;

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

            vm.host_parents = false;

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
                data: "",
                desc: "",
                easeofresolution: undefined,
                impact: {
                    accountability: false,
                    availability: false,
                    confidentiality: false,
                    integrity: false
                },
                method: "",
                name: "",
                owned: false,
                params: "",
                parents: [],
                path: "",
                pname: "",
                query: "",
                refs: [],
                request: "",
                resolution: "",
                response: "",
                severity: undefined,
                type: "Vulnerability",
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
            // add the ref in new_ref, if there's any
            vm.newReference();

            // convert refs to an array of strings
            var refs = [];
            vm.data.refs.forEach(function(ref) {
                refs.push(ref.value);
            });
            vm.data.refs = refs;

            var parents = vm.data.parents;
            vm.data.parents = [];
            parents.forEach(function(parent) {
                vm.data.parents.push(parent._id);
            });

            $modalInstance.close(vm.data);
        };

        vm.cancel = function() {
            $modalInstance.dismiss('cancel');
        };

        vm.resetTarget = function () {
            vm.data.parents = [];
            vm.host_parents = false;
        };

        vm.setPageTargets = function(filter, start, size) {
            var end = start + size,
            targets = vm.targets;

            if(filter) {
                targets = vm.targets_filtered;
            }

            targets = targets.slice(start, end);

            vm.data.parents = targets;

            targets.forEach(function(target) {
                if(target.type === 'Host' && target.services.length > 0) {
                    vm.data.parents = vm.data.parents.concat(target.services);
                }
            });

            vm.host_parents = vm.data.parents.some(function(elem, ind, arr) {
                return elem.type === 'Host';
            });
        };

        vm.setTarget = function(target) {
            var index = vm.data.parents.indexOf(target);

            if(index >= 0) {
                // if target already selected, user is deselecting
                vm.data.parents.splice(index, 1);
            } else {
                // else, add to parents list
                vm.data.parents.push(target);
            }

            // refresh host_parents var
            vm.host_parents = vm.data.parents.some(function(elem, ind, arr) {
                return elem.type === 'Host';
            });
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
