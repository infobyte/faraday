// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('modalNewVulnCtrl', [
        '$modalInstance',
        '$filter',
        '$upload',
        'EASEOFRESOLUTION',
        'commonsFact',
        'severities',
        'workspace',
        'targetFact',
        'vulnModelsManager',
        'vulnsManager',
        'customFields',
        function ($modalInstance,
                  $filter,
                  $upload,
                  EASEOFRESOLUTION,
                  commonsFact,
                  severities,
                  workspace,
                  targetFact,
                  vulnModelsManager,
                  vulnsManager,
                  customFields) {

        var vm = this;

        vm.vuln_types;
        vm.easeofresolution;
        vm.workspace;
        vm.new_ref;
        vm.new_policyviolation;
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

        vm.activeSearch;

        init = function() {
            vm.vuln_types = [
                {name:'Vulnerability', value:'Vulnerability'},
                {name:'Vulnerability Web', value:'VulnerabilityWeb'}
            ];
            vm.easeofresolution = EASEOFRESOLUTION;
            vm.severities = severities;
            vm.workspace = workspace;
            vm.new_ref = "";
            vm.new_policyviolation = "";
            vm.icons = {};

            vm.host_parents = false;

            vm.customFields = customFields;

            vm.cweList = [];
            vulnModelsManager.get().then(function(data) {
                vm.cweList = data;
            });
            vm.cweLimit = 5;
            vm.cwe_filter = "";

            vm.file_name_error = false;

            vm.pageSize = 5;
            vm.currentPage = 1;
            vm.newCurrentPage = 0;
            vm.total_rows = 0;

            vm.data = {
                _attachments: {},
                data: "",
                desc: "",
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
                parents: [],  // a tuple with (parent_id, parent_type)
                path: "",
                status_code: undefined,
                pname: "",
                policyviolations: [],
                easeofresolution: null,
                query: "",
                refs: [],
                request: "",
                resolution: "",
                response: "",
                severity: undefined,
                type: "Vulnerability",
                website: "",
                custom_fields:{},
		external_id: "",
            };

            customFields.forEach(function(cf) {
                vm.data.custom_fields[cf.field_name] = null;
            });

            vm.targets = [];
            vm.target_filter = "";

            targetFact.getTargets(workspace,  vm.currentPage, vm.pageSize).then(function(targets){
                vm.targets = targets.hosts;
                vm.total_rows = targets.total;
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
            vm.icons = commonsFact.loadIcons(vm.data._attachments);
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
            vm.newPolicyViolation();

            // convert refs to an array of strings
            var refs = [];
            vm.data.refs.forEach(function(ref) {
                refs.push(ref.value);
            });
            vm.data.refs = refs;

            var policyviolations = [];
            vm.data.policyviolations.forEach(function(violation) {
                policyviolations.push(violation.value);
            });
            vm.data.policyviolations = policyviolations;

            vulnsManager.createVuln(vm.workspace, vm.data).then(function(){
                $modalInstance.close(vm.data);
            }, function(response){
                if (response.status == 409) {
                    commonsFact.showMessage("Error while creating a new Vulnerability " + vm.data.name + " Conflicting Vulnerability with id: " + response.data.object._id + ". " + response.data.message);
                } else if (response.status == 400){
                    //commonsFact.showMessage("Your input data is wrong, Attachments error");
                    var field = Object.keys(response.data.messages)[0];
                    var error = response.data.messages[field][0];
                    commonsFact.showMessage("Your input data is wrong,    " + field.toUpperCase() +":      " + error);

                }else {
                    commonsFact.showMessage("Error from backend: " + response.status);
                }
            });
        };

        vm.cancel = function() {
            $modalInstance.dismiss('cancel');
        };

        vm.setTargets = function(filter, start, size) {
            var end = start + size,
            targets = vm.targets;

            if(filter) {
                targets = vm.targets_filtered;
            }

            vm.data.parents = targets.slice(start, end);

            vm.host_parents = vm.data.parents.some(function(elem, ind, arr) {
                return elem.type === 'Host';
            });
        };

        vm.resetTarget = function() {
            vm.data.parents = [];
            vm.host_parents = false;
        }

        vm.setTarget = function(target) {
            var index = -1;
            var array = $.grep(vm.data.parents, function(e, i){
                index = i;
                return e.id === target.id && e.type === target.type
            });

            if (array.length > 0)
                vm.data.parents.splice(index, 1);
            else
                vm.data.parents.push(target);

            // refresh host_parents var
            vm.host_parents = vm.data.parents.some(function(elem, ind, arr) {
                return elem.type === 'Host';
            });
        }

        vm.go = function() {
            vm.currentPage = 0;
            if((vm.newCurrentPage) <= parseInt(vm.total_rows/vm.pageSize)
                    && (vm.newCurrentPage) > 0) {
                vm.currentPage = vm.newCurrentPage;
            }

            vm.updatePaginator(false, vm.newCurrentPage)
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

        vm.newPolicyViolation = function() {
            if (vm.new_policyviolation != "") {
                // we need to check if the policy violation already exists
                if (vm.data.policyviolations.filter(function(policyviolation) {return policyviolation.value === vm.new_policyviolation}).length == 0) {
                    vm.data.policyviolations.push({value: vm.new_policyviolation});
                    vm.new_policyviolation = "";
                }
            }
        }

        vm.populate = function(item, model, label) {

            for (var key in item) {
                if(key != "refs" && key != "policyviolations" && vm.data.hasOwnProperty(key)) {
                    vm.data[key] = item[key];
                }else if (key === 'exploitation'){
                    vm.data['severity'] = item['exploitation'];
                }
            }

            // convert refs to an array of objects
            var refs = [];
            item.refs.forEach(function(ref) {
                refs.push({value: ref});
            });
            vm.data.refs = refs;

            var policyviolations = [];
            if(item.hasOwnProperty('policyviolations')) item.policyviolations.forEach(function(policyviolation) {
                policyviolations.push({value: policyviolation});
            });
            vm.data.policyviolations = policyviolations;

            if(item.customfields){
                for(var cf in item.customfields){
                    vm.data.custom_fields[cf] = item.customfields[cf];
                }
            }
        }

        vm.updateBtnSeverityColor = function (severity) {
            var color = undefined;
            switch (severity) {
                case "unclassified":
                    color = '#999999';
                    break;
                case "info":
                    color = '#2e97bd';
                    break;
                case "low":
                    color = '#a1ce31';
                    break;
                case "med":
                    color = '#dfbf35';
                    break;
                case "high":
                    color = '#df3936';
                    break;
                case "critical":
                    color = '#932ebe';
                    break;
                default:
                    color = '#AAAAAA';
                    break;
            }

            angular.element('#btn-chg-severity').css('background-color', color);
            angular.element('#caret-chg-severity').css('background-color', color);
        };

        vm.changeSeverity = function (severity) {
            vm.data.severity = severity;
            vm.updateBtnSeverityColor(severity);
        };

        vm.updatePaginator = function (isNext, toGo) {
            if (isNext === true)
                vm.currentPage = vm.currentPage + 1;
            else
                vm.currentPage = vm.currentPage - 1;

            if (toGo)
                vm.currentPage = toGo;


            targetFact.getTargets(workspace,  vm.currentPage, vm.pageSize).then(function(targets){
                vm.targets = targets.hosts;
                vm.targets_filtered = vm.targets
            });
        };

        vm.isParentSelected = function (target) {
               return $.grep(vm.data.parents, function(e){ return e.id === target.id && e.type === target.type}).length > 0;
        };

        vm.filterTargets = function () {
            var filter = { search : vm.target_filter };
            targetFact.getTargets(workspace,  vm.currentPage, vm.pageSize, filter).then(function(targets){
                vm.targets = targets.hosts;
                vm.activeSearch = true;
            });
        };

        vm.clearFilterTargets = function () {
            vm.activeSearch = false;
            targetFact.getTargets(workspace,  vm.currentPage, vm.pageSize).then(function(targets){
                vm.targets = targets.hosts;
                vm.target_filter = '';
            });
        };

        init();
    }]);
