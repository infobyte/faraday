// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('modalNewVulnCtrl',
        ['$modalInstance', '$filter', '$upload', 'EASEOFRESOLUTION', 'commonsFact', 'severities', 'workspace', 'hostsManager','servicesManager', 'cweFact',
        function($modalInstance, $filter, $upload, EASEOFRESOLUTION, commons, severities, workspace, hostsManager, servicesManager, cweFact) {

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
                type: "Vulnerability",
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

            hostsManager.getHosts(workspace).then(function(hosts){
                hosts.forEach(function(host){
                    host.hostnames = [];
                    host.services = [];
                    hostsManager.getInterfaces(workspace, host._id).then(function(interfaces){
                        interfaces.forEach(function(interface){
                            host.hostnames = host.hostnames.concat(interface.value.hostnames);
                        });
                        servicesManager.getServicesByHost(workspace, host._id).then(function(services) {
                            host.services = services;
                            vm.targets.push(host);
                        });
                    });
                });
            });
        };

        vm.selectedFiles = function(files, e) {
            files.forEach(function(file) {
                if(file.name.charAt(0) != "_") {
                    if(!vm.data.evidence.hasOwnProperty(file)) vm.data.evidence[file.name] = file;
                    vm.file_name_error = false;
                } else {
                    vm.file_name_error = true;
                }
            });
            vm.icons = commons.loadIcons(vm.data.evidence);
        };

        vm.removeEvidence = function(name) {
            delete vm.data.evidence[name];
            delete vm.icons[name];
        };

        vm.toggleImpact = function(key) {
            vm.data.impact[key] = !vm.data.impact[key];
        };

        vm.ok = function() {
            if (!(vm.data.type === "VulnerabilityWeb" && vm.data.parent.type === "Host")) {
                vm.data.parent = vm.data.parent._id;
                $modalInstance.close(vm.data);
            }
        };

        vm.cancel = function() {
            $modalInstance.dismiss('cancel');
        };

        vm.setTarget = function(target) {
            if (vm.data.parent != undefined) {
                vm.data.parent.selected = false;
            }
            target.selected = true;
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
            vm.data.refs.push(vm.new_ref);
            vm.new_ref = "";
        }

        vm.populate = function(item, model, label) {
            for (var key in item) {
                if (vm.data.hasOwnProperty(key)) {
                    vm.data[key] = item[key];
                }
            }
        }

        init();
    }]);
