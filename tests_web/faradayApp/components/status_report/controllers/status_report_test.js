// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

describe('statusReportCtrl', function() {
    var $controller,
        $scope;

    var $vulnsManager,
    vulnsManagerMock,
    $hostsManager,
    hostsManagerMock,
    $workspacesFact,
    workspacesFactMock,
    getCurrentSelection,
    vuln1, vuln2, vuln3;

    var returnPromise;

    var fakeModal = {
        result: {
            then: function(confirmCallback, cancelCallback) {
                //Store the callbacks for later when the user clicks on the OK or Cancel button of the dialog
                this.confirmCallBack = confirmCallback;
                this.cancelCallback = cancelCallback;
                return this;
            }
        },
        close: function(item) {
            //The user clicked OK on the modal dialog, call the stored confirm callback with the selected item
            this.result.confirmCallBack(item);
        },
        dismiss: function(type) {
            //The user clicked cancel on the modal dialog, call the stored cancel callback
            if (this.result.cancelCallback) this.result.cancelCallback(type);
        }
    };

    beforeEach(function () {
        module('faradayApp');

        inject(function(_$rootScope_, _$controller_, _$q_, _$modal_) {
            // The injector unwraps the underscores (_) from around the parameter names when matching
            $scope = _$rootScope_.$new();
            // workspaces variables
            vuln1 = {
                "_id": "1.2.3.4",
                "_rev": "1-abe16726389e434ca3f37384ea76128e",
                "name": "Internet Key Exchange (IKE) Aggressive Mode with Pre-Shared Key",
                "parent": "1.2.3",
                "resolution": "Be careful",
                "refs": [
                   "CVE-2002-1623",
                   "7423",
                   "OSVDB:3820, CERT:886601"
                ],
                "metadata": {
                   "update_time": 1429643049.395857,
                   "update_user": "john",
                   "update_action": 0,
                   "creator": "john",
                   "create_time": 1429643049.395857,
                   "update_controller_action": "ModelControler.newVuln",
                   "owner": "john"
                },
                "impact": {
                    accountability: false,
                    availability: false,
                    confidentiality: false,
                    integrity: false
                },
                "owned": false,
                "severity": "med",
                "type": "Vulnerability",
                "owner": "john",
                "desc": "I'm scared!",
                "data": "",
                "easeofresolution": "simple",
                "description": "I'm scared!"
            };
            vuln2 = {
                "_id": "1.2.3.5",
                "_rev": "1-abe16726389e434ca3f37384ea76128e",
                "name": "Another vuln",
                "parent": "1.2.3",
                "resolution": "Be careful",
                "refs": [
                   "CVE-2002-1623",
                   "7423",
                   "OSVDB:3820, CERT:886601"
                ],
                "metadata": {
                   "update_time": 1429643049.395857,
                   "update_user": "john",
                   "update_action": 0,
                   "creator": "john",
                   "create_time": 1429643049.395857,
                   "update_controller_action": "ModelControler.newVuln",
                   "owner": "john"
                },
                "impact": {
                    accountability: false,
                    availability: false,
                    confidentiality: false,
                    integrity: false
                },
                "owned": false,
                "severity": "med",
                "type": "Vulnerability",
                "owner": "john",
                "desc": "I'm scared!",
                "data": "",
                "easeofresolution": "trivial",
                "description": "I'm scared!"
            };
            vuln3 = {
                "_id": "6.7.8.9",
                "_rev": "3-f34c61eca3cb5ffc5654f710774708af",
                "desc": "It was possible to identify the remote service by its banner.",
                "metadata": {
                   "update_time": 1407530638.669383,
                   "update_user": "",
                   "update_action": 0,
                   "creator": "",
                   "create_time": 1407530638.669383,
                   "update_controller_action": "No model controller call",
                   "owner": ""
                },
                "easeofresolution": "simple",
                "name": "Service Detection",
                "obj_id": "008cba9b11897f2d52c53dd953d75fa233a7fffe",
                "owned": false,
                "owner": "",
                "parent": "6.7.8",
                "refs": [
                ],
                "impact": {
                    accountability: false,
                    availability: false,
                    confidentiality: false,
                    integrity: false
                },
                "severity": "low",
                "type": "VulnerabilityWeb",
                "method": "",
                "params": "",
                "path": "",
                "pname": "",
                "query": "",
                "request": "",
                "response": "",
                "website": "test.test.com"
            };

            returnPromise = function(res) {
                var deferred = _$q_.defer();
                deferred.resolve(res);
                return deferred.promise;
            }

            rejectPromise = function(res) {
                var deferred = _$q_.defer();
                deferred.reject(res);
                return deferred.promise;
            }

            workspacesFactMock = {
                list: function() {
                    return returnPromise(['ws1', 'ws2'])
                }
            }

            hostsManagerMock = {
            }

            vulnsManagerMock = {
                vulns: [],
                getVulns: function(workspace) {
                    if (vulnsManagerMock.vulns.length == 0)
                        vulnsManagerMock.vulns = [vuln1, vuln2, vuln3];
                    return returnPromise({
                        vulnerabilities: vulnsManagerMock.vulns,
                        count: vulnsManagerMock.vulns.length});
                },
                deleteVuln: function(vuln) {
                    if (vuln._id === "1.2.3.4" ||
                        vuln._id === "1.2.3.5" ||
                        vuln._id === "6.7.8.9") {
                        for (var i = 0; i < vulnsManagerMock.vulns.length; i++) {
                            var v = vulnsManagerMock.vulns[i];
                            if (v._id == vuln._id) {
                                vulnsManagerMock.vulns.splice(i, 1);
                                break;
                            }
                        };
                        return returnPromise(vulnsManagerMock.vulns);
                    } else {
                        return rejectPromise("error");
                    }
                },
                createVuln: function(workspace, vuln) {
                    vuln["id"] = "1.2.3.6";
                    vulnsManagerMock.vulns.push(vuln);
                    return returnPromise(vuln);
                },
                updateVuln: function(vuln, vulnData) {
                    if (vuln._id === "1.2.3.4" ||
                        vuln._id === "1.2.3.5" ||
                        vuln._id === "6.7.8.9") {
                        angular.extend(vuln, vulnData);
                        return returnPromise();
                    } else {
                        return rejectPromise("error");
                    }
                }

            };

            // fakeModal
            spyOn(_$modal_, 'open').and.returnValue(fakeModal);

            $controller = _$controller_('statusReportCtrl', {
                $scope: $scope,
                vulnsManager: vulnsManagerMock,
                hostsManager: hostsManagerMock,
                workspacesFact: workspacesFactMock,
                $routeParams: {wsId: 'ws1'},
                $uibModal: _$modal_,
            });
        });
    });


    describe('Status report init function without filter', function() {
        it('vulns loaded after execution', function() {
            $scope.$apply();
            expect($scope.gridOptions.data.length).toEqual(3);
            expect($scope.gridOptions.data).toContain(vuln1);
            expect($scope.gridOptions.data).toContain(vuln2);
            expect($scope.gridOptions.data).toContain(vuln3);
        });
    });

    describe('Status report vuln deletion - remove method', function() {
        it('remove valid vuln id 1.2.3.4', function() {
            $scope.remove([vuln1]);
            $scope.$apply();

            expect($scope.gridOptions.data.length).toEqual(2);
            expect($scope.gridOptions.data).not.toContain(vuln1);
            expect($scope.gridOptions.data).toContain(vuln2);
            expect($scope.gridOptions.data).toContain(vuln3);
        });
        it('remove invalid vuln id 9.9.9.9', function() {
            vuln = {"_id": "9.9.9.9"}
            $scope.remove([vuln]);
            $scope.$apply();

            expect($scope.gridOptions.data.length).toEqual(3);
            expect($scope.gridOptions.data).toContain(vuln1);
            expect($scope.gridOptions.data).toContain(vuln2);
            expect($scope.gridOptions.data).toContain(vuln3);
        });
        it('remove valid id 1.2.3.4 and invalid id 9.9.9.9', function() {
            vuln = {"_id": "9.9.9.9"}
            $scope.remove([vuln1, vuln]);
            $scope.$apply();

            expect($scope.gridOptions.data.length).toEqual(2);
            expect($scope.gridOptions.data).not.toContain(vuln1);
            expect($scope.gridOptions.data).toContain(vuln2);
            expect($scope.gridOptions.data).toContain(vuln3);
        });
        it('remove valid vulns ids', function() {
            $scope.remove([vuln1, vuln2]);
            $scope.$apply();

            expect($scope.gridOptions.data.length).toEqual(1);
            expect($scope.gridOptions.data).not.toContain(vuln1);
            expect($scope.gridOptions.data).not.toContain(vuln2);
            expect($scope.gridOptions.data).toContain(vuln3);
        });
    });

    describe('Status report vuln deletion - delete method (modal)', function() {
        it('call delete with no vulns selected', function() {
            // we need $scope.gridOptions.data to have all the vulns before calling
            // the delete method
            $scope.getCurrentSelection = function() { return []; }
            $scope.$apply();
            $scope.delete();
            $scope.$apply();

            expect($scope.gridOptions.data.length).toEqual(3);
            expect($scope.gridOptions.data).toContain(vuln1);
            expect($scope.gridOptions.data).toContain(vuln2);
            expect($scope.gridOptions.data).toContain(vuln3);
        });
        it('call delete with a valid vuln (1.2.3.4) selected and accept modal', function() {
            // we need $scope.gridOptions.data to have all the vulns before calling
            // the delete method
            $scope.getCurrentSelection = function() { return [vuln1]; }
            $scope.$apply();
            $scope.delete();
            fakeModal.close();
            $scope.$apply();

            expect($scope.gridOptions.data.length).toEqual(2);
            expect($scope.gridOptions.data).not.toContain(vuln1);
            expect($scope.gridOptions.data).toContain(vuln2);
            expect($scope.gridOptions.data).toContain(vuln3);
        });
        it('call delete with a valid vuln (1.2.3.4) selected and cancel modal', function() {
            // we need $scope.gridOptions.data to have all the vulns before calling
            // the delete method
            $scope.getCurrentSelection = function() { return [vuln1]; }
            $scope.$apply();
            $scope.delete();
            fakeModal.dismiss();
            $scope.$apply();

            expect($scope.gridOptions.data.length).toEqual(3);
            expect($scope.gridOptions.data).toContain(vuln1);
            expect($scope.gridOptions.data).toContain(vuln2);
            expect($scope.gridOptions.data).toContain(vuln3);
        });
        it('call delete with valid vulns selected and accept modal', function() {
            $scope.getCurrentSelection = function() { return [vuln1, vuln2]; }
            $scope.$apply();
            $scope.delete();
            fakeModal.close();
            $scope.$apply();

            expect($scope.gridOptions.data.length).toEqual(1);
            expect($scope.gridOptions.data).not.toContain(vuln1);
            expect($scope.gridOptions.data).not.toContain(vuln2);
            expect($scope.gridOptions.data).toContain(vuln3);
        });
    });

    describe('Status report vuln creation - insert method', function() {
        it('create a valid vuln', function() {
            var vulnNew = {
                "name": "Just a test vuln",
                "parent": "1.2.3",
                "resolution": "Be careful",
                "refs": [
                   "test"
                ],
                "metadata": {
                   "update_time": 1429643049.395857,
                   "update_user": "john",
                   "update_action": 0,
                   "creator": "john",
                   "create_time": 1429643049.395857,
                   "update_controller_action": "",
                   "owner": "john"
                },
                "owned": false,
                "severity": "med",
                "type": "Vulnerability",
                "owner": "john",
                "desc": "Test!",
                "data": "",
                "description": "Test!"
            };
            $scope.insert(vulnNew);
            $scope.$apply();

            expect($scope.gridOptions.data.length).toEqual(4);
            expect($scope.gridOptions.data).toContain(vulnNew);
        });
        it('create a duplicated vuln', function() {
            var vulnNew = {
                "name": "Just a test vuln",
                "parent": "1.2.3",
                "resolution": "Be careful",
                "refs": [
                   "test"
                ],
                "metadata": {
                   "update_time": 1429643049.395857,
                   "update_user": "john",
                   "update_action": 0,
                   "creator": "john",
                   "create_time": 1429643049.395857,
                   "update_controller_action": "",
                   "owner": "john"
                },
                "owned": false,
                "severity": "med",
                "type": "Vulnerability",
                "owner": "john",
                "desc": "Test!",
                "data": "",
                "description": "Test!"
            };

            // we change the mock to simulate an error during creation
            spyOn(vulnsManagerMock, 'createVuln').and.returnValue(
                rejectPromise("error"));
            $scope.insert(vulnNew);
            $scope.$apply();

            expect($scope.gridOptions.data.length).toEqual(3);
            expect($scope.gridOptions.data).not.toContain(vulnNew);
        });
    });

    describe('Status report vuln creation - new method (modal)', function() {
        it('create a valid vuln and accept modal', function() {
            var vulnNew = {
                "name": "Just a test vuln",
                "parent": "1.2.3",
                "resolution": "Be careful",
                "refs": [
                   "test"
                ],
                "metadata": {
                   "update_time": 1429643049.395857,
                   "update_user": "john",
                   "update_action": 0,
                   "creator": "john",
                   "create_time": 1429643049.395857,
                   "update_controller_action": "",
                   "owner": "john"
                },
                "owned": false,
                "severity": "med",
                "type": "Vulnerability",
                "owner": "john",
                "desc": "Test!",
                "data": "",
                "description": "Test!"
            };
            $scope.new();
            fakeModal.close(vulnNew);
            $scope.$apply();

            expect($scope.gridOptions.data.length).toEqual(4);
            expect($scope.gridOptions.data).toContain(vulnNew);
        });
        it('create a valid vuln but cancel modal', function() {
            var vulnNew = {
                "name": "Just a test vuln",
                "parent": "1.2.3",
                "resolution": "Be careful",
                "refs": [
                   "test"
                ],
                "metadata": {
                   "update_time": 1429643049.395857,
                   "update_user": "john",
                   "update_action": 0,
                   "creator": "john",
                   "create_time": 1429643049.395857,
                   "update_controller_action": "",
                   "owner": "john"
                },
                "owned": false,
                "severity": "med",
                "type": "Vulnerability",
                "owner": "john",
                "desc": "Test!",
                "data": "",
                "description": "Test!"
            };

            $scope.new();
            fakeModal.dismiss();
            $scope.$apply();

            expect($scope.gridOptions.data.length).toEqual(3);
            expect($scope.gridOptions.data).not.toContain(vulnNew);
        });
    });

    describe('Status report vuln edition - update method', function() {
        it('edit many vulns by property', function() {
            $scope.getCurrentSelection = function() { return [vuln1, vuln2, vuln3]; };
            var impact = {
                accountability: true,
                availability: true,
                confidentiality: true,
                integrity: false
            };

            $scope.$apply();
            // String properties
            $scope.editString('name');
            fakeModal.close('Changed name');
            // Text properties
            $scope.editText('desc');
            fakeModal.close('Changed description');
            // Severity property
            $scope.editSeverity();
            fakeModal.close('high');
            // Ease of resolution property(obj)
            $scope.editEaseofresolution();
            fakeModal.close('difficult');
            // References property
            $scope.editReferences();
            fakeModal.close(['CVE-new-ref','OSVDB:new-ref']);
            // Impact property(obj)
            $scope.editImpact();
            fakeModal.close(impact);
            // Comfirm property
            $scope.editConfirm();
            fakeModal.close('Confirm');

            $scope.gridOptions.data.forEach(function(v) {
                expect(v.name).toEqual("Changed name");
                expect(v.desc).toEqual("Changed description");
                expect(v.severity).toEqual("high");
                expect(v.easeofresolution).toEqual("difficult");
                expect(v.refs).toContain('CVE-new-ref', 'OSVDB:new-ref');
                expect(v.impact).toEqual(impact);
                expect(v.confirmed).toEqual(true);
            });
        });
        it('edit many vulns by property but cancel the modal', function() {
            $scope.getCurrentSelection = function() { return [vuln1, vuln2, vuln3]; };
            var impact = {
                accountability: true,
                availability: true,
                confidentiality: true,
                integrity: false
            };

            $scope.$apply();
            // String properties
            $scope.editString('name');
            fakeModal.dismiss();
            // Text properties
            $scope.editText('desc');
            fakeModal.dismiss();
            // Severity property
            $scope.editSeverity();
            fakeModal.dismiss();
            // Ease of resolution property(obj)
            $scope.editEaseofresolution();
            fakeModal.dismiss();
            // References property
            $scope.editReferences();
            fakeModal.dismiss();
            // Impact property(obj)
            $scope.editImpact();
            fakeModal.dismiss();
            // Comfirm property
            $scope.editConfirm();
            fakeModal.dismiss();

            $scope.gridOptions.data.forEach(function(v) {
                expect(v.name).not.toEqual("Changed name");
                expect(v.desc).not.toEqual("Changed description");
                expect(v.severity).not.toEqual("high");
                expect(v.easeofresolution).not.toEqual("difficult");
                expect(v.refs).not.toContain('CVE-new-ref', 'OSVDB:new-ref');
                expect(v.impact).not.toEqual(impact);
                expect(v.confirmed).not.toEqual(true);
            });
        });
        it('edit many vulns from CWE', function() {
            $scope.getCurrentSelection = function() { return [vuln1, vuln2, vuln3]; };
            var CWE_obj = {
                name: "ES-Cisco ASA Error",
                desc: "Summary: El cisco ASA es vulnerable",
                refs: ['CVE-new-ref'],
                resolution: "Actualizar la ultima version"
            };

            $scope.$apply();
            $scope.editCWE();
            fakeModal.close(CWE_obj);

            $scope.gridOptions.data.forEach(function(v) {
                expect(v.name).toEqual("ES-Cisco ASA Error");
                expect(v.desc).toEqual("Summary: El cisco ASA es vulnerable");
                expect(v.refs).toContain('CVE-new-ref');
                expect(v.resolution).toEqual('Actualizar la ultima version');
            });
        });
        it('edit many vulns from CWE but cancel the modal', function() {
            $scope.getCurrentSelection = function() { return [vuln1, vuln2, vuln3]; };
            var CWE_obj = {
                name: "ES-Cisco ASA Error",
                desc: "Summary: El cisco ASA es vulnerable",
                refs: ['CVE-new-ref'],
                resolution: "Actualizar la ultima version"
            };

            $scope.$apply();
            $scope.editCWE();
            fakeModal.dismiss();
            $scope.$apply();

            $scope.gridOptions.data.forEach(function(v) {
                expect(v.name).not.toEqual("ES-Cisco ASA Error");
                expect(v.desc).not.toEqual("Summary: El cisco ASA es vulnerable");
                expect(v.refs).not.toContain('CVE-new-ref');
                expect(v.resolution).not.toEqual('Actualizar la ultima version');
            });
        });
    });

    describe('Status report vuln edition - edit method (modal)', function() {
        it('edit a vuln and accept modal', function() {
            var vulnData = {
                "name": "Changed name",
                "resolution": "New resolution",
                "refs": [
                   "test",
                   "another ref"
                ],
                "owned": true,
                "severity": "high"
            };

            $scope.getCurrentSelection = function() { return [vuln1]; };

            $scope.$apply();
            $scope.edit();
            fakeModal.close(vulnData);
            $scope.$apply();

            expect($scope.gridOptions.data.length).toEqual(3);
            $scope.gridOptions.data.forEach(function(vuln) {
                if (vuln._id == "1.2.3.4") {
                    expect(vuln.name).toEqual("Changed name");
                    expect(vuln.resolution).toEqual("New resolution");
                    expect(vuln.refs.length).toEqual(2);
                    expect(vuln.owned).toEqual(true);
                    expect(vuln.severity).toEqual("high");

                }
            });

        });
        it('edit a valid vuln but cancel modal', function() {
            var vulnData = {
                "name": "Changed name",
                "resolution": "New resolution",
                "refs": [
                   "test",
                   "another ref"
                ],
                "owned": true,
                "severity": "high"
            };
            $scope.getCurrentSelection = function() { return [vuln1]; };
            $scope.$apply();
            $scope.edit();
            fakeModal.dismiss();
            $scope.$apply();

            expect($scope.gridOptions.data.length).toEqual(3);
            $scope.gridOptions.data.forEach(function(vuln) {
                if (vuln._id == "1.2.3.4") {
                    expect(vuln.name).not.toEqual("Changed name");
                    expect(vuln.resolution).not.toEqual("New resolution");
                    expect(vuln.refs.length).not.toEqual(2);
                    expect(vuln.owned).not.toEqual(true);
                    expect(vuln.severity).not.toEqual("high");

                }
            });
        });
    });

    describe('statusReportCtrl check all function', function() {
        var $controller,
            $scope;

        var $vulnsManager,
        vulnsManagerMock,
        $workspacesFact,
        workspacesFactMock;

        var returnPromise;

        beforeEach(function () {
            module('faradayApp');

            inject(function(_$rootScope_, _$controller_, _$q_, _$modal_) {
                // The injector unwraps the underscores (_) from around the parameter names when matching
                $scope = _$rootScope_.$new();
                // workspaces variables

                returnPromise = function(res) {
                    var deferred = _$q_.defer();
                    deferred.resolve(res);
                    return deferred.promise;
                }

                rejectPromise = function(res) {
                    var deferred = _$q_.defer();
                    deferred.reject(res);
                    return deferred.promise;
                }

                workspacesFactMock = {
                    list: function() {
                        return returnPromise(['ws1', 'ws2'])
                    }
                }

                vulnsManagerMock = {
                    vulns: [],
                    getVulns: function(workspace) {
                        vulnsManagerMock.vulns = [];
                        for (var i=0; i < 10; i++) {
                            var vuln1 = {
                                "_id": "1.2.3." + i,
                                "_rev": "1-abe16726389e434ca3f37384ea76128e",
                                "name": "vuln " + i,
                                "parent": "1.2.3",
                                "resolution": "Be careful",
                                "refs": [
                                   "CVE-2002-1623",
                                   "7423",
                                   "OSVDB:3820, CERT:886601"
                                ],
                                "metadata": {
                                   "update_time": 1429643049.395857,
                                   "update_user": "john",
                                   "update_action": 0,
                                   "creator": "john",
                                   "create_time": 1429643049.395857 + i,
                                   "update_controller_action": "ModelControler.newVuln",
                                   "owner": "john"
                                },
                                "owned": false,
                                "severity": "med",
                                "type": "Vulnerability",
                                "owner": "john",
                                "desc": "I'm scared!",
                                "data": "",
                                "description": "I'm scared!"
                            };
                            var vuln2 = {
                                "_id": "2.2.3." + i,
                                "_rev": "1-abe16726389e434ca3f37384ea76128e",
                                "name": "vuln " + i,
                                "parent": "2.2.3",
                                "resolution": "Be careful",
                                "refs": [
                                   "CVE-2002-1623",
                                   "7423",
                                   "OSVDB:3820, CERT:886601"
                                ],
                                "metadata": {
                                   "update_time": 1429643049.395857,
                                   "update_user": "john",
                                   "update_action": 0,
                                   "creator": "john",
                                   "create_time": 1429643049.395857 + i + 10,
                                   "update_controller_action": "ModelControler.newVuln",
                                   "owner": "john"
                                },
                                "owned": false,
                                "severity": "high",
                                "type": "Vulnerability",
                                "owner": "john",
                                "desc": "I'm scared!",
                                "data": "",
                                "description": "I'm scared!"
                            };
                            vulnsManagerMock.vulns.push(vuln1);
                            vulnsManagerMock.vulns.push(vuln2);
                        }
                        return returnPromise(vulnsManagerMock.vulns);
                    }
                };

                $controller = _$controller_('statusReportCtrl', {
                    $scope: $scope,
                    vulnsManager: vulnsManagerMock,
                    hostsManager: {},
                    workspacesFact: workspacesFactMock,
                    $routeParams: {wsId: 'ws1'},
                    $modal: _$modal_
                });
            });
        });
    });

    describe('sort properly', function() {
        beforeEach(function() {
            $scope.selectall = false;
            $scope.reverse = false;
            $scope.pageSize = 5;
            // we set the sort field to make sure that
            // vulns are in the same order in every test
            $scope.sortField = "metadata.create_time";
            search_elem = function(aVulns, id){
                for(var i=0; i < aVulns.length; i++){
                    if (aVulns[i]._id == id) {
                        return aVulns[i];
                    }
                }
                return {};
            };
        });
        // it('when current page is 0', function() {
        //     $scope.currentPage = 0;
        //     $scope.$apply();
        //     $scope.checkAll();

        //     $scope.gridOptions.data.forEach(function(v) {
        //         if(v._id === "1.2.3.0" || v._id === "1.2.3.1" || v._id === "1.2.3.2" || v._id === "1.2.3.3" || v._id === "1.2.3.4") {
        //             expect(search_elem($scope.gridOptions.data, v._id).selected_statusreport_controller).toEqual(true);
        //         } else {
        //             expect(search_elem($scope.gridOptions.data, v._id).selected_statusreport_controller).not.toEqual(true);
        //         }
        //     });
        // });
        // it('when current page is 1', function() {
        //     $scope.currentPage = 1;
        //     $scope.$apply();
        //     $scope.checkAll();

        //     $scope.gridOptions.data.forEach(function(v) {
        //         if(v._id === "1.2.3.5" || v._id === "1.2.3.6" || v._id === "1.2.3.7" || v._id === "1.2.3.8" || v._id === "1.2.3.9") {
        //             expect(search_elem($scope.gridOptions.data, v._id).selected_statusreport_controller).toEqual(true);
        //         } else {
        //             expect(search_elem($scope.gridOptions.data, v._id).selected_statusreport_controller).not.toEqual(true);
        //         }
        //     });
        // });
        // it('when current page is 0 and filtering', function() {
        //     $scope.expression = {severity:"med"};
        //     $scope.$apply();
        //     $scope.checkAll();

        //     $scope.gridOptions.data.forEach(function(v) {
        //         if(v._id === "1.2.3.0" || v._id === "1.2.3.1" || v._id === "1.2.3.2" || v._id === "1.2.3.3" || v._id === "1.2.3.4") {
        //             expect(search_elem($scope.gridOptions.data, v._id).selected_statusreport_controller).toEqual(true);
        //         } else {
        //             expect(search_elem($scope.gridOptions.data, v._id).selected_statusreport_controller).not.toEqual(true);
        //         }
        //     });
        // });
        // it('when current page is 1 and filtering', function() {
        //     $scope.currentPage = 1;
        //     $scope.expression = {severity:"high"};
        //     $scope.$apply();
        //     $scope.checkAll();

        //     $scope.gridOptions.data.forEach(function(v) {
        //         if(v._id === "2.2.3.5" || v._id === "2.2.3.6" || v._id === "2.2.3.7" || v._id === "2.2.3.8" || v._id === "2.2.3.9") {
        //             expect(search_elem($scope.gridOptions.data, v._id).selected_statusreport_controller).toEqual(true);
        //         } else {
        //             expect(search_elem($scope.gridOptions.data, v._id).selected_statusreport_controller).not.toEqual(true);
        //         }
        //     });
        // });
        // it('when page size is the total of vulns', function() {
        //     $scope.currentPage = 0;
        //     $scope.pageSize = 20;
        //     $scope.expression = {severity:"high"};
        //     $scope.$apply();
        //     $scope.checkAll();

        //     $scope.gridOptions.data.forEach(function(v) {
        //         if(v._id.split(".")[0] === "2") {
        //             expect(search_elem($scope.gridOptions.data, v._id).selected_statusreport_controller).toEqual(true);
        //         } else {
        //             expect(search_elem($scope.gridOptions.data, v._id).selected_statusreport_controller).not.toEqual(true);
        //         }
        //     });
        // });
    });

});
