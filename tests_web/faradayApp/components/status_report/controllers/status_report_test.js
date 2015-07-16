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
    vuln1, vuln2, vuln3;

    var returnPromise;

    var fakeModal = {
        result: {
            then: function(confirmCallback, cancelCallback) {
                //Store the callbacks for later when the user clicks on the OK or Cancel button of the dialog
                this.confirmCallBack = confirmCallback;
                this.cancelCallback = cancelCallback;
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
                "owned": false,
                "severity": "med",
                "type": "Vulnerability",
                "owner": "john",
                "desc": "I'm scared!",
                "data": "",
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
                "owned": false,
                "severity": "med",
                "type": "Vulnerability",
                "owner": "john",
                "desc": "I'm scared!",
                "data": "",
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
                "name": "Service Detection",
                "obj_id": "008cba9b11897f2d52c53dd953d75fa233a7fffe",
                "owned": false,
                "owner": "",
                "parent": "6.7.8",
                "refs": [
                ],
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
                    vulnsManagerMock.vulns = [vuln1, vuln2, vuln3];
                    return returnPromise(true);
                },
                deleteVuln: function(workspace, vuln) {
                    if (vuln._id === "1.2.3.4" ||
                        vuln._id === "1.2.3.5" ||
                        vuln._id === "6.7.8.9") {
                        var vulns_tmp = [];
                        vulnsManagerMock.vulns.forEach(function(v) {
                            if (v._id != vuln._id) {
                                vulns_tmp.push(v);
                            }
                        });
                        vulnsManagerMock.vulns = vulns_tmp;
                        return returnPromise(true);
                    } else {
                        return rejectPromise("error");
                    }
                },
                createVuln: function(workspace, vuln) {
                    vuln["id"] = "1.2.3.6";
                    vulnsManagerMock.vulns.push(vuln);
                    return returnPromise(vuln);
                },
                updateVuln: function(workspace, vuln, vulnData) {
                    if (vuln._id === "1.2.3.4" ||
                        vuln._id === "1.2.3.5" ||
                        vuln._id === "6.7.8.9") {
                        angular.extend(vuln, vulnData);
                        return returnPromise(true);
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
                $modal: _$modal_
            });
        });
    });


    describe('Status report init function without filter', function() {
        it('vulns loaded after execution', function() {
            $scope.$apply();
            expect($scope.vulns.length).toEqual(3);
            expect($scope.vulns).toContain(vuln1);
            expect($scope.vulns).toContain(vuln2);
            expect($scope.vulns).toContain(vuln3);
        });
    });

    describe('Status report vuln deletion - remove method', function() {
        it('remove valid vuln id 1.2.3.4', function() {
            $scope.remove([vuln1]);
            $scope.$apply();

            expect($scope.vulns.length).toEqual(2);
            expect($scope.vulns).not.toContain(vuln1);
            expect($scope.vulns).toContain(vuln2);
            expect($scope.vulns).toContain(vuln3);
        });
        it('remove invalid vuln id 9.9.9.9', function() {
            vuln = {"_id": "9.9.9.9"}
            $scope.remove([vuln]);
            $scope.$apply();

            expect($scope.vulns.length).toEqual(3);
            expect($scope.vulns).toContain(vuln1);
            expect($scope.vulns).toContain(vuln2);
            expect($scope.vulns).toContain(vuln3);
        });
        it('remove valid id 1.2.3.4 and invalid id 9.9.9.9', function() {
            vuln = {"_id": "9.9.9.9"}
            $scope.remove([vuln1, vuln]);
            $scope.$apply();

            expect($scope.vulns.length).toEqual(2);
            expect($scope.vulns).not.toContain(vuln1);
            expect($scope.vulns).toContain(vuln2);
            expect($scope.vulns).toContain(vuln3);
        });
        it('remove valid vulns ids', function() {
            $scope.remove([vuln1, vuln2]);
            $scope.$apply();

            expect($scope.vulns.length).toEqual(1);
            expect($scope.vulns).not.toContain(vuln1);
            expect($scope.vulns).not.toContain(vuln2);
            expect($scope.vulns).toContain(vuln3);
        });
    });

    describe('Status report vuln deletion - delete method (modal)', function() {
        it('call delete with no vulns selected', function() {
            // we need $scope.vulns to have all the vulns before calling
            // the delete method
            $scope.$apply();
            $scope.delete();
            $scope.$apply();

            expect($scope.vulns.length).toEqual(3);
            expect($scope.vulns).toContain(vuln1);
            expect($scope.vulns).toContain(vuln2);
            expect($scope.vulns).toContain(vuln3);
        });
        it('call delete with a valid vuln (1.2.3.4) selected and accept modal', function() {
            // we need $scope.vulns to have all the vulns before calling
            // the delete method
            vuln1.selected = true;
            $scope.$apply();
            $scope.delete();
            fakeModal.close();
            $scope.$apply();

            expect($scope.vulns.length).toEqual(2);
            expect($scope.vulns).not.toContain(vuln1);
            expect($scope.vulns).toContain(vuln2);
            expect($scope.vulns).toContain(vuln3);
        });
        it('call delete with a valid vuln (1.2.3.4) selected and cancel modal', function() {
            // we need $scope.vulns to have all the vulns before calling
            // the delete method
            vuln1.selected = true;
            $scope.$apply();
            $scope.delete();
            fakeModal.dismiss();
            $scope.$apply();

            expect($scope.vulns.length).toEqual(3);
            expect($scope.vulns).toContain(vuln1);
            expect($scope.vulns).toContain(vuln2);
            expect($scope.vulns).toContain(vuln3);
        });
        it('call delete with valid vulns selected and accept modal', function() {
            vuln1.selected = true;
            vuln2.selected = true;
            $scope.$apply();
            $scope.delete();
            fakeModal.close();
            $scope.$apply();

            expect($scope.vulns.length).toEqual(1);
            expect($scope.vulns).not.toContain(vuln1);
            expect($scope.vulns).not.toContain(vuln2);
            expect($scope.vulns).toContain(vuln3);
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

            expect($scope.vulns.length).toEqual(4);
            expect($scope.vulns).toContain(vulnNew);
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

            expect($scope.vulns.length).toEqual(3);
            expect($scope.vulns).not.toContain(vulnNew);
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

            expect($scope.vulns.length).toEqual(4);
            expect($scope.vulns).toContain(vulnNew);
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

            expect($scope.vulns.length).toEqual(3);
            expect($scope.vulns).not.toContain(vulnNew);
        });
    });

    describe('Status report vuln edition - update method', function() {
        it('edit a valid vuln', function() {
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
            $scope.update([vuln1], vulnData);
            $scope.$apply();

            expect($scope.vulns.length).toEqual(3);
            $scope.vulns.forEach(function(vuln) {
                if (vuln._id == "1.2.3.4") {
                    expect(vuln.name).toEqual("Changed name");
                    expect(vuln.resolution).toEqual("New resolution");
                    expect(vuln.refs.length).toEqual(2);
                    expect(vuln.owned).toEqual(true);
                    expect(vuln.severity).toEqual("high");

                }
            });
        });
        it('edit two valid vulns', function() {
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
            $scope.update([vuln1, vuln2], vulnData);
            $scope.$apply();

            expect($scope.vulns.length).toEqual(3);
            $scope.vulns.forEach(function(vuln) {
                if (vuln._id == "1.2.3.4" || vuln._id == "1.2.3.5") {
                    expect(vuln.name).toEqual("Changed name");
                    expect(vuln.resolution).toEqual("New resolution");
                    expect(vuln.refs.length).toEqual(2);
                    expect(vuln.owned).toEqual(true);
                    expect(vuln.severity).toEqual("high");

                }
            });

        });
    });
    
    describe('Status report vuln edition - edit method (modal)', function() {
        it('edit two vulns and accept modal', function() {
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

            vuln1.selected = true;
            vuln2.selected = true;
            $scope.$apply();
            $scope.edit();
            fakeModal.close(vulnData);
            $scope.$apply();
            
            expect($scope.vulns.length).toEqual(3);
            $scope.vulns.forEach(function(vuln) {
                if (vuln._id == "1.2.3.4" || vuln._id == "1.2.3.5") {
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

            vuln1.selected = true;
            vuln2.selected = true;
            $scope.$apply();
            //$scope.edit();
            //fakeModal.dismiss();
            //$scope.$apply();
            
            expect($scope.vulns.length).toEqual(3);
            $scope.vulns.forEach(function(vuln) {
                if (vuln._id == "1.2.3.4" || vuln._id == "1.2.3.5") {
                    expect(vuln.name).not.toEqual("Changed name");
                    expect(vuln.resolution).not.toEqual("New resolution");
                    expect(vuln.refs.length).not.toEqual(2);
                    expect(vuln.owned).not.toEqual(true);
                    expect(vuln.severity).not.toEqual("high");

                }
            });
        });
    });
});
