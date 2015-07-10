// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

describe('statusReportCtrl', function() {
    var $controller,
        $scope;

    // workspaces variables
    var vuln1 = {
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
    var vuln2 = {
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
    var vuln3 = {
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

    var $vulnsManager,
    vulnsManagerMock,
    $hostsManager,
    hostsManagerMock,
    $workspacesFact,
    workspacesFactMock;

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
                getVulns: function(workspace) {
                    return returnPromise([vuln1, vuln2, vuln3])
                },
                deleteVuln: function(workspace, id) {
                    if (id === "1.2.3.4" ||
                        id === "1.2.3.5" ||
                        id === "6.7.8.9") {
                        return returnPromise(true);
                    } else {
                        return rejectPromise("error");
                    }
                },
                createVuln: function(workspace, vuln) {
                    vuln["id"] = "1.2.3.6";
                    return returnPromise(vuln);
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
            $scope.remove(["1.2.3.4"]);
            $scope.$apply();

            expect($scope.vulns.length).toEqual(2);
            expect($scope.vulns).not.toContain(vuln1);
            expect($scope.vulns).toContain(vuln2);
            expect($scope.vulns).toContain(vuln3);
        });
        it('remove invalid vuln id 9.9.9.9', function() {
            $scope.remove(["9.9.9.9"]);
            $scope.$apply();

            expect($scope.vulns.length).toEqual(3);
            expect($scope.vulns).toContain(vuln1);
            expect($scope.vulns).toContain(vuln2);
            expect($scope.vulns).toContain(vuln3);
        });
        it('remove valid id 1.2.3.4 and invalid id 9.9.9.9', function() {
            $scope.remove(["1.2.3.4", "9.9.9.9"]);
            $scope.$apply();

            expect($scope.vulns.length).toEqual(2);
            expect($scope.vulns).not.toContain(vuln1);
            expect($scope.vulns).toContain(vuln2);
            expect($scope.vulns).toContain(vuln3);
        });
        it('remove valid vulns ids', function() {
            $scope.remove(["1.2.3.4", "1.2.3.5"]);
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

    // describe('Workspace update function', function() {
    //     beforeEach(function() {
    //         spyOn(workspacesFactMock, 'update').and.callThrough();
    //     });
    //     it('variables changed after execution of onSuccessEdit function', function() {
    //         $scope.workspaces = [{
    //             "_id": "ws2",
    //             "_rev": "2-bd88abf79cf2b7e8b419cd4387c64bef",
    //             "children": [],
    //             "customer": "",
    //             "description": "Testing Workspace",
    //             "duration": {
    //                 "start": 1410832741.48194,
    //                 "end": 1410832741.48194
    //             },
    //             "name": "ws2",
    //             "scope": "",
    //             "sdate": 1410832741.48194,
    //             "selected": true,
    //             "type": "Workspace",
    //         }];
    //         var tmp_ws2_modified = {
    //             "_id": "ws2",
    //             "_rev": "10-bd88abf79cf2b7e8b419cd4387c64bef",
    //             "children": [],
    //             "customer": "",
    //             "description": "Nuevo",
    //             "duration": {
    //                 "start": 141083274148194,
    //                 "end": 141083274148194
    //             },
    //             "name": "ws2",
    //             "sdate": 1410832741.48194,
    //             "scope": "",
    //             "selected": true,
    //             "type": "Workspace",
    //         };
    //         $scope.onSuccessEdit(tmp_ws2_modified);
    //         $scope.$apply();
    //         expect($scope.workspaces[0].description).toEqual("Nuevo");
    //         expect($scope.workspaces[0]._rev).toEqual("10-bd88abf79cf2b7e8b419cd4387c64bef");
    //         expect($scope.workspaces[0].duration.start).toEqual(141083274148194);
    //         expect($scope.workspaces[0].duration.end).toEqual(141083274148194);
    //     });
    //     it('variables are defined after execution of update function', function() {

    //         $scope.update(tmp_ws2);
    //         $scope.$apply();
    //         expect(workspacesFactMock.update).toHaveBeenCalled();

    //         expect(workspace._id).toBeDefined();
    //         expect(workspace._rev).toBeDefined();
    //         expect(workspace.children).toBeDefined();
    //         expect(workspace.customer).toBeDefined();
    //         expect(workspace.description).toBeDefined();
    //         expect(workspace.duration.start).toBeDefined();
    //         expect(workspace.duration.end).toBeDefined();
    //         expect(workspace.name).toBeDefined();
    //         expect(workspace.sdate).toBeDefined();
    //         expect(workspace.scope).toBeDefined();
    //         expect(workspace.selected).toBeDefined();
    //         expect(workspace.type).toBeDefined();
    //     });
    //     it('the object that comes to the update function it is the same as is sended to update Mock', function() {
    //         $scope.update(tmp_ws2);
    //         $scope.$apply();
    //         expect(workspacesFactMock.update).toHaveBeenCalled();

    //         expect(workspace._id).toEqual(tmp_ws2._id);
    //         expect(workspace._rev).toEqual(tmp_ws2._rev);
    //         expect(workspace.children).toEqual(tmp_ws2.children);
    //         expect(workspace.customer).toEqual(tmp_ws2.customer);
    //         expect(workspace.description).toEqual(tmp_ws2.description);
    //         expect(workspace.duration.start).toEqual(tmp_ws2.duration.startDate);
    //         expect(workspace.duration.end).toEqual(tmp_ws2.duration.endDate);
    //         expect(workspace.name).toEqual(tmp_ws2.name);
    //         expect(workspace.sdate).toEqual(tmp_ws2.sdate);
    //         expect(workspace.scope).toEqual(tmp_ws2.scope);
    //         expect(workspace.selected).toEqual(tmp_ws2.selected);
    //         expect(workspace.type).toEqual(tmp_ws2.type);

    //         expect(typeof(start)).not.toEqual("object");
    //         expect(typeof(end)).not.toEqual("object");

    //     });
    // });


});
