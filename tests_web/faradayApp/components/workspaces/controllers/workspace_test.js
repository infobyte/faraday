// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

describe('workspacesCtrl', function() {
    var $controller,
        $scope;

    // workspaces variables
    var tmp_ws1 = {
        "_id": "ws1",
        "_rev": "2-bd88abf79cf2b7e8b419cd4387c64bef",
        "children": [],
        "customer": "",
        "description": "Testing Workspaces",
        "duration": {
            "start": 1410832741.48194,
            "end": 1410832741.48194
        },
        "name": "ws1",
        "sdate": 1410832741.48194,
        "scope": "",
        "selected": true,
        "type": "Workspace"
    };
    var tmp_ws2 = {
        "_id": "ws2",
        "_rev": "10-bd88abf79cf2b7e8b419cd4387c64bef",
        "children": [],
        "customer": "",
        "description": "Nuevo",
        "duration": {
            "startDate": 141083274148194,
            "endDate": 141083274148194
        },
        "name": "ws2",
        "sdate": 1410832741.48194,
        "scope": "",
        "selected": true,
        "type": "Workspace",
    };
    var tmp_ws3 = {
        "_id": "ws3",
        "_rev": "2-bd88abf79cf2b7e8b419cd4387c64bef",
        "children": [],
        "customer": "",
        "description": "Testing Workspaces",
        "duration": {
            "start": 1410832741.48194,
            "end": 1410832741.48194
        },
        "name": "ws3",
        "sdate": 1410832741.48194,
        "scope": "",
        "selected": true,
        "type": "Workspace"
    };

    var $workspacesFact,
    workspacesFactMock;

    beforeEach(function () {
        module('faradayApp');

        inject(function(_$rootScope_, _$controller_, _$q_) {
            // The injector unwraps the underscores (_) from around the parameter names when matching
            $scope = _$rootScope_.$new();

            dashboardSrvMock = {
                getObjectsCount: function(ws) {
                    var deferred = _$q_.defer();
                    deferred.resolve([
                        {"key":"hosts","value":2},
                        {"key":"interfaces","value":2},
                        {"key":"services","value":1},
                        {"key":"total vulns","value":3},
                        {"key":"vulns","value":1},
                        {"key":"web vulns","value":2}
                    ]);
                    return deferred.promise;
                }
            };
            workspacesFactMock = {
                list: function(callback) {
                    var deferred = _$q_.defer();
                    deferred.resolve(['ws1', 'ws2']);
                    return deferred.promise;
                },
                update: function(workspace) {
                    var deferred = _$q_.defer();
                    deferred.resolve({"data":{"ok":"true", "id":"ws1", "rev":"36-e56619bfa3a9ee9b09650d3fc8878d2c"}});
                    return deferred.promise;
                },
                get: function(workspace_name){
                    var objs = {
                        "ws1" : tmp_ws1,
                        "ws2" : tmp_ws2
                    };
                    var deferred = _$q_.defer();
                    deferred.resolve(objs[workspace_name]);
                    return deferred.promise;
                },
                put: function(workspace) {
                    var deferred = _$q_.defer();
                    deferred.resolve("");
                    return deferred.promise;
                },
                delete: function(workspace_name) {
                    var deferred = _$q_.defer();
                    deferred.resolve(workspace_name);
                    return deferred.promise;
                },
                exists: function(workspace_name){
                    return false;
                }

            };

            $controller = _$controller_('workspacesCtrl', {
                $scope: $scope,
                dashboardSrv: dashboardSrvMock,
                workspacesFact: workspacesFactMock
            });
        });
    });


    describe('Workspaces init function', function() {
        beforeEach(function() {
            spyOn(workspacesFactMock, 'get').and.callThrough();
        });
        it('variables are defined after execution', function() {
            $scope.$apply();
            expect($scope.wss).toBeDefined();
            expect($scope.objects).toBeDefined();
            expect($scope.workspaces).toBeDefined();
            expect($scope.minDate).toBeDefined();
            expect($scope.dateOptions).toBeDefined();
            expect($scope.hash).toBeDefined();
        });
        it('variables have proper values after execution', function() {
            $scope.$apply();
            expect($scope.wss).toEqual(['ws1', 'ws2']);
            expect($scope.objects).not.toEqual({});
            expect($scope.workspaces).not.toEqual([]);
            expect($scope.minDate).not.toEqual({});
            expect($scope.dateOptions).not.toEqual({});
            expect($scope.hash).not.toEqual(null);
            expect(workspacesFactMock.get).toHaveBeenCalled();
            $scope.workspaces.forEach(function(ws){
                expect(ws.selected).toEqual(false);
            });
            expect($scope.workspaces.length).toEqual(2);
            expect($scope.workspaces).toContain(tmp_ws1);
            expect($scope.workspaces).toContain(tmp_ws2);
        });
    });

    describe('Workspace update function', function() {
        beforeEach(function() {
            spyOn(workspacesFactMock, 'update').and.callThrough();
        });
        it('variables changed after execution of onSuccessEdit function', function() {
            $scope.workspaces = [{
                "_id": "ws2",
                "_rev": "2-bd88abf79cf2b7e8b419cd4387c64bef",
                "children": [],
                "customer": "",
                "description": "Testing Workspace",
                "duration": {
                    "start": 1410832741.48194,
                    "end": 1410832741.48194
                },
                "name": "ws2",
                "scope": "",
                "sdate": 1410832741.48194,
                "selected": true,
                "type": "Workspace",
            }];
            var tmp_ws2_modified = {
                "_id": "ws2",
                "_rev": "10-bd88abf79cf2b7e8b419cd4387c64bef",
                "children": [],
                "customer": "",
                "description": "Nuevo",
                "duration": {
                    "start": 141083274148194,
                    "end": 141083274148194
                },
                "name": "ws2",
                "sdate": 1410832741.48194,
                "scope": "",
                "selected": true,
                "type": "Workspace",
            };
            $scope.onSuccessEdit(tmp_ws2_modified);
            $scope.$apply();
            expect($scope.workspaces[0].description).toEqual("Nuevo");
            expect($scope.workspaces[0]._rev).toEqual("10-bd88abf79cf2b7e8b419cd4387c64bef");
            expect($scope.workspaces[0].duration.start).toEqual(141083274148194);
            expect($scope.workspaces[0].duration.end).toEqual(141083274148194);
        });
        it('variables are defined after execution of update function', function() {

            $scope.update(tmp_ws2);
            $scope.$apply();
            expect(workspacesFactMock.update).toHaveBeenCalled();

            expect(workspace._id).toBeDefined();
            expect(workspace._rev).toBeDefined();
            expect(workspace.children).toBeDefined();
            expect(workspace.customer).toBeDefined();
            expect(workspace.description).toBeDefined();
            expect(workspace.duration.start).toBeDefined();
            expect(workspace.duration.end).toBeDefined();
            expect(workspace.name).toBeDefined();
            expect(workspace.sdate).toBeDefined();
            expect(workspace.scope).toBeDefined();
            expect(workspace.selected).toBeDefined();
            expect(workspace.type).toBeDefined();
        });
        it('the object that comes to the update function it is the same as is sended to update Mock', function() {
            $scope.update(tmp_ws2);
            $scope.$apply();
            expect(workspacesFactMock.update).toHaveBeenCalled();

            expect(workspace._id).toEqual(tmp_ws2._id);
            expect(workspace._rev).toEqual(tmp_ws2._rev);
            expect(workspace.children).toEqual(tmp_ws2.children);
            expect(workspace.customer).toEqual(tmp_ws2.customer);
            expect(workspace.description).toEqual(tmp_ws2.description);
            expect(workspace.duration.start).toEqual(tmp_ws2.duration.startDate);
            expect(workspace.duration.end).toEqual(tmp_ws2.duration.endDate);
            expect(workspace.name).toEqual(tmp_ws2.name);
            expect(workspace.sdate).toEqual(tmp_ws2.sdate);
            expect(workspace.scope).toEqual(tmp_ws2.scope);
            expect(workspace.selected).toEqual(tmp_ws2.selected);
            expect(workspace.type).toEqual(tmp_ws2.type);

            expect(typeof(start)).not.toEqual("object");
            expect(typeof(end)).not.toEqual("object");

        });
    });

    describe('Workspaces inserts in $scope.wss', function() {
        beforeEach(function() {
            spyOn(workspacesFactMock, 'put').and.callThrough();
            spyOn($scope, 'onSuccessInsert').and.callThrough();
        });
        it('if put Mock is called after execution of insert function', function() {
            $scope.insert(tmp_ws1);
            $scope.$apply();

            expect(workspacesFactMock.put).toHaveBeenCalledWith(tmp_ws1);
            expect($scope.onSuccessInsert).toHaveBeenCalledWith(tmp_ws1);
        });
        it('variables update properly after execution of onSuccessInsert function', function() {
            // define wss after execution
            // if it is not defined, push to $scope.wss fails
            $scope.wss = [];
            $scope.$apply();
            $scope.onSuccessInsert(tmp_ws3);
            $scope.$apply();

            expect($scope.wss).toContain(tmp_ws3.name);
            expect($scope.workspaces).toContain(tmp_ws3);
        });
    });

    describe('Workspaces object creation', function() {
        it('tests if workspaces create object is consistent', function() {
            var date = new Date();
            workspace = $scope.create('wname','wdesc', date, date, '');
            $scope.$apply();

            expect(workspace._id).toBeDefined();
            expect(workspace._rev).toBeDefined();
            expect(workspace.customer).toBeDefined();
            expect(workspace.sdate).toBeDefined();
            expect(workspace.name).toBeDefined();
            // find out if this variable is being used
            // is defined as undefined
            expect(workspace.fdate).toBeUndefined();

            expect(workspace.type).toBeDefined();
            expect(workspace.children).toBeDefined();
            expect(workspace.duration.start).toBeDefined();
            expect(workspace.duration.end).toBeDefined();
            expect(workspace.scope).toBeDefined();
            expect(workspace.description).toBeDefined();

            expect(workspace.name).toEqual('wname');
            expect(workspace._id).toEqual('wname');
            expect(workspace.description).toEqual('wdesc');
            expect(workspace.duration.start).toEqual(date.getTime());
            expect(workspace.duration.end).toEqual(date.getTime());
            expect(workspace.scope).toEqual('');
        });
    });

    describe('Workspaces removal properly', function() {
        beforeEach(function() {
            spyOn(workspacesFactMock, 'delete').and.callThrough();
        });
        it('tests if workspaces in scope.wss are removed after execution of remove function', function() {
            $scope.remove('ws1');
            $scope.$apply();

            expect(workspacesFactMock.delete).toHaveBeenCalled();
            expect($scope.wss).not.toContain('ws1');
        });
        it('tests if workspaces in scope.workspaces are removed after execution of onSuccessDelete function', function() {
            $scope.onSuccessGet(tmp_ws3);
            $scope.$apply();
            $scope.onSuccessDelete('ws1');
            $scope.$apply();

            expect($scope.workspaces).not.toContain(tmp_ws1);
        });
    });

});
