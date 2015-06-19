// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

describe('workspacesCtrl', function() {
    var $controller,
        $scope;

    var $workspacesFact,
    workspacesFactMock;

    var spyOnPutFactory;

    spyOnPutFactory = jasmine.createSpy('Put Workspace Factory Spy');
    spyOnDeleteFactory = jasmine.createSpy('Delete Workspace Factory Spy'); 
    spyOnExistsFactory = jasmine.createSpy('Delete Workspace Factory Spy');
    spyOnExistsFactory('test_workspace', function(){
        return false;
    });
            
    

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
                update: function(workspace, onSuccess) {
                    var deferred = _$q_.defer();
                    deferred.resolve({"data":{"ok":"true", "id":"ws1", "rev":"36-e56619bfa3a9ee9b09650d3fc8878d2c"}});
                    return deferred.promise.success(function(data){
                        workspace._rev = data.rev;
                        onSuccess(workspace);
                    });
                    //workspacesFact.update(workspace, $scope.onSuccessEdit);
                },
                // onSuccessEdit: function(workspace) {
                //     for(var i = 0; i < $scope.workspaces.length; i++) {
                //         if($scope.workspaces[i].name == workspace.name){
                //             $scope.workspaces[i]._rev = workspace._rev;
                //             $scope.workspaces[i].description = workspace.description;
                //             $scope.workspaces[i].duration.start = workspace.duration.start;
                //             $scope.workspaces[i].duration.end = workspace.duration.end;
                //             break;
                //         }
                //     };
                // },
                get: function(workspace_name, onSuccess){
                    workspace = {
                        "_id": workspace_name,
                        "_rev": "2-bd88abf79cf2b7e8b419cd4387c64bef",
                        "children": [],
                        "customer": "",
                        "description": "Testing Workspaces",
                        "duration": {
                            "start": 1410832741.48194,
                            "end": 1410832741.48194
                        },
                        "name": workspace_name,
                        "sdate": 1410832741.48194,
                        "selected": true,
                        "type": "Workspace",
                    };
                    onSuccess(workspace);
                },
                put: spyOnPutFactory,
                delete: function(workspace, onSuccess) {
                        onSuccess(workspace);
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
            spyOn(workspacesFactMock, 'list').and.callThrough();
            spyOn(dashboardSrvMock, 'getObjectsCount').and.callThrough();
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
        });
        it('testing onSuccessGet', function() {
            var workspace = {
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
                "selected": true,
                "type": "Workspace",
            };
            $scope.onSuccessGet(workspace);
            $scope.$apply();
            expect(workspacesFactMock.get).toHaveBeenCalled();
            // falta testear si tiene puntos el date
            expect(workspace.selected).toEqual(false);
            expect($scope.workspaces.length).toEqual(3);
        });
    });

    describe('Workspace update', function() {
        beforeEach(function() {
            spyOn(workspacesFactMock, 'update').and.callThrough();
        });
        it('testing onSuccessEdit', function() {
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
            var workspace = {
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
                "selected": true,
                "type": "Workspace",
            };
            $scope.onSuccessEdit(workspace);
            $scope.$apply();
            expect($scope.workspaces[0].description).toEqual("Nuevo");
            expect($scope.workspaces[0]._rev).toEqual("10-bd88abf79cf2b7e8b419cd4387c64bef");
            expect($scope.workspaces[0].duration.start).toEqual(141083274148194);
            expect($scope.workspaces[0].duration.end).toEqual(141083274148194);
        });
        it('tests if update works', function() {
            var workspace = {
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
                "selected": true,
                "type": "Workspace",
            };
            $scope.update(workspace);
            $scope.$apply();
            expect(workspacesFactMock.update).toHaveBeenCalled();
        });
    });

    // describe('Workspaces inserts in $scope.wss', function() { 
    //     it('tests if duplicated inserts are avoided', function() {
    //         // Replace the mock exists function
    //         // to return that the workspace 'tuvieja' exists
    //         workspacesFactMock.exists = function(workspace_name){ return true;};
    //         workspace_name = 'tuvieja';
    //         workspace = {
    //             "_id": workspace_name,
    //             "_rev": "2-bd88abf79cf2b7e8b419cd4387c64bef",
    //             "customer": "",
    //             "sdate": 1410832741.48194,
    //             "name": workspace_name,
    //             "fdate": 1410832741.48194,
    //             "type": "Workspace",
    //             "children": [
    //             ],
    //             "description": ""
    //         };
    //         $scope.insert(workspace);

    //         expect($scope.wss).not.toContain(workspace_name);
    //         expect($scope.wss.length).toEqual(2);
    //         expect(spyOnPutFactory).not.toHaveBeenCalledWith(workspace);
    //     });
    //     it('tests if wss is updated properly', function() {
    //         workspace_name = 'test_workspace';
    //         workspace = {
    //             "_id": workspace_name,
    //             "_rev": "2-bd88abf79cf2b7e8b419cd4387c64bef",
    //             "customer": "",
    //             "sdate": 1410832741.48194,
    //             "name": workspace_name,
    //             "fdate": 1410832741.48194,
    //             "type": "Workspace",
    //             "children": [
    //             ],
    //             "description": ""
    //         };
    //         $scope.insert(workspace);

    //         // http://jasmine.github.io/1.3/introduction.html#section-Matchers
    //         expect(spyOnPutFactory).toHaveBeenCalledWith(workspace, $scope.onSuccessInsert);
    //    });
    // });
    // describe('Workspaces removal in $scope.wss', function() { 
    //     it('tests if workspaces in scope.wss are removed ', function() {

    //         $scope.remove('ws1');
    //         expect($scope.wss).not.toContain('ws1');
    //         expect($scope.workspaces['ws1']).not.toBeDefined(); 
    //     });
    // });

    // describe('Workspaces object creation ', function() { 
    //     it('tests if workspaces create object is consistent', function() {
    //         workspace = $scope.create('wname','wdesc');
    //         workspace_properties = Object.keys(workspace);
    //         expect(workspace_properties).toContain('_id');
    //         expect(workspace_properties).toContain('name');
    //         expect(workspace_properties).toContain('description');
    //         expect(workspace_properties).toContain('customer');
    //         expect(workspace_properties).toContain('sdate');
    //         expect(workspace_properties).toContain('fdate');
    //         expect(workspace_properties).toContain('type');
    //         expect(workspace_properties).toContain('children');

    //         expect(workspace.name).toEqual('wname');
    //         expect(workspace._id).toEqual('wname');
    //         expect(workspace.description).toEqual('wdesc'); 
    //     });
    // });
});

