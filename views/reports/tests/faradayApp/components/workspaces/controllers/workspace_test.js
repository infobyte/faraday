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
                get: function(workspace_name, onSuccess){
                    workspace = {
                        "_id": workspace_name,
                        "_rev": "2-bd88abf79cf2b7e8b419cd4387c64bef",
                        "customer": "",
                        "sdate": 1410832741.48194,
                        "name": workspace_name,
                        "fdate": 1410832741.48194,
                        "type": "Workspace",
                        "children": [
                        ],
                        "description": ""
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
        });
        it('ok 1111tests if wss is loaded properly', function() {
            $scope.init();
            $scope.$apply();
            expect(workspacesFactMock.list).toHaveBeenCalled();
            expect(workspacesFactMock.put).not.toHaveBeenCalled();
            expect(dashboardSrvMock.getObjectsCount).toHaveBeenCalled();
            expect($scope.wss).toEqual(['ws1', 'ws2']);
        });
        it('lala', function() {
            expect($scope.wss).toEqual([]);
            $scope.init();
            $scope.$apply();
            expect($scope.wss).not.toEqual([]);
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

