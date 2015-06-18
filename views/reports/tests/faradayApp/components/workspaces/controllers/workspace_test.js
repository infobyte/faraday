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

        inject(function(_$rootScope_, _$controller_, $q){
            // The injector unwraps the underscores (_) from around the parameter names when matching
            $scope = _$rootScope_.$new();
            workspacesFactMock = {
                list: function(callback) {
                    var deferred = $q.defer();
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
            $controller = _$controller_('workspacesCtrl',
                    { $scope: $scope, workspacesFact: workspacesFactMock});
        });
    });


    describe('Workspaces load in $scope.wss', function() {
        it('tests if wss is loaded properly', function() {
            spyOn(workspacesFactMock, 'list').and.callThrough();
            $scope.init();
            expect(workspacesFactMock.list).toHaveBeenCalled();
            //expect($scope.workspaces.length).toEqual(2);
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

