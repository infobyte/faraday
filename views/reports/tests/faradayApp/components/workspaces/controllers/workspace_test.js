describe('workspacesCtrl', function() {
    var $controller,
        $scope;

    var workspaceFact,
    workspaceFactMock;

    beforeEach(function () { 
        workspaceFactMock = {
            get: function(callback) {
                return ['ws1', 'ws2'];
            }
        };
        module('faradayApp');
        module(function($provide){
            $provide.factory('workspacesFact', workspaceFactMock);
        });

        inject(function(_$rootScope_, _$controller_){
            // The injector unwraps the underscores (_) from around the parameter names when matching
            $scope = _$rootScope_.$new();
            $controller = _$controller_('workspacesCtrl', { $scope: $scope,
                workspacesFact: workspaceFactMock});
        });
    });


    // beforeEach(
    //     module('workspacesCtrl', function ($provide) {
    //         $provide.value('workspacesFact', mockWorkspaceFact);
    //     });


    describe('$scope.wss', function() {
        it('tests if wss is loaded properly', function() {
            expect($scope.wss).toEqual(['ws1', 'ws2']);
        });
    });
});

