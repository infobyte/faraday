describe('workspacesCtrl', function() {
    var $controller,
        $scope;

    var $workspacesFact,
    workspacesFactMock;

    beforeEach(function () { 
        workspacesFactMock = {
            get: function(callback) {
                callback(['ws1', 'ws2']);
            }
        };
        module('faradayApp');
        module(function($provide){
            $provide.value('workspacesFact', workspacesFactMock);
        });

        inject(function(_$rootScope_, _$controller_, _workspacesFact_){
            // The injector unwraps the underscores (_) from around the parameter names when matching
            $scope = _$rootScope_.$new();
            $controller = _$controller_('workspacesCtrl', { $scope: $scope, workspacesFact: _workspacesFact_});
        });
    });



    describe('$scope.wss', function() {
        it('tests if wss is loaded properly', function() {
            expect($scope.wss).toEqual(['ws1', 'ws2']);
        });
    });
});

