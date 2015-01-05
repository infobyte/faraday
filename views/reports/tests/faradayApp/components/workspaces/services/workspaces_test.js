describe('workspacesFact', function() {
    var $httpBackend, createFactory; 

    // Set up the module
    beforeEach(module('faradayApp'));

    beforeEach(inject(function($injector) {
        // Set up the mock http service responses
        $httpBackend = $injector.get('$httpBackend');
        var $workspacesFact = $injector.get('workspacesFact');

        createFactory = function() {
            return $('workspacesFact', {'BASEURL' : 'http://localhost:5984/'});
        };
    }));


   afterEach(function() {
     $httpBackend.verifyNoOutstandingExpectation();
     $httpBackend.verifyNoOutstandingRequest();
   });

   describe('Workspaces Service CRUD', function() {
       it('Tests if factory is well created', function() {
           fact = createFactory(); 
       });
   }); 

});
