describe('workspacesFact', function() {
    var $httpBackend, createFactory; 

    // Set up the module
    beforeEach(module('faradayApp'));

    beforeEach(inject(function($injector) {
        // Set up the mock http service responses
        $httpBackend = $injector.get('$httpBackend');
        var $workspacesFact = $injector.get('workspacesFact');

        createFactory = function() {
            return $injector.get('workspacesFact', {'BASEURL' : 'http://localhost:9876/',
                                    '$http': $httpBackend});
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

       it('Tests if existence is well asked', function() {
           $httpBackend.when('HEAD', 'http://localhost:9876/tuvieja')
                                           .respond(200, '');

           $httpBackend.expectHEAD('http://localhost:9876/tuvieja');
           fact = createFactory();
           fact.exists('tuvieja');
           $httpBackend.flush();
       });
   }); 

});
