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
           workspace_exists = fact.exists('tuvieja');
           expect(workspace_exists).toBe(true);
           $httpBackend.flush();
       });

       it('Tests if OK Inserts are well done', function() {

           var workspace =  {
               "_id": "test_workspace",
               "customer": "",
               "sdate": 1415901244.040532,
               "name": "test_workspace",
               "fdate": 1415901244.040532,
               "type": "Workspace",
               "children": [
               ],
               "description": ""
           };

           $httpBackend.expectPUT('http://localhost:9876/test_workspace',
                   workspace).respond(200, {"ok": true});

           fact = createFactory();
           var workspace_exists = false;
           onSuccess = function(){ workspace_exists = true;};

           workspace_exists = fact.put(workspace, onSuccess); 
           $httpBackend.flush();
           expect(workspace_exists).toBe(true);
       });
   }); 

});
