// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

describe('workspacesFact', function() {
    var $httpBackend, createFactory;

    // Set up the module
    beforeEach(module('faradayApp'));

    beforeEach(inject(function($injector) {
        // Set up the mock http service responses
        $httpBackend = $injector.get('$httpBackend');
        var $workspacesFact = $injector.get('workspacesFact');

        createFactory = function() {
            return $injector.get('workspacesFact', {'BASEURL' : 'http://localhost:9876/_api/',
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
           $httpBackend.when('HEAD', 'http://localhost:9876/_api/ws/test_workspace')
                                           .respond(200, '');

           $httpBackend.expectHEAD('http://localhost:9876/_api/ws/test_workspace');
           fact = createFactory();
           fact.exists('test_workspace').then(function(exist){
	           expect(exist).toBe(true);
           });
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

           var object = {
            _attachments:
              { views:
                {"content_type": "application/javascript"}
              }
           };

           $httpBackend.expectPUT('http://localhost:9876/_api/ws/test_workspace',
                   workspace).respond(200, {"ok": true});

           $httpBackend.expectPUT('http://localhost:9876/_api/ws/test_workspace/test_workspace',
                   workspace).respond(200, {"ok": true});

           $httpBackend.expectGET('http://localhost:9876/_api/ws/reports/_design/reports').respond(200, object);

           $httpBackend.expectPOST('http://localhost:9876/_api/ws/test_workspace/_bulk_docs',
                   {'docs': []}).respond(200, {"ok": true});

           $httpBackend.when('HEAD', 'http://localhost:9876/_api/ws/test_workspace')
                                           .respond(200, '');

           fact = createFactory();

           fact.put(workspace);
           fact.exists('test_workspace').then(function(exist){
             expect(exist).toBe(true);
           });
           $httpBackend.flush();
       });

       it('Tests if OK Delete are well done', function() {
           $httpBackend.expectDELETE('http://localhost:9876/_api/ws/test_workspace').
               respond(200, {"ok": true});

           fact = createFactory();

           fact.delete('test_workspace').then(function(resp) {
            expect(resp).toBe('test_workspace');
           });
           $httpBackend.flush();
       });
   });

});
