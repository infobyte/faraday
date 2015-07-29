// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

describe('vulnsManager', function() {
    var vulnsManager,
    Vuln,
    WebVuln,
    $filter,
    $httpBackend,
    $q,
    BASEURL,
    vuln1;

    // Set up the module
    beforeEach(module('faradayApp'));

    beforeEach(inject(function($injector, _vulnsManager_, _Vuln_, _WebVuln_) {
        $filter = $injector.get('$filter');
        $httpBackend = $injector.get('$httpBackend');
        $q = $injector.get('$q');
        $rootScope = $injector.get('$rootScope');
        vulnsManager = _vulnsManager_;
        Vuln = _Vuln_;
        WebVuln = _WebVuln_;
        BASEURL = 'http://localhost:9876/'; 

        vuln1 = {
            "_id": "1.2.3.e29ba38bfa81e7f9050f6517babc14cf32cacdff",
            "_rev": "1-abe16726389e434ca3f37384ea76128e",
            "desc": "I'm scared!",
            "data": "",
            "metadata": {
               "update_time": 1429643049.395857,
               "update_user": "john",
               "update_action": 0,
               "creator": "john",
               "create_time": 1429643049.395857,
               "update_controller_action": "ModelControler.newVuln",
               "owner": "john"
            },
            "name": "Internet Key Exchange (IKE) Aggressive Mode with Pre-Shared Key",
            "owned": false,
            "owner": "john",
            "parent": "1.2.3",
            "resolution": "Be careful",
            "refs": [
               "CVE-2002-1623",
               "7423",
               "OSVDB:3820, CERT:886601"
            ],
            "severity": "med",
            "type": "Vulnerability",
            "ws": "ws"
        };
    }));

    afterEach(function() {
        $httpBackend.verifyNoOutstandingExpectation();
        $httpBackend.verifyNoOutstandingRequest();
    });

    describe('Basic usage', function() {
        it('getVulns', function() {
            var resp = {
                "total_rows":1,
                "offset":0,
                "rows":[
                    {
                        "id": "1.2.3.8b4ffaedb84dd60d5f43c58eba66a7651458c8de",
                        "key":"4b84b15bff6ee5796152495a230e45e3d7e947d9.34ac3ea37a2854ce00f2d97c648bf3a7cc27ebca",
                        "value": vuln1
                    }
                ]
            };

            var vulns;

            $httpBackend.expect('GET', BASEURL + 'ws/_design/vulns/_view/all').respond(200, resp);

            vulnsManager.getVulns("ws").then(function(vs) {
                vulns = vs;
            });

            $httpBackend.flush();

            expect(vulns.length).toEqual(1);
            expect(vulns[0]._id).toEqual(vuln1._id);
        });

        it('createVuln', function() {
            var id = vuln1._id,
            vuln = vuln1;
            delete vuln._id;
            delete vuln._rev;

            var resp = {
                "total_rows":1,
                "offset":0,
                "rows":[
                    {
                        "id": "1.2.3.8b4ffaedb84dd60d5f43c58eba66a7651458c8de",
                        "key":"4b84b15bff6ee5796152495a230e45e3d7e947d9.34ac3ea37a2854ce00f2d97c648bf3a7cc27ebca",
                        "value": vuln1
                    }
                ]
            };

            var vulns = [];

            // insert new vuln in Couch
            $httpBackend.expect('PUT', BASEURL + "ws/" + id).respond(201, {"rev": "1234"});
            // getVulns
            $httpBackend.expect('GET', BASEURL + 'ws/_design/vulns/_view/all').respond(200, resp);

            var lala = vulnsManager.createVuln("ws", vuln);

            $httpBackend.flush();
            $rootScope.$apply();

            expect(vulns.length).toEqual(1);
            expect(vulns[0]._id).toEqual(id);
        });

        it('deleteVuln', function() {
            var id = vuln1._id;
            var vuln = angular.copy(vuln1);
            delete vuln._id;
            delete vuln._rev;

            var respInsert = {
                "total_rows":1,
                "offset":0,
                "rows":[
                    {
                        "id": "1.2.3.8b4ffaedb84dd60d5f43c58eba66a7651458c8de",
                        "key":"4b84b15bff6ee5796152495a230e45e3d7e947d9.34ac3ea37a2854ce00f2d97c648bf3a7cc27ebca",
                        "value": vuln1
                    }
                ]
            };

            var respDelete = {
                "total_rows":0,
                "offset":0,
                "rows":[]
            };

            // insert new vuln in Couch
            $httpBackend.expect('PUT', BASEURL + "ws/" + id).respond(201, {"rev": vuln1._rev});
            // getVulns
            $httpBackend.expect('GET', BASEURL + 'ws/_design/vulns/_view/all').respond(200, respInsert);

            vulnsManager.createVuln("ws", vuln);

            $httpBackend.flush();

            // delete vuln
            $httpBackend.expect('DELETE', BASEURL + 'ws/' + id + "?rev=" + vuln1._rev).respond(200);
            // getVulns
            $httpBackend.expect('GET', BASEURL + 'ws/_design/vulns/_view/all').respond(200, respDelete);
            
            vulnsManager.deleteVuln("ws", vulnsManager.vulns[0]);
            $httpBackend.flush();

            expect(vulnsManager.vulns.length).toEqual(0);
        });

        it('updateVuln', function() {
            var id = vuln1._id;
            var vuln = angular.copy(vuln1);
            delete vuln._id;
            delete vuln._rev;

            var vulnMod = {
                "_id": "1.2.3.e29ba38bfa81e7f9050f6517babc14cf32cacdff",
                "_rev": "1-abe16726389e434ca3f37384ea76128e",
                "desc": "Hello World!",
                "data": "",
                "metadata": {
                   "update_time": 1429643049.395857,
                   "update_user": "",
                   "update_action": 0,
                   "creator": "UI Web",
                   "create_time": 1429643049.395857,
                   "update_controller_action": "ModelControler.newVuln",
                   "owner": ""
                },
                "name": "Something something dark side",
                "owned": false,
                "owner": "",
                "parent": "1.2.3",
                "resolution": "Be careful",
                "refs": [
                   "CVE-2002-1623",
                   "7423",
                   "OSVDB:3820, CERT:886601"
                ],
                "severity": "med",
                "type": "Vulnerability",
                "ws": "ws"
            };

            var respInsert = {
                "total_rows":1,
                "offset":0,
                "rows":[
                    {
                        "id": "1.2.3.8b4ffaedb84dd60d5f43c58eba66a7651458c8de",
                        "key":"4b84b15bff6ee5796152495a230e45e3d7e947d9.34ac3ea37a2854ce00f2d97c648bf3a7cc27ebca",
                        "value": vuln1
                    }
                ]
            };

            var respUpdate = {
                "total_rows":1,
                "offset":0,
                "rows":[
                    {
                        "id": "1.2.3.8b4ffaedb84dd60d5f43c58eba66a7651458c8de",
                        "key":"4b84b15bff6ee5796152495a230e45e3d7e947d9.34ac3ea37a2854ce00f2d97c648bf3a7cc27ebca",
                        "value": vulnMod
                    }
                ]
            };

            // insert new vuln in Couch
            $httpBackend.expect('PUT', BASEURL + "ws/" + id).respond(201, {"rev": "1234"});
            // getVulns
            $httpBackend.expect('GET', BASEURL + 'ws/_design/vulns/_view/all').respond(200, respInsert);
            // call to insert
            vulnsManager.createVuln("ws", vuln);
            $httpBackend.flush();

            // update vuln
            $httpBackend.expect('PUT', BASEURL + 'ws/' + id).respond(200, {"rev": "2345"});
            // getVulns
            $httpBackend.expect('GET', BASEURL + 'ws/_design/vulns/_view/all').respond(200, respUpdate);
            
            var vulns = vulnsManager.updateVuln(vuln.ws, vulnsManager.vulns[0], vulnMod);
            $httpBackend.flush();

            expect(vulnsManager.vulns.length).toEqual(1);

            for(var prop in vulnMod) {
                if(vulnMod.hasOwnProperty(prop)) {
                    if(prop != "metadata") expect(vulnsManager.vulns[0][prop]).toEqual(vulnMod[prop]);
                }
            }
        });
    });
});
