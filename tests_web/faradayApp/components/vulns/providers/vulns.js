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
    vuln1, vuln2, vuln3;

    // Set up the module
    beforeEach(module('faradayApp'));

    beforeEach(inject(function($injector, _vulnsManager_, _Vuln_, _WebVuln_) {
        $filter = $injector.get('$filter');
        $httpBackend = $injector.get('$httpBackend');
        $q = $injector.get('$q');
        vulnsManager = _vulnsManager_;
        Vuln = _Vuln_;
        WebVuln = _WebVuln_;
        BASEURL = 'http://localhost:9876/'; 

        vuln1 = {
            "_id": "1.2.3.e29ba38bfa81e7f9050f6517babc14cf32cacdff",
            "_rev": "1-abe16726389e434ca3f37384ea76128e",
            "desc": "I'm scared!",
            "data": "",
            "description": "I'm scared!",
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
        vuln2 = {
            "_id": "1.2.3.5",
            "_rev": "1-abe16726389e434ca3f37384ea76128e",
            "name": "Another vuln",
            "parent": "1.2.3",
            "resolution": "Be careful",
            "refs": [
               "CVE-2002-1623",
               "7423",
               "OSVDB:3820, CERT:886601"
            ],
            "metadata": {
               "update_time": 1429643049.395857,
               "update_user": "john",
               "update_action": 0,
               "creator": "john",
               "create_time": 1429643049.395857,
               "update_controller_action": "ModelControler.newVuln",
               "owner": "john"
            },
            "owned": false,
            "severity": "med",
            "type": "Vulnerability",
            "owner": "john",
            "desc": "I'm scared!",
            "data": "",
            "description": "I'm scared!"
        };
        vuln3 = {
            "_id": "6.7.8.9",
            "_rev": "3-f34c61eca3cb5ffc5654f710774708af",
            "desc": "It was possible to identify the remote service by its banner.",
            "metadata": {
               "update_time": 1407530638.669383,
               "update_user": "",
               "update_action": 0,
               "creator": "",
               "create_time": 1407530638.669383,
               "update_controller_action": "No model controller call",
               "owner": ""
            },
            "name": "Service Detection",
            "obj_id": "008cba9b11897f2d52c53dd953d75fa233a7fffe",
            "owned": false,
            "owner": "",
            "parent": "6.7.8",
            "refs": [
            ],
            "severity": "low",
            "type": "VulnerabilityWeb",
            "method": "",
            "params": "",
            "path": "",
            "pname": "",
            "query": "",
            "request": "",
            "response": "",
            "website": "test.test.com"
        };
    }));

    afterEach(function() {
        $httpBackend.verifyNoOutstandingExpectation();
        $httpBackend.verifyNoOutstandingRequest();
    });

    describe(' ', function() {
        it('Initialization', function() {
            expect(vulnsManager.vulns).toBeDefined();
            expect(vulnsManager.vulns).toEqual([]);
            expect(vulnsManager.update_seq).toBeDefined();
            expect(vulnsManager.update_seq).toEqual(0);
        });

        it('getVulns with unchanged DB', function() {
            $httpBackend.expect('GET', BASEURL + 'ws').respond(200, {"update_seq": 0});

            vulnsManager.getVulns("ws");

            $httpBackend.flush();

            expect(vulnsManager.vulns).toEqual([]);
            expect(vulnsManager.update_seq).toEqual(0);
        });

        it('getVulns with changed DB', function() {
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

            $httpBackend.expect('GET', BASEURL + 'ws').respond(200, {"update_seq": 1});
            $httpBackend.expect('GET', BASEURL + 'ws/_design/vulns/_view/all').respond(200, resp);

            vulnsManager.getVulns("ws");

            $httpBackend.flush();

            expect(vulnsManager.vulns.length).toEqual(1);
            expect(vulnsManager.vulns[0]._id).toEqual(vuln1._id);
            expect(vulnsManager.update_seq).toEqual(1);
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

            // insert new vuln in Couch
            $httpBackend.expect('POST', BASEURL + "ws/" + id).respond(201, {"rev": "1234"});
            // getVulns
            $httpBackend.expect('GET', BASEURL + 'ws').respond(200, {"update_seq": 1});
            $httpBackend.expect('GET', BASEURL + 'ws/_design/vulns/_view/all').respond(200, resp);

            vulnsManager.createVuln("ws", vuln);

            $httpBackend.flush();

            expect(vulnsManager.vulns.length).toEqual(1);
            expect(vulnsManager.vulns[0]._id).toEqual(id);
            expect(vulnsManager.update_seq).toEqual(1);
        });

        it('deleteVuln', function() {
            var id = vuln1._id,
            vuln = vuln1;
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
            $httpBackend.expect('POST', BASEURL + "ws/" + id).respond(201, {"rev": "1234"});
            // getVulns
            $httpBackend.expect('GET', BASEURL + 'ws').respond(200, {"update_seq": 1});
            $httpBackend.expect('GET', BASEURL + 'ws/_design/vulns/_view/all').respond(200, respInsert);

            vulnsManager.createVuln("ws", vuln);

            $httpBackend.flush();

            // delete vuln
            $httpBackend.expect('DELETE', BASEURL + 'ws/' + id).respond(200);
            // getVulns
            $httpBackend.expect('GET', BASEURL + 'ws').respond(200, {"update_seq": 2});
            $httpBackend.expect('GET', BASEURL + 'ws/_design/vulns/_view/all').respond(200, respDelete);
            
            vulnsManager.deleteVuln("ws", vulnsManager.vulns[0]);
            $httpBackend.flush();

            expect(vulnsManager.vulns.length).toEqual(0);
        });

        it('updateVuln', function() {
            var id = vuln1._id,
            vuln = vuln1;
            delete vuln._id;
            delete vuln._rev;

            var vulnMod = {
                "_id": "1.2.3.e29ba38bfa81e7f9050f6517babc14cf32cacdff",
                "_rev": "1-abe16726389e434ca3f37384ea76128e",
                "desc": "Hello World!",
                "data": "",
                "description": "I'm scared!",
                "metadata": {
                   "update_time": 1429643049.395857,
                   "update_user": "john",
                   "update_action": 0,
                   "creator": "john",
                   "create_time": 1429643049.395857,
                   "update_controller_action": "ModelControler.newVuln",
                   "owner": "john"
                },
                "name": "Something something dark side",
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
                        "value": vuln1
                    }
                ]
            };

            // insert new vuln in Couch
            $httpBackend.expect('POST', BASEURL + "ws/" + id).respond(201, {"rev": "1234"});
            // getVulns
            $httpBackend.expect('GET', BASEURL + 'ws').respond(200, {"update_seq": 1});
            $httpBackend.expect('GET', BASEURL + 'ws/_design/vulns/_view/all').respond(200, respInsert);
            // call to insert
            vulnsManager.createVuln("ws", vuln);
            $httpBackend.flush();

            // update vuln
            $httpBackend.expect('PUT', BASEURL + 'ws/' + id).respond(200, {"rev": "2345"});
            // getVulns
            $httpBackend.expect('GET', BASEURL + 'ws').respond(200, {"update_seq": 2});
            $httpBackend.expect('GET', BASEURL + 'ws/_design/vulns/_view/all').respond(200, respUpdate);
            
            console.log(vulnsManager.vulns[0].name);
            vulnsManager.updateVuln(vuln.ws, vulnsManager.vulns[0], vulnMod);
            $httpBackend.flush();
            console.log(vulnsManager.vulns[0].name);

            expect(vulnsManager.vulns.length).toEqual(1);
            
            for(var prop in vulnMod) {
                if(vulnMod.hasOwnProperty(prop)) {
                    if(prop != "metadata") expect(vuln[prop]).toEqual(vulnMod[prop]);
                }
            }
        });
    });
});
