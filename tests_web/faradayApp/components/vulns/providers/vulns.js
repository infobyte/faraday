// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

describe('vulnsManager', function() {
    // Declare dependencies
    var vulnsManager,
    Vuln,
    WebVuln,
    hostsManager,
    servicesManager;

    var $filter,
    $httpBackend,
    $q,
    BASEURL;

    // Declare data
    var vuln1,
    couchVuln1,
    vuln2,
    couchVuln2,
    couchVulnEmpty;

    var hosts, interfaces,
    hostnames = [];

    // Set up the module
    beforeEach(module('faradayApp'));

    // Initialize data
    beforeEach(function() {
        vuln1 = {
            "_id": "1.e29ba38bfa81e7f9050f6517babc14cf32cacdff",
            "_rev": "1-abe16726389e434ca3f37384ea76128e",
            "_attachments": {},
            "desc": "I'm scared!",
            "data": "",
            "easeofresolution": 'trivial',
            "impact": {
                "availability": false,
                "accountability": false,
                "confidentiality": false,
                "integrity": false
            },
            "metadata": {
               "update_time": 1429643049.395857,
               "update_user": "",
               "update_action": 0,
               "creator": "",
               "create_time": 1429643049.395857,
               "update_controller_action": "ModelControler.newVuln",
               "owner": ""
            },
            "name": "Internet Key Exchange (IKE) Aggressive Mode with Pre-Shared Key",
            "obj_id": "e29ba38bfa81e7f9050f6517babc14cf32cacdff",
            "owned": false,
            "owner": "john",
            "parent": "1",
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

        couchVuln1 = {
            "total_rows": 1,
            "offset": 0,
            "rows":[
                {
                    "id": "1.2.3.8b4ffaedb84dd60d5f43c58eba66a7651458c8de",
                    "key":"4b84b15bff6ee5796152495a230e45e3d7e947d9.34ac3ea37a2854ce00f2d97c648bf3a7cc27ebca",
                    "value": vuln1
                }
            ]
        };

        vuln2 = {
            "_id": "1.e29ba38bfa81e7f9050f6517babc14cf32cacdff",
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
            "owner": "john",
            "parent": "1",
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

        couchVuln2 = {
            "total_rows":1,
            "offset":0,
            "rows":[
                {
                    "id": "1.2.3.8b4ffaedb84dd60d5f43c58eba66a7651458c8de",
                    "key":"4b84b15bff6ee5796152495a230e45e3d7e947d9.34ac3ea37a2854ce00f2d97c648bf3a7cc27ebca",
                    "value": vuln2
                }
            ]
        };

        couchVulnEmpty = {
            "total_rows":0,
            "offset":0,
            "rows":[]
        };

        hosts = [
            {
                "_id": "1",
                "name": "Host parent"
            }
        ];

        interfaces = [
            {
                "parent": "1",
                "hostnames": [
                    "h21",
                    "h22",
                    "h23"
                ]
            }, {
                "parent": "1",
                "hostnames": [
                    "h31",
                    "h32",
                    "h33"
                ]
            }, {
                "parent": "1",
                "hostnames": [
                    "h41",
                    "h42",
                    "h43"
                ]
            }
        ];

        services = [];

        interfaces.forEach(function(interf) {
            interf.hostnames.forEach(function(hostname) {
                if(hostnames.indexOf(hostname) < 0) hostnames.push(hostname);
            });
        });
    });

    // Initialize dependencies
    //beforeEach(inject(function($injector, _vulnsManager_, _Vuln_, _WebVuln_, _$filter_, _$httpBackend_, _$q_) {
    beforeEach(function() {
        var hostsManagerMock = {
            getHosts: function(ws) {
                var deferred = $q.defer();
                deferred.resolve(hosts);
                return deferred.promise;
            },
            getAllInterfaces: function(ws) {
                var deferred = $q.defer();
                deferred.resolve(interfaces);
                return deferred.promise;
            }
        };

        var servicesManagerMock = {
            getServices: function(ws) {
                var deferred = $q.defer();
                deferred.resolve(services);
                return deferred.promise;
            }
        };

        module(function($provide) {
            $provide.factory('hostsManager', function($q) { return hostsManagerMock; });
            $provide.factory('servicesManager', function($q) { return servicesManagerMock; });
        });

        inject(function(_vulnsManager_, _Vuln_, _WebVuln_, _$filter_, _$httpBackend_, _$q_, _hostsManager_, _servicesManager_) {
            $filter = _$filter_;
            $httpBackend = _$httpBackend_;
            $q = _$q_;
            vulnsManager = _vulnsManager_;
            Vuln = _Vuln_;
            WebVuln = _WebVuln_;
            hostsManager = _hostsManager_;
            servicesManager = _servicesManager_;
            BASEURL = 'http://localhost:9876/_api/ws/';
        });

    });

    afterEach(function() {
        $httpBackend.verifyNoOutstandingExpectation();
        $httpBackend.verifyNoOutstandingRequest();
    });

    describe('Basic usage', function() {
        xit('getVulns', function() {
            var vulns;

            $httpBackend.expect('GET', BASEURL + 'ws/vulns').respond(200, couchVuln1);

            vulnsManager.getVulns("ws")
                .then(function(vs) {
                    vulns = vs;
                });

            $httpBackend.flush();

            expect(vulns.length).toEqual(1);
            expect(vulnsManager.vulns.length).toEqual(1);

            // promise is resolved correctly
            vulns.forEach(function(v) {
                for(var prop in vuln1) {
                    expect(v[prop]).toEqual(vuln1[prop]);
                }
                expect(v["target"]).toEqual(hosts[0].name);
                expect(v["hostnames"]).toEqual(hostnames);
            });

            // array is updated correctly
            vulnsManager.vulns.forEach(function(v) {
                for(var prop in vuln1) {
                    expect(v[prop]).toEqual(vuln1[prop]);
                }
                expect(v["target"]).toEqual(hosts[0].name);
                expect(v["hostnames"]).toEqual(hostnames);
            });
        });

        xit('createVuln', function() {
            var id = vuln1._id,
            vuln = vuln1;

            delete vuln._id;
            delete vuln._rev;

            var vulns = [];

            // insert new vuln in Couch
            $httpBackend.expect('PUT', BASEURL + "ws/doc/" + id).respond(201, {"rev": "1234"});

            vulnsManager.createVuln("ws", vuln)
                .then(function(vs) {
                    vulns = vs;
                });

            $httpBackend.flush();

            expect(vulnsManager.vulns.length).toEqual(1);
            expect(vulnsManager.vulns[0]._id).toEqual(id);
            vulnsManager.vulns.forEach(function(v) {
                for(var prop in vuln1) {
                    if(prop !== "metadata") expect(v[prop]).toEqual(vuln1[prop]);
                }
                expect(v["target"]).toEqual(hosts[0].name);
                expect(v["hostnames"]).toEqual(hostnames);
            });
        });

        xit('deleteVuln', function() {
            var id = vuln1._id;
            var vuln = angular.copy(vuln1);
            delete vuln._id;
            delete vuln._rev;

            // insert new vuln in Couch
            $httpBackend.expect('PUT', BASEURL + "ws/doc/" + id).respond(201, {"rev": vuln1._rev});

            vulnsManager.createVuln("ws", vuln);

            $httpBackend.flush();

            // delete vuln
            $httpBackend.expect('DELETE', BASEURL + 'ws/doc/' + id + "?rev=" + vuln1._rev).respond(200);

            vulnsManager.deleteVuln(vulnsManager.vulns[0]);
            $httpBackend.flush();

            expect(vulnsManager.vulns.length).toEqual(0);
        });

        xit('updateVuln', function() {
            var id = vuln1._id;
            var vuln = angular.copy(vuln1);
            delete vuln._id;
            delete vuln._rev;

            // insert new vuln in Couch
            $httpBackend.expect('PUT', BASEURL + "ws/doc/" + id).respond(201, {"rev": "1234"});
            // call to insert
            vulnsManager.createVuln("ws", vuln);
            $httpBackend.flush();

            // update vuln
            $httpBackend.expect('PUT', BASEURL + 'ws/doc/' + id).respond(200, {"rev": "1-abe16726389e434ca3f37384ea76128e"});

            var vulns = vulnsManager.updateVuln(vulnsManager.vulns[0], vuln2);
            $httpBackend.flush();

            expect(vulnsManager.vulns.length).toEqual(1);

            for(var prop in vuln2) {
                if(vuln2.hasOwnProperty(prop)) {
                    if(prop != "metadata") expect(vulnsManager.vulns[0][prop]).toEqual(vuln2[prop]);
                }
            }
        });
    });
});
