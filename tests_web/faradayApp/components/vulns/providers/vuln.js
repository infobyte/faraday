// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

describe('Vulnerability Object', function() {
    var Vuln,
    $httpBackend,
    BASEURL;

    var new_data,
    new_name,
    new_id,
    new_id_parent,
    new_full_id,
    old_data,
    old_name,
    old_id,
    old_id_parent,
    old_full_id;

    // Set up the module
    beforeEach(module('faradayApp'));

    beforeEach(inject(function($injector, _$httpBackend_, _$q_, _Vuln_, _attachmentsFact_) {
        $httpBackend = _$httpBackend_;
        $q = _$q_;
        Vuln = _Vuln_;
        attachmentsFact = _attachmentsFact_;
        BASEURL = 'http://localhost:9876/_api/'; 

        new_name = "new name";
        new_desc = "new desc";
        new_id = CryptoJS.SHA1(new_name + "." + new_desc).toString();
        new_id_parent = CryptoJS.SHA1("parent").toString();
        new_full_id = new_id_parent + "." + new_id;

        new_data = {
            "data": "data",
            "desc": new_desc,
            "easeofresolution": "easeofresolution",
            "impact": "impact",
            "name": new_name,
            "owned": false,
            "parent": new_id_parent,
            "refs": "refs",
            "resolution": "resolution",
            "severity": "severity",
            "ws": "ws"
        };

        // this is used to create a web vuln that "already exists"
        var now = new Date(),
        old_date = now.getTime();

        old_name = "old name";
        old_desc = "old desc";
        old_id = CryptoJS.SHA1(old_name + "." + old_desc).toString();
        old_id_parent = CryptoJS.SHA1("parent").toString();
        old_full_id = old_id_parent + "." + old_id;

        old_data = {
            "_id": old_full_id,
            "_rev": "1-lalalala",
            "data": "data",
            "desc": old_desc,
            "easeofresolution": "easeofresolution",
            "impact": "impact",
            "metadata": {
                "update_time": old_date,
                "update_user":  "update_user",
                "update_action": "update_action",
                "creator": "creator",
                "create_time": old_date,
                "update_controller_action": "update_controller_action",
                "owner": "owner"
            },
            "name": old_name,
            "owned": false,
            "parent": old_id_parent,
            "refs": "refs",
            "resolution": "resolution",
            "severity": "severity",
            "ws": "ws"
        };
    }));

    afterEach(function() {
        $httpBackend.verifyNoOutstandingExpectation();
        $httpBackend.verifyNoOutstandingRequest();
    });

    describe('CRUD with invalid data', function() {
        it('Setting new object', function() {
            delete new_data.name;

            expect(function() { new Vuln('ws', new_data); }).toThrowError(Error, "Unable to create Vuln without a name");
        });
    });

    describe('CRUD with valid data', function() {
        it('Setting new object', function() {
            vuln = new Vuln('ws', new_data);

            expect(vuln._id).toBeDefined();
            expect(vuln._id).toEqual(new_full_id);
            expect(vuln.type).toEqual("Vulnerability");
            
            for(var prop in new_data) {
                if(new_data.hasOwnProperty(prop)) {
                    expect(vuln[prop]).toEqual(new_data[prop]);
                }
            }
        });

        it('Setting existing object', function() {
            vuln = new Vuln('ws', old_data);

            expect(vuln._id).toBeDefined();
            expect(vuln._id).toEqual(old_full_id);
            
            for(var prop in old_data) {
                if(old_data.hasOwnProperty(prop)) {
                    if(prop != "metadata") expect(vuln[prop]).toEqual(old_data[prop]);
                }
            }
        });

        it('Saving new object', function() {
            var url = BASEURL + "ws/ws/doc/" + new_full_id;
            var vuln = new Vuln('ws', new_data);

            $httpBackend.expect('PUT', url).respond(201, {"rev": "1234"});

            vuln.save();

            $httpBackend.flush();

            expect(vuln._rev).toEqual("1234");
        });

        it('Saving existing object', function() {
            var url = BASEURL + "ws/ws/doc/" + old_full_id;
            var vuln = new Vuln('ws', old_data);

            $httpBackend.expect('PUT', url).respond(201, {"rev": "1234"});

            vuln.save();
            
            $httpBackend.flush();

            expect(vuln._rev).toEqual("1234");
        });

        it('Updating object', function() {
            var url = BASEURL + "ws/ws/doc/" + new_full_id;
            var vuln = new Vuln('ws', new_data);

            $httpBackend.expect('PUT', url).respond(201, {"rev": "1234"});

            delete old_data._id;
            delete old_data._rev;
            vuln.update(old_data);

            $httpBackend.flush();

            expect(vuln._rev).toEqual("1234");
            
            for(var prop in old_data) {
                if(old_data.hasOwnProperty(prop)) {
                    if(prop != "metadata") expect(vuln[prop]).toEqual(old_data[prop]);
                }
            }
        });

        it('Deleting object', function() {
            var url = BASEURL + "ws/ws/doc/" + old_full_id + "?rev=" + old_data._rev;
            var vuln = new Vuln('ws', old_data);

            $httpBackend.expect('DELETE', url).respond(200);

            vuln.remove();

            $httpBackend.flush();
        });
    });
});
