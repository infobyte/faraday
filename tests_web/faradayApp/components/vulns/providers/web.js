// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

describe('WebVuln', function() {
    var WebVuln,
    $httpBackend,
    BASEURL;

    var new_data,
    new_name,
    new_website,
    new_path,
    new_id,
    new_id_parent,
    new_full_id,
    old_data,
    old_name,
    old_website,
    old_path,
    old_id,
    old_id_parent,
    old_full_id;

    // Set up the module
    beforeEach(module('faradayApp'));

    beforeEach(inject(function($injector, _WebVuln_) {
        $httpBackend = $injector.get('$httpBackend');
        WebVuln = _WebVuln_;
        BASEURL = 'http://localhost:9876/'; 

        new_name = "new name";
        new_website = "new website";
        new_path = "new path";
        new_desc = "new desc";
        new_id = CryptoJS.SHA1(new_name + "." + new_website + "." + new_path + "." + new_desc).toString();
        new_id_parent = CryptoJS.SHA1("parent").toString();
        new_full_id = new_id_parent + "." + new_id;

        new_data = {
            "data": "data",
            "desc": new_desc,
            "easeofresolution": "easeofresolution",
            "impact": "impact",
            "method": "method",
            "name": new_name,
            "owned": false,
            "params": "params",
            "parent": new_id_parent,
            "path": new_path,
            "pname": "pname",
            "query": "query",
            "refs": "refs",
            "request": "request",
            "resolution": "resolution",
            "response": "response",
            "severity": "severity",
            "website": new_website,
            "ws": "ws"
        };

        var now = new Date(),
        old_date = now.getTime();

        old_name = "old name";
        old_website = "old website";
        old_path = "old path";
        old_desc = "old desc";
        old_id = CryptoJS.SHA1(old_name + "." + old_website + "." + old_path + "." + old_desc).toString();
        old_id_parent = CryptoJS.SHA1("parent").toString();
        old_full_id = old_id_parent + "." + old_id;

        old_data = {
            "_id": old_full_id,
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
            "method": "method",
            "name": old_name,
            "owned": false,
            "params": "params",
            "parent": old_id_parent,
            "path": old_path,
            "pname": "pname",
            "query": "query",
            "refs": "refs",
            "request": "request",
            "resolution": "resolution",
            "response": "response",
            "severity": "severity",
            "website": old_website,
            "ws": "ws"
        };
    }));

    afterEach(function() {
        $httpBackend.verifyNoOutstandingExpectation();
        $httpBackend.verifyNoOutstandingRequest();
    });

    describe('CRUD', function() {
        it('Setting data to new object', function() {
            vuln = new WebVuln(new_data);

            expect(vuln._id).toBeDefined();
            expect(vuln._id).toEqual(new_full_id);
            expect(vuln.type).toEqual("VulnerabilityWeb");
            
            for(var prop in new_data) {
                if(new_data.hasOwnProperty(prop)) {
                    //console.log(vuln[prop]);
                    expect(vuln[prop]).toEqual(new_data[prop]);
                }
            }
        });

/*
        it('Setting data to existing object', function() {
            vuln = new WebVuln(old_data);

            expect(vuln._id).toBeDefined();
            expect(vuln._id).toEqual(old_full_id);
            
            for(var prop in old_data) {
                if(old_data.hasOwnProperty(prop)) {
                    expect(vuln.prop).toEqual(old_data.prop);
                }
            }
        });

        it('Save data to new object', function() {
            var url = BASEURL + "ws/" + new_full_id;

            vuln = new WebVuln(new_data);

            $httpBackend.when('POST', url).respond(201, {"rev": "1234"});
            $httpBackend.expect('POST', url);

            vuln.save();

            $httpBackend.flush();

            expect(vuln._rev).toEqual("1234");
        });

        it('Save data to existing object', function() {
            var url = BASEURL + "ws/" + old_full_id;

            vuln = new WebVuln(old_data);

            $httpBackend.when('POST', url).respond(201, {"rev": "1234"});
            $httpBackend.expect('POST', url);

            vuln.save();

            $httpBackend.flush();

            expect(vuln._rev).toEqual("1234");
        });

        it('Update data', function() {
            var url = BASEURL + "ws/" + new_full_id;

            vuln = new WebVuln(new_data);
            expect(vuln._rev).toBeUndefined();

            $httpBackend.when('PUT', url).respond(201, {"rev": "1234"});
            $httpBackend.expect('PUT', url);

            vuln.update(old_data);

            $httpBackend.flush();

            expect(vuln._rev).toEqual("1234");
        });

        it('Delete data', function() {
            var url = BASEURL + "ws/" + new_full_id;

            vuln = new WebVuln(new_data);

            $httpBackend.expect('DELETE', url);

            vuln.remove();

            $httpBackend.flush();
        });
*/
    });
});
