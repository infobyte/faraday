angular.module('faradayApp')
    .factory('vulnsFact', ['BASEURL', '$http', function(BASEURL, $http) {
        var vulnsFact = {};

        vulnsFact.get = function(ws) {
            var vulns = [];
            vulns_url = BASEURL + ws +"/_design/vulns/_view/vulns";
            // gets vulns json from couch
            $.getJSON(vulns_url, function(data) {
                $.each(data.rows, function(n, obj){
                    var d = new Date(0);
                    d.setUTCSeconds(obj.value.date);
                    d = d.getDate() + "/" + (d.getMonth() + 1) + "/" + d.getFullYear();
                    var v = {
                        "id":           obj.id,
                        "rev":          obj.value.rev,
                        "couch_parent": obj.value.parent,
                        "data":         obj.value.data,
                        "date":         d, 
                        "delete":       false,
                        "desc":         obj.value.desc,
                        "meta":         obj.value.meta,
                        "name":         obj.value.name, 
                        "oid":          obj.value.oid,
                        "owned":        obj.value.owned,
                        "owner":        obj.value.owner,
                        "parent":       obj.key.substring(0, obj.key.indexOf('.')),
                        "refs":         obj.value.refs,
                        "selected":     false,
                        "severity":     obj.value.severity,
                        "type":         obj.value.type, 
                        "web":          false
                    };
                    vulns.push(v);
                });
            });
            return vulns;
        }

        vulnsFact.put = function(ws, vuln, callback) {
            var url = BASEURL + ws + "/" + vuln.id;
            if(typeof(vuln.evidence) != undefined && vuln.evidence != undefined) {
                //delete vuln.evidence.icon;
                evidence = vuln.evidence[0];
                var filename = encodeURIComponent(evidence.name);
                var filetype = evidence.type;
                var fileReader = new FileReader();
                //$http.defaults.headers.put = {'Content-Type': filetype};
                //fileReader.readAsDataURL(evidence);
                fileReader.readAsDataURL(evidence);
                fileReader.onloadend = function (readerEvent) {
                    /*
                    var id = "036407e058a0233cb06160ca711b17d5544cc5b0";
                    var rev = "12-ccd6b8013f4f16cb3e91f290dfa4344e";
                    url = BASEURL + ws + "/" + id + "/attachment?rev=" + rev;
                    */
                    var result = readerEvent.target.result.replace('data:image/jpeg;base64', '');
                    //var result = readerEvent.target.result;

                    var docid = "andalaconchadetumadre";
                    url = BASEURL + "zzz_tuvieja/" + docid; 
                    result = {
                        "_id": docid,
                        "field1": "lala",
                        "_attachments": {
                            "titulo.jpg": {
                                "content_type": "image/jpeg",
                                "data": readerEvent.target.result.replace('data:image/jpeg;base64,', '')
                                //"data": "VGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIHRleHQ="
                            }
                        }
                    };
                    //JSON.stringify(result);

                    //$http.put(url, result, {'headers': {'Content-Type': filetype}}).success(function(d, s, h, c) {
                    $http.put(url, result).success(function(d, s, h, c) {
                        callback(d);
                        callback(s);
                        callback(h);
                        callback(c);
                    });
                };
            } else {
                var v = {
                    "_rev":         vuln.rev,
                    "data":         vuln.data,
                    "desc":         vuln.desc,
                    "metadata":     vuln.meta,
                    "name":         vuln.name,
                    "obj_id":       vuln.oid,
                    "owned":        vuln.owned,
                    "owner":        vuln.owner,
                    "parent":       vuln.couch_parent, 
                    "refs":         vuln.refs,
                    "severity":     vuln.severity, 
                    "type":         vuln.type
                };
                $http.put(url, v).success(function(d, s, h, c) {
                    callback(d.rev);
                });
            }

        };

        vulnsFact.remove = function(ws, vuln) {
            var url = BASEURL + ws + "/" + vuln.id + "?rev=" + vuln.rev;
            $http.delete(url).success(function(d, s, h, c) {});
        };

        return vulnsFact;
    }]);
