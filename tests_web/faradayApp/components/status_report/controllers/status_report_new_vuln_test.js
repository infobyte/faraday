// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

describe('StatusReport modalNewVulnCtrl', function() {
    var $controller, 
        vm,
        $scope;

    var $cweFact,
    cweFact,
    targetFactMock;

    var returnPromise;

    var modalInstance; 

    beforeEach(function () {
        module('faradayApp');

        inject(function(_$rootScope_, _$controller_, _$q_) {
            // The injector unwraps the underscores (_) from around the parameter names when matching
            $scope = _$rootScope_.$new();
            returnPromise = function(res) {
                var deferred = _$q_.defer();
                deferred.resolve(res);
                return deferred.promise;
            }

            rejectPromise = function(res) {
                var deferred = _$q_.defer();
                deferred.reject(res);
                return deferred.promise;
            }

            targetFactMock = {
                getTargets: function(ws) {
                    return returnPromise([
                        {
                            _id: "1",
                            name: "host1",
                            hostnames: ['test1.faradaysec.com'],
                            services:[
                                {
                                    _id: "1.1.1",
                                    name: "srv1"
                                },
                                {
                                    _id: "1.1.2",
                                    name: "srv2"
                                }
                            ]
                        },
                        {
                            _id: "2",
                            name: "host2",
                            hostnames: ['test2.faradaysec.com'],
                            services:[
                                {
                                    _id: "2.1.1",
                                    name: "srv1"
                                },
                                {
                                    _id: "2.1.2",
                                    name: "srv2"
                                }
                            ]
                        },
                        {
                            _id: "3",
                            name: "host3",
                            hostnames: ['test3.faradaysec.com'],
                            services:[
                                {
                                    _id: "3.1.1",
                                    name: "srv1"
                                },
                                {
                                    _id: "3.1.2",
                                    name: "srv2"
                                }
                            ]
                        }
                    ])
                }
            }

            cweFactMock = {
                get: function() {
                    return returnPromise([]);
                }
            }

            modalInstance = {
                close: jasmine.createSpy('modalInstance.close'),
                dismiss: jasmine.createSpy('modalInstance.dismiss')
            }

            $controller = _$controller_('modalNewVulnCtrl', {
                $scope: $scope,
                $modalInstance: modalInstance,
                EASEOFRESOLUTION: ['simple', 'moderate', 'hard'],
                severities: ['low', 'medium', 'high'],
                workspace: 'test',
                targetFact: targetFactMock,
                cweFact: cweFactMock
            });

        });
    });


    describe('Modal controller init function', function() {
        beforeEach(function() {
            vm = $controller;
        });
        it('controller variables loaded', function() {
            $scope.$apply();
            vm.targets.forEach(function(target, j) {
                expect(target.name).toEqual("host" + (j + 1));
                expect(target.hostnames).toEqual(["test" + (j + 1) + ".faradaysec.com"]);
                target.services.forEach(function(services, k) {
                    expect(services._id).toEqual((j + 1) + ".1." + (k + 1));
                    expect(services.name).toEqual("srv" + (k + 1));
                });
            });
        });
    });

    describe('Modal controller functions', function() {
        beforeEach(function() {
            vm = $controller;
        });
        it('object changed after execution of toggleImpact function', function() {
            $scope.$apply();
            expect(vm.data.impact['accountability']).toEqual(false);
            vm.toggleImpact('accountability');
            expect(vm.data.impact['accountability']).toEqual(true);
        });
        it('add variable to data.refs after execution of newReference function', function() {
            $scope.$apply();
            vm.new_ref = "This is a new Reference";
            vm.newReference();
            expect(vm.data.refs).toContain({value: 'This is a new Reference'});

            vm.new_ref = "This is another reference";
            vm.newReference();
            expect(vm.data.refs).toContain({value: 'This is another reference'});
        });
        it('selected is true of data.parent object execution of setTarget function', function() {
            $scope.$apply();
            var target = vm.targets[0];
            vm.setTarget(target);
            expect(vm.data.parent).toEqual(target);
            expect(vm.data.parent.selected_modalNewCtrl).toEqual(true);

            //if a service is the target
            var service_target = target.services[0];
            vm.setTarget(target.services[0]);
            expect(vm.data.parent).toEqual(service_target);
            expect(vm.data.parent.selected_modalNewCtrl).toEqual(true);
        });
        it('variables have proper values after execution of ok function', function() {
            $scope.$apply();
            var vuln = {
                data: "data",
                desc: "desc",
                easeofresolution: "simple",
                evidence: {"name": "evidence", "type":"image/vnd.microsoft.icon"},
                impact: {
                    "accountability": true,
                    "availability": true,
                    "confidentiality": false,
                    "integrity": false
                },
                method: "method",
                name: "name",
                owned: true,
                params: "params",
                parent: {"_id":"d037090bfc65d5d94e95c9da29a2803249a65e0b","type":"Service"},
                path: "path",
                pname: "pname",
                query: "query",
                refs: [{value: "ref1"}, {value: "ref2"}],
                request: "request",
                resolution: "resolution",
                response: "response",
                severity: "info",
                type: "VulnerabilityWeb",
                website: "website"
            };

            for(var key in vuln){
                if (vuln.hasOwnProperty(key)) {
                    vm.data[key] = vuln[key];
                }
            }
            vm.ok();
            expect(vm.data.data).toEqual('data');
            expect(vm.data.desc).toEqual('desc');
            expect(vm.data.easeofresolution).toEqual('simple');
            expect(vm.data.evidence).toEqual({"name": "evidence", "type": "image/vnd.microsoft.icon"});
            expect(vm.data.impact).toEqual({"accountability": true, "availability": true, "confidentiality": false, "integrity": false});
            expect(vm.data.method).toEqual('method');
            expect(vm.data.name).toEqual('name');
            expect(vm.data.owned).toEqual(true);
            expect(vm.data.params).toEqual('params');
            expect(vm.data.parent).toEqual('d037090bfc65d5d94e95c9da29a2803249a65e0b');
            expect(vm.data.path).toEqual('path');
            expect(vm.data.pname).toEqual('pname');
            expect(vm.data.query).toEqual('query');
            expect(vm.data.refs).toContain('ref1');
            expect(vm.data.refs).toContain('ref2');
            expect(vm.data.request).toEqual('request');
            expect(vm.data.resolution).toEqual('resolution');
            expect(vm.data.response).toEqual('response');
            expect(vm.data.severity).toEqual('info');
            expect(vm.data.type).toEqual('VulnerabilityWeb');
            expect(vm.data.website).toEqual('website');
        });
    });
});
