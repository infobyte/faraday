// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

describe('modalNewVulnCtrl', function() {
    var $controller, 
        vm,
        $scope;

    var $hostsManager,
    hostsManagerMock,
    $cweFact,
    cweFact,
    servicesManagerMock;

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

            hostsManagerMock = {
                getHosts: function(ws) {
                    return returnPromise([
                        { _id: "1", name: "host1" },
                        { _id: "2", name: "host2" },
                        { _id: "3", name: "host3" }
                    ])
                },
                getInterfaces: function(ws, h_id) {
                    return returnPromise([
                        {"value":
                            {
                                _id: h_id + ".1",
                                name: "int1",
                                hostnames: ["test" + h_id + ".faradaysec.com"]
                            }
                        }
                    ])
                }
            }

            servicesManagerMock = {
                getServicesByHost: function(ws, h_id) {
                    return returnPromise([
                        { _id: h_id + ".1.1", name: "serv" + h_id },
                        { _id: h_id + ".1.2", name: "serv" + h_id },
                        { _id: h_id + ".1.3", name: "serv" + h_id },
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
                hostsManager: hostsManagerMock,
                servicesManager: servicesManagerMock,
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
                    expect(services.name).toEqual("serv" + (j + 1));
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
            expect(vm.data.refs).toContain('This is a new Reference');

            vm.new_ref = "This is another reference";
            vm.newReference();
            expect(vm.data.refs).toContain('This is another reference');
        });
        it('selected is true of data.parent object execution of setTarget function', function() {
            $scope.$apply();
            var target = vm.targets[0];
            vm.setTarget(target);
            expect(vm.data.parent).toEqual(target);
            expect(vm.data.parent.selected).toEqual(true);

            //if a service is the target
            var service_target = target.services[0];
            vm.setTarget(target.services[0]);
            expect(vm.data.parent).toEqual(service_target);
            expect(vm.data.parent.selected).toEqual(true);
        });
    });
});
