// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

describe('modalNewVulnCtrl', function() {
    var $controller,
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

        inject(function(_$rootScope_, _$controller_, _$q_, _$modalInstance_) {
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
                    return [
                        { _id: "1", name: "host1" },
                        { _id: "2", name: "host2" },
                        { _id: "3", name: "host3" }
                    ]
                },
                getInterfaces: function(ws, h_id) {
                    return [{
                        _id: h_id + ".1",
                        name: "int1",
                        hostnames: ["test" + h_id + ".faradaysec.com"]
                    }]
                }
            }

            servicesManagerMock = {
                getServicesByHost: function(ws, h_id) {
                    return [
                        { _id: h_id + ".1.1", name: "serv" + h_id },
                        { _id: h_id + ".1.2", name: "serv" + h_id },
                        { _id: h_id + ".1.3", name: "serv" + h_id },
                    ]
                }
            }

            cweFactMock = {
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
                cweFact: cweFactMock,
            });
        });
    });


    describe('Modal controller init function', function() {
        it('controller variables loaded', function() {
            $scope.$apply();
            expect($scope.vulns.length).toEqual(3);
            expect($scope.vulns).toContain(vuln1);
            expect($scope.vulns).toContain(vuln2);
            expect($scope.vulns).toContain(vuln3);
        });
    });
});
