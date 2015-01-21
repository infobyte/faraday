angular.module('faradayApp')
  .directive('d3Cake', ['d3Service', function(d3Service) {
    return {
      restrict: 'EA',
      scope: {},
      link: function(scope, element, attrs) {
        d3Service.d3().then(function(d3) {
          // our d3 code will go here
        });
      }};
  }]);