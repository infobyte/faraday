//Filter to order by field, when you have and object
angular.module('faradayApp')
  .filter('orderObjectBy', ['SEVERITIES',
    function(SEVERITIES) {
      return function(items, field, reverse) {
        var filtered = [];
        angular.forEach(items, function(item) {
          filtered.push(item);
        });
        filtered.sort(compareItems(field));
        if(reverse) filtered.reverse();
        return filtered;
      };

      function compareItems(field) {
        return function(a, b) {
          var res;
          a = a[field];
          b = b[field];
          if(typeof(a) == "string" && typeof(b) == "string") {
            a = a.toLowerCase();
            b = b.toLowerCase();
          }
          res = (a > b || typeof(b) == "undefined" ? 1 : -1);
          if(field == 'impact'){
            res = compareImpact(a, b);
          }
          if(field == 'severity') {
            res = compareSeverities(a, b);
          }
          return res;
        }
      }

      function compareImpact(a, b) {
          var contA = 0, contB = 0;
          for(key in a){
            if(a.hasOwnProperty(key)){
              if(a[key]){
                contA = contA + 1;
              }
            }
          }
          for(key in b){
            if(b.hasOwnProperty(key)){
              if(b[key]){
                contB = contB + 1;
              }
            }
          }
          return (contA > contB ? 1 : -1);
      }

      function compareSeverities(a, b) {
        var res = 1;
        if(SEVERITIES.indexOf(a) > SEVERITIES.indexOf(b)) {
          res = -1;
        }
        return res;
      }
}]);