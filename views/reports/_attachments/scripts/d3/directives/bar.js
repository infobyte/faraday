angular.module('faradayApp')
  .directive('d3Bars', ['$window', '$timeout', 'd3Service', 
  function($window, $timeout, d3Service) {
    return {
      restrict: 'EA',
      scope: {
        data: '=',
        label: '@',
        onClick: '&'
      },
      link: function(scope, ele, attrs) {
        d3Service.d3().then(function(d3) {
 
          var margin = {
            "top": parseInt(attrs.marginTop) || 20,
            "right": parseInt(attrs.marginRight) || 20,
            "bottom": parseInt(attrs.marginBottom) || 30,
            "left": parseInt(attrs.marginLeft) || 40,
          }
 
          var svg = d3.select(ele[0])
            .append('svg')
            .style('width', "100%")
 
          scope.$watch('data', function(newData) {
            scope.render(newData);
          }, true);
 
          scope.render = function(data) {
            svg.selectAll('*').remove();
 
            if (!data) return;
 
            var barHeight = parseInt(attrs.barHeight) || 20,
                barPadding = parseInt(attrs.barPadding) || 5,
                width = parseInt(attrs.svgWitdh) || 160,
                height = parseInt(attrs.svgHeight) || 149;

            var color = d3.scale.category20b();
            var x = d3.scale.ordinal()
                .rangeRoundBands([0, width - margin.left - margin.right], .1);
            x.domain(data.map(function(d) { return d.key; }));
            
            var y = d3.scale.linear()
                .range([height - margin.top - margin.bottom, 0]);
            y.domain([0, d3.max(data, function(d) { return d.value; })]);

            var xAxis = d3.svg.axis()
                .scale(x)
                .orient("bottom");
            var yAxis = d3.svg.axis()
                .scale(y)
                .orient("left")
                .ticks(5);
            
            svg.attr('width', width);
            svg.attr('height', height);
            svg.append("g")
              .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

            svg.selectAll('rect')
              .data(data)
              .enter()
                .append('rect')
                .attr("class", "bar")
                .attr("x", function(d) { return x(d.key); })
                .attr("y", function(d) { return y(d.value - 1); })
                .style("fill", function(d) { return color(Math.random()*55); })
                .attr("height", function(d) { return height - y(d.value); })
                .attr("width", 30);
          };
        });
      }}
  }]);