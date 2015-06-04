// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .directive('d3StackedBars', ['d3Service', 
        function(d3Service) {
            return {
                restrict: 'EA',
                scope: {
                    data: '='
                },
                link: function(scope, ele, attrs) {
                    d3Service.d3().then(function(d3) {
                        // update scope when changes occur
                        scope.$watch('data', function(newData) {
                            scope.render(newData);
                        }, true);

                        scope.render = function(data) {
/*                            
                            data = [
                                {severity: "critical", amount: 2},
                                {severity: "high", amount: 100},
                                {severity: "med", amount: 40},
                                {severity: "low", amount: 23},
                                {severity: "info", amount: 87},
                                {severity: "unclassified", amount: 15}
                            ];

                            var x = d3.scale.linear()
                                .domain(d3.extent(data, function(d) {return d.amount;}))
                                .range([200, 0]);
                            var ext = d3.extent(x.domain());
                            var totalWidth = ext[1] - ext[0];

                            var svg = d3.select(".stackedbars").append("svg");

                            var rects = svg.selectAll('rect')
                                .data(data);

                            var newRects = rects.enter();

                            console.log(x.range());
                            console.log(x(0));
                            console.log(x);
                            newRects.append('rect')
                                .attr('x', x(0))
                                .attr('y', 100)
                                .attr('height', 20)
                                .attr('width', function(d, i) {
                                    return d.amount * 100 / totalWidth;
                                });
*/


var data = [
{"key":"FL", "pop1":3000, "pop2":4000, "pop3":5000},
{"key":"CA", "pop1":3000, "pop2":3000, "pop3":3000},
{"key":"NY", "pop1":12000, "pop2":5000, "pop3":13000},
{"key":"NC", "pop1":8000, "pop2":21000, "pop3":11000},
{"key":"SC", "pop1":30000, "pop2":12000, "pop3":8000},
{"key":"AZ", "pop1":26614, "pop2":6944, "pop3":30778},
{"key":"TX", "pop1":8000, "pop2":12088, "pop3":20000}
];
 
var n = 3, // number of layers
    m = data.length, // number of samples per layer
    stack = d3.layout.stack(),
    labels = data.map(function(d) {return d.key;}),
    
    //go through each layer (pop1, pop2 etc, that's the range(n) part)
    //then go through each object in data and pull out that objects's population data
    //and put it into an array where x is the index and y is the number
    layers = stack(d3.range(n).map(function(d) { 
                var a = [];
      			for (var i = 0; i < m; ++i) {
        			a[i] = {x: i, y: data[i]['pop' + (d+1)]};  
      			}
  				return a;
             })),
    
	//the largest single layer
    yGroupMax = d3.max(layers, function(layer) { return d3.max(layer, function(d) { return d.y; }); }),
    //the largest stack
    yStackMax = d3.max(layers, function(layer) { return d3.max(layer, function(d) { return d.y0 + d.y; }); });

var margin = {top: 40, right: 10, bottom: 20, left: 50},
    width = 677 - margin.left - margin.right,
    height = 533 - margin.top - margin.bottom;

var y = d3.scale.ordinal()
    .domain(d3.range(m))
    .rangeRoundBands([2, height], .08);

var x = d3.scale.linear()
    .domain([0, yStackMax])
    .range([0, width]);

var color = d3.scale.linear()
    .domain([0, n - 1])
    .range(["#aad", "#556"]);

var svg = d3.select("svg.stackedbars")
    .attr("width", width + margin.left + margin.right)
    .attr("height", height + margin.top + margin.bottom)
  .append("g")
    .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

var layer = svg.selectAll(".layer")
    .data(layers)
  .enter().append("g")
    .attr("class", "layer")
    .style("fill", function(d, i) { return color(i); });

layer.selectAll("rect")
    .data(function(d) { return d; })
  	.enter().append("rect")
    .attr("y", function(d) { return y(d.x); })
	.attr("x", function(d) { return x(d.y0); })
    .attr("height", y.rangeBand())
    .attr("width", function(d) { return x(d.y); });

var yAxis = d3.svg.axis()
    .scale(y)
    .tickSize(1)
    .tickPadding(6)
	.tickValues(labels)
    .orient("left");

svg.append("g")
    .attr("class", "y axis")
    .call(yAxis);

/*
from here simple horizontal stacked bars
var sales = [
  {
    name: "Hoodie",
    values: [
      { count: 6, date: "2014-01-01" },
      { count: 7, date: "2014-01-02" },
      { count: 8, date: "2014-01-03" }
    ]
  },
  {
    name: "Jacket",
    values: [
      { count: 2, date: "2014-01-01" },
      { count: 5, date: "2014-01-02" },
      { count: 7, date: "2014-01-03" }
    ]
  },
  {
    name: "Snuggie",
    values: [
      { count: 3, date: "2014-01-01" },
      { count: 2, date: "2014-01-02" },
      { count: 3, date: "2014-01-03" }
    ]
  }
];
  
var stack = d3.layout.stack()
  .values(function(d) { return d.values; })
  .x(function(d) { return new Date(Date.parse(d.date)); })
  .y(function(d) { return d.count; });

var stacked = stack(sales);
  
var height = 200;
var width = 200;

// we need to calculate the maximum y-value
// across all our layers, and for each data point,
// we need to combine the start `d.y0` and the
// height `d.y` to get highest point
var maxY = d3.max(stacked, function(d) {
  return d3.max(d.values, function(d) {
    return d.y0 + d.y;
  });
});

var y = d3.scale.linear()
  .range([height, 0])
  .domain([0, maxY]);

var x = d3.time.scale()
  .range([0, width])
  .domain(d3.extent(sales[0].values, function(d) {
    // normally we would check across all our layers,
    // but we can "cheat" and use `sales[0].values`
    // since we know all layers have the same domain
    return new Date(Date.parse(d.date));
  }))
  .nice(4);

var svg = d3.select('svg.stackedbars');
var color = d3.scale.category10();

// bind a <g> tag for each layer
var layers = svg.selectAll('g.layer')
  .data(stacked, function(d) { return d.name; })
    .enter()
      .append('g')
        .attr('class', 'layer')
        .attr('fill', function(d) { return color(d.name); })

// bind a <rect> to each value inside the layer
layers.selectAll('rect')
  .data(function(d) { return d.values; })
  .enter()
    .append('rect')
      .attr('x', function(d) {return x(new Date(Date.parse(d.date))); })
      .attr('width', width / 3)
      .attr('y', function(d) {
        // remember that SVG is y-down while our graph is y-up!
        // here, we set the top-left of this bar segment
        return y(d.y0 + d.y);
      }).attr('height', function(d) {
        // since we are drawing our bar from the top downwards,
        // the length of the bar is the distance from the bottom
        // so we subtract from `height`
        return height - y(d.y)
      });
up to here, simple stacked vertical bars
*/


                        };
                    });
                }
            };
        }]);
