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
                            newRects.append('rect')
                                .attr('x', x(0))
                                .attr('y', 100)
                                .attr('height', 20)
                                .attr('width', function(d, i) {
                                    return d.amount * 100 / totalWidth;
                                });







/*
                            var svg = d3.select(".stackedbars").append("svg")
                                .attr("width", width + margin.left + margin.right)
                                .attr("height", height + margin.top + margin.bottom)
                                .append("g")
                                .attr("transform", "translate(" + margin.left + "," + margin.top + ")");



                            var margin = {top: 50, right: 50, bottom: 50, left: 50},
                                width = 960 - margin.left - margin.right,
                                height = 500 - margin.top - margin.bottom;

                            var x = d3.scale.ordinal()
                                .rangeRoundBands([0, width], .1);

                            var y = d3.scale.linear()
                                .rangeRound([height, 0]);

                            var color = d3.scale.ordinal()
                                .range(["#98abc5", "#8a89a6", "#7b6888", "#6b486b", "#a05d56", "#d0743c", "#ff8c00"]);

                            var svg = d3.select(".stackedbars").append("svg")
                                .attr("width", width + margin.left + margin.right)
                                .attr("height", height + margin.top + margin.bottom)
                                .append("g")
                                .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

                            color.domain(d3.keys(data[0]).filter(function(key) { return key !== "State"; }));

                            data.forEach(function(d) {
                                var y0 = 0;
                                d.ages = color.domain().map(function(name) { return {name: name, y0: y0, y1: y0 += +d[name]}; });
                                d.ages.forEach(function(d) { d.y0 /= y0; d.y1 /= y0; });
                            });

                            data.sort(function(a, b) { return b.ages[0].y1 - a.ages[0].y1; });

                            x.domain(data.map(function(d) { return d.State; }));

                            svg.append("g")
                                .attr("class", "x axis")
                                .attr("transform", "translate(0," + height + ")")
                                .call(xAxis);

                            svg.append("g")
                                .attr("class", "y axis")
                                .call(yAxis);

                            var state = svg.selectAll(".state")
                                .data(data)
                                .enter().append("g")
                                .attr("class", "state")
                                .attr("transform", function(d) { return "translate(" + x(d.State) + ",0)"; });

                            state.selectAll("rect")
                                .data(function(d) { return d.ages; })
                                .enter().append("rect")
                                .attr("width", x.rangeBand())
                                .attr("y", function(d) { return y(d.y1); })
                                .attr("height", function(d) { return y(d.y0) - y(d.y1); })
                                .style("fill", function(d) { return color(d.name); });

                            var legend = svg.select(".state:last-child").selectAll(".legend")
                                .data(function(d) { return d.ages; })
                                .enter().append("g")
                                .attr("class", "legend")
                                .attr("transform", function(d) { return "translate(" + x.rangeBand() / 2 + "," + y((d.y0 + d.y1) / 2) + ")"; });

                            legend.append("line")
                                .attr("x2", 10);

                            legend.append("text")
                                .attr("x", 13)
                                .attr("dy", ".35em")
                                .text(function(d) { return d.name; });
*/
                        };
                    });
                }
            };
        }]);
