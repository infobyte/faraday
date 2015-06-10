// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .directive('d3HorizontalStackedBar', ['d3Service', 
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
                            var margins = {
                                top: 12,
                                left: 48,
                                right: 24,
                                bottom: 24
                            },
                            legendPanel = {
                                width: 180
                            },
                            width = 500 - margins.left - margins.right - legendPanel.width,
                            height = 100 - margins.top - margins.bottom,
                            series = data.map(function(d) {
                                return {"key": d.key, "color": d.color};
                            });
                            dataset = data.map(function(d) {
                                    return [{
                                        c: d.color,
                                        y: d.value,
                                        x: 0
                                    }];
                            });
                            stack = d3.layout.stack();

                            stack(dataset);

                            var dataset = dataset.map(function (group) {
                                return group.map(function (d) {
                                    // Invert the x and y values, and y0 becomes x0
                                    return {
                                        c: d.c,
                                        x: d.y,
                                        y: d.x,
                                        x0: d.y0
                                    };
                                });
                            }),
                            svg = d3.select(".stackedbars")
                                .append('svg')
                                .attr('width', width + margins.left + margins.right + legendPanel.width)
                                .attr('height', height + margins.top + margins.bottom)
                                .append('g')
                                .attr('transform', 'translate(' + margins.left + ',' + margins.top + ')'),
                            xMax = d3.max(dataset, function (group) {
                                return d3.max(group, function (d) {
                                    return d.x + d.x0;
                                });
                            }),
                            xScale = d3.scale.linear()
                                .domain([0, xMax])
                                .range([0, width]),
                            months = dataset[0].map(function (d) {
                                return d.y;
                            }),
                            yScale = d3.scale.ordinal()
                                .domain(months)
                                .rangeRoundBands([0, height], .1),
                            xAxis = d3.svg.axis()
                                .scale(xScale)
                                .orient('bottom'),
                            yAxis = d3.svg.axis()
                                .scale(yScale)
                                .orient('left'),
                            colours = d3.scale.category10(),
                            groups = svg.selectAll('g')
                                .data(dataset)
                                .enter()
                                .append('g')
                                .style('fill', function (d, i) {
                                return d[0].c;
                            }),
                            rects = groups.selectAll('rect')
                                .data(function (d) {
                                return d;
                            })
                                .enter()
                                .append('rect')
                                .attr('x', function (d) {
                                return xScale(d.x0);
                            })
                                .attr('y', function (d, i) {
                                return yScale(d.y);
                            })
                                .attr('height', function (d) {
                                return yScale.rangeBand();
                            })
                                .attr('width', function (d) {
                                return xScale(d.x);
                            })
                                // this adds tooltips, and its not working - maybe styles?
                                .on('mouseover', function (d) {
                                var xPos = parseFloat(d3.select(this).attr('x')) / 2 + width / 2;
                                var yPos = parseFloat(d3.select(this).attr('y')) + yScale.rangeBand() / 2;

                                d3.select('#tooltip')
                                    .style('left', xPos + 'px')
                                    .style('top', yPos + 'px')
                                    .select('#value')
                                    .text(d.x);

                                d3.select('#tooltip').classed('hidden', false);
                            })
                            .on('mouseout', function () {
                                d3.select('#tooltip').classed('hidden', true);
                            });

                        /* this adds the chart of reference, which color belongs to each label, etc
                            // i think it should be done without D3 since its easier to handle style etc
                            svg.append('rect')
                                .attr('fill', 'grey')
                                .attr('width', 160)
                                .attr('height', 30 * dataset.length)
                                .attr('x', width + margins.left)
                                .attr('y', 0);

                            series.forEach(function(s, i) {
                                svg.append('text')
                                    .attr('fill', 'black')
                                    .attr('x', width + margins.left + 8)
                                    .attr('y', i * 24 + 24)
                                    .text(s.key);
                                svg.append('rect')
                                    .attr('fill', s.color)
                                    .attr('width', 60)
                                    .attr('height', 20)
                                    .attr('x', width + margins.left + 90)
                                    .attr('y', i * 24 + 6);
                            });
                        */

                        };
                    });
                }
            };
        }]);
