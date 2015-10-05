// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

module.exports = function(config){
  config.set({

    basePath : './',

    files : [ 
      '../views/reports/_attachments/script/jquery-1.11.2.js',
      '../views/reports/_attachments/script/angular.js',
      '../views/reports/_attachments/script/angular-mocks.js',
      '../views/reports/_attachments/script/angular-route.js',
      '../views/reports/_attachments/script/angular-selection-model.js',
      '../views/reports/_attachments/script/*bootstrap*.js',
      '../views/reports/_attachments/scripts/app.js',
      '../views/reports/_attachments/scripts/**/*.js',
      '../tests_web/faradayApp/components/**/*.js',
      '../views/reports/_attachments/script/angular-file-upload-shim.js',
      '../views/reports/_attachments/script/angular-file-upload.js',
      '../views/reports/_attachments/script/ngClip.js',
      '../views/reports/_attachments/script/angular-cookies.js',
      '../views/reports/_attachments/script/ZeroClipboard.min.js',
      '../views/reports/_attachments/script/mousetrap.js',
      '../views/reports/_attachments/script/angular-hotkeys.js',
      '../views/reports/_attachments/script/cryptojs-sha1.js',
      '../views/reports/_attachments/script/Chart.js',
      '../views/reports/_attachments/script/angular-chart.min.js'
    ],

    autoWatch : true,

    frameworks: ['jasmine'],

    browsers : ['Chrome'],

    plugins : [
            'karma-chrome-launcher',
            'karma-firefox-launcher',
            'karma-jasmine',
            'karma-junit-reporter'
            ],

    junitReporter : {
      outputFile: 'test_out/unit.xml',
      suite: 'unit'
    }

  });
};
