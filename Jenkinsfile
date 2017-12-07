#!groovy
node {
    def ENV_PATH = "$HOME/venv/faraday"
    echo "${ENV_PATH}"

    stage("Clean virtualenv") {
        sh "rm -rf ${ENV_PATH}"
    }

    stage("Install Python Virtual Enviroment") {
        sh "/usr/local/bin/virtualenv --no-site-packages ${ENV_PATH}"
    }

    // Get the latest version of our application code.
    stage ("Pull Code from SCM") {
        checkout scm
    }

    stage ("Install Application Dependencies") {
        sh """
            source ${ENV_PATH}/bin/activate
            pip install virtualenv responses
            pip install -r $WORKSPACE/requirements.txt
            pip install -r $WORKSPACE/requirements_server.txt
            pip install -r $WORKSPACE/requirements_extras.txt
            pip install -r $WORKSPACE/requirements_dev.txt
            pip uninstall -y filteralchemy
            pip install -e git+https://github.com/sh4r3m4n/filteralchemy@dev#egg=filteralchemy
            deactivate
           """
    }

    stage ("Check code style") {
        sh """
            sloccount --duplicates --wide --details $WORKSPACE   | fgrep -v .git > $WORKSPACE/sloccount.sc || :
            find $WORKSPACE -name \\"*.py\\" | egrep -v '^./tests/'  | xargs pyflakes  > $WORKSPACE/pyflakes.log || :
            find $WORKSPACE -name \\"*.py\\" | egrep -v '^./tests/'  | xargs pylint --output-format=parseable --reports=y > $WORKSPACE/pylint.log || :
            eslint -c /home/faraday/.eslintrc.js -f checkstyle $WORKSPACE/server/www/scripts/**/* > eslint.xml || true

           """
           warnings canComputeNew: false, canResolveRelativePaths: false, consoleParsers: [[parserName: 'PyFlakes']], defaultEncoding: '', excludePattern: '', healthy: '', includePattern: '', messagesPattern: '', parserConfigurations: [[parserName: 'AcuCobol Compiler', pattern: 'pyflakes.log']], unHealthy: ''

    }

    stage ("Run Unit/Integration Tests") {
        def testsError = null
        try {
            sh """
                source ${ENV_PATH}/bin/activate
                cd $WORKSPACE && pytest -v  --junitxml=$WORKSPACE/xunit.xml || :
                deactivate
               """
               step([$class: 'CoberturaPublisher', autoUpdateHealth: false, autoUpdateStability: false, coberturaReportFile: '**/coverage.xml', failNoReports: false, failUnhealthy: false, failUnstable: false, maxNumberOfBuilds: 0, onlyStable: false, sourceEncoding: 'ASCII', zoomCoverageChart: false])
        }
        catch(err) {
            testsError = err
            currentBuild.result = 'FAILURE'
        }
        finally {
            junit "**/xunit.xml"

            if (testsError) {
                throw testsError
            }
        }
    }

    stage ("Run Unit/Integration Tests (with PostgreSQL)") {
        def testsError = null
        try {
            withCredentials([string(credentialsId: 'postgresql_connection_string', variable: 'CONN_STRING')]) {
                sh """
                    source ${ENV_PATH}/bin/activate
                    cd $WORKSPACE && pytest -v  --junitxml=$WORKSPACE/xunit-postgres.xml --connection-string "$CONN_STRING" || :
                    deactivate
                """
                step([$class: 'CoberturaPublisher', autoUpdateHealth: false, autoUpdateStability: false, coberturaReportFile: '**/coverage.xml', failNoReports: false, failUnhealthy: false, failUnstable: false, maxNumberOfBuilds: 0, onlyStable: false, sourceEncoding: 'ASCII', zoomCoverageChart: false])
            }
        }
        catch(err) {
            testsError = err
            currentBuild.result = 'FAILURE'
        }
        finally {
            junit "**/xunit-postgres.xml"

            if (testsError) {
                throw testsError
            }
        }
    }

    stage ("Build docs") {
        sh """
            pip install sphinx
            mkdir -p ~/docs
            rm -rf ~/docs/jenkins_build
            cd $WORKSPACE/doc && make html && cp -r _build/html ~/docs/jenkins_build
        """
    }
}
