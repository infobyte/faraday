#!/usr/bin/env sh
cd ..
# nosetests2 --no-byte-compile --with-coverage --cover-html --cover-html-dir=cover  --cover-package=auth --cover-package=bin --cover-package=config --cover-package=exporters --cover-package=external --cover-package=gui --cover-package=managers --cover-package=model --cover-package=persistence --cover-package=plugins --cover-package=shell --cover-package=utils test_cases/model_controller.py
# nosetests2 --no-byte-compile --with-coverage --cover-html --cover-html-dir=cover  --cover-package=auth --cover-package=bin --cover-package=config --cover-package=exporters --cover-package=external --cover-package=gui --cover-package=managers --cover-package=model --cover-package=persistence --cover-package=plugins --cover-package=shell --cover-package=utils test_cases/model_controller.py
# nosetests2 --with-coverage --cover-html --cover-html-dir=cover  --cover-package=model test_cases/*.py
nosetests --ignore-files='.*dont_run_rest_controller_apis.*' --no-byte-compile -v `find test_cases -name '*.py' | grep -v dont_run`

