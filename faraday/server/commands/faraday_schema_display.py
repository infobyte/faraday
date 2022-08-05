"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Standard library imports
import sys

# Related third party imports
from sqlalchemy import MetaData
from sqlalchemy.orm import class_mapper

# Local application imports
import faraday.server.config
from faraday.server import models


class DatabaseSchema:

    def run(self):
        self._draw_entity_diagram()
        self._draw_uml_class_diagram()

    @property
    def description(self):
        return 'Generates an entity diagram and uml class diagram from the implemented model'

    @staticmethod
    def _draw_entity_diagram():
        # create the pydot graph object by autoloading all tables via a bound metadata object
        try:
            from sqlalchemy_schemadisplay import create_schema_graph  # pylint:disable=import-outside-toplevel
        except ImportError:
            print('Please install sqlalchemy_schemadisplay with "pip install sqlalchemy_schemadisplay"')
            sys.exit(1)
        graph = create_schema_graph(
            metadata=MetaData(faraday.server.config.database.connection_string.strip("'")),
            show_datatypes=False,  # The image would get nasty big if we'd show the datatypes
            show_indexes=False,  # ditto for indexes
            rankdir='LR',  # From left to right (instead of top to bottom)
            concentrate=False  # Don't try to join the relation lines together
        )
        try:
            graph.write_png('entity_dbschema.png')  # write out the file
        except OSError as ex:
            if 'dot' in ex.strerror:
                print('Rendering entity schema requires dot. Please install it with: sudo apt install xdot')
                sys.exit(1)
            raise

    @staticmethod
    def _draw_uml_class_diagram():
        # lets find all the mappers in our model
        try:
            from sqlalchemy_schemadisplay import create_uml_graph  # pylint:disable=import-outside-toplevel
        except ImportError:
            print('Please install sqlalchemy_schemadisplay with "pip install sqlalchemy_schemadisplay"')
            sys.exit(1)
        mappers = []
        for attr in dir(models):
            if attr[0] == '_':
                continue
            try:
                cls = getattr(models, attr)
                mappers.append(class_mapper(cls))
            except Exception as ex:
                print(ex)

        # pass them to the function and set some formatting options
        graph = create_uml_graph(
            mappers,
            show_operations=False,  # not necessary in this case
            show_multiplicity_one=False,  # some people like to see the ones, some don't
            # show_attributes=False,  # Uncomment to don't show fields, only model names
        )
        graph.write_png('uml_schema.png')  # write out the file
        print("Graph written to fle uml_schema.png")
