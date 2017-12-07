from __future__ import print_function
import sys
from sqlalchemy import MetaData
try:
    from sqlalchemy_schemadisplay import create_schema_graph
    from sqlalchemy_schemadisplay import create_uml_graph
except ImportError:
    print('Please install sqlalchemy_schemadisplay with "pip install sqlalchemy_schemadisplay"')
    sys.exit(1)
from sqlalchemy.orm import class_mapper

from server import models
import server.config


class DatabaseSchema():

    def run(self):
        self._draw_entity_diagrama()
        self._draw_uml_class_diagram()

    @property
    def description(self):
        return 'Generates an entity diagram and uml class diagram from the implemented model'

    def _draw_entity_diagrama(self):
        # create the pydot graph object by autoloading all tables via a bound metadata object
        graph = create_schema_graph(
            metadata=MetaData(server.config.database.connection_string.strip("'")),
            show_datatypes=False,  # The image would get nasty big if we'd show the datatypes
            show_indexes=False,  # ditto for indexes
            rankdir='LR',  # From left to right (instead of top to bottom)
            concentrate=False  # Don't try to join the relation lines together
        )
        graph.write_png('entity_dbschema.png')  # write out the file

    def _draw_uml_class_diagram(self):
        # lets find all the mappers in our model
        mappers = []
        for attr in dir(models):
            if attr[0] == '_':
                continue
            try:
                cls = getattr(models, attr)
                mappers.append(class_mapper(cls))
            except:
                pass

        # pass them to the function and set some formatting options
        graph = create_uml_graph(
            mappers,
            show_operations=False,  # not necessary in this case
            show_multiplicity_one=False,  # some people like to see the ones, some don't
            # show_attributes=False,  # Uncomment to don't show fields, only model names
        )
        graph.write_png('uml_schema.png')  # write out the file
        print("Graph written to fle uml_schema.png")
