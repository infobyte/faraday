'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
class Conflict():
	def __init__(self, first_object, second_object):
		self.type = None
		self.model_object_type = first_object.class_signature
		self.first_object = first_object
		self.second_object = second_object

	def getFirstObject(self):
		return self.first_object

	def getSecondObject(self):
		return self.second_object

	def getType(self):
		return self.type

	def getModelObjectType(self):
		return self.model_object_type

	def resolve(self, kwargs):
		return False


class ConflictUpdate(Conflict):
	def __init__(self, first_object, second_object):
		Conflict.__init__(self, first_object, second_object)
		self.type = "Update"

	def resolve(self, kwargs):
		self.first_object.updateAttributes(**kwargs)
		self.first_object.updateResolved(self)
		return True


		
