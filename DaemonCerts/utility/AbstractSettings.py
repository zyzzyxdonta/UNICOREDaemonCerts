# -*- coding: utf-8 -*-
import abc
from six import string_types
import logging
import yaml
import yaml.constructor
from ast import literal_eval


# Abstract Settings base class, handles both a settings format and a commandline parser
# Override _set_defaults in child class

# To use this class, check the code at the end of this file and do the same.

### Taken from: https://gist.github.com/enaeseth/844388#file-yaml_ordered_dict-py
try:
    # included in standard lib from Python 2.7
    from collections import OrderedDict
except ImportError:
    # try importing the backported drop-in replacement
    # it's available on PyPI
    from ordereddict import OrderedDict

class AttributeDict(OrderedDict):
    def __getattr__(self, attr):
        # This is a python2 specific workaround, reason:
        # in python2 OrderedDict queries for self.__root, which might be callable.
        # If it is not there, an attributeerror is thrown. We have to catch this.
        # Therefore we check first if the attribute exists in the dict and if not we raise an anonymous attriberror
        if not attr in self:
            raise AttributeError()

        returnvalue = self[attr]
        if isinstance(returnvalue,dict):
            return AttributeDict(returnvalue)
        else:
            return returnvalue

class OrderedDictYAMLLoader(yaml.Loader):
    """
    A YAML loader that loads mappings into ordered dictionaries.
    """

    def __init__(self, *args, **kwargs):
        yaml.Loader.__init__(self, *args, **kwargs)

        self.add_constructor(u'tag:yaml.org,2002:map', type(self).construct_yaml_map)
        self.add_constructor(u'tag:yaml.org,2002:omap', type(self).construct_yaml_map)

    def construct_yaml_map(self, node):
        data = AttributeDict()
        yield data
        value = self.construct_mapping(node)
        data.update(value)

    def construct_mapping(self, node, deep=False):
        if isinstance(node, yaml.MappingNode):
            self.flatten_mapping(node)
        else:
            raise yaml.constructor.ConstructorError(None, None,
                'expected a mapping node, but found %s' % node.id, node.start_mark)

        mapping = AttributeDict()
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                hash(key)
            except TypeError as exc:
                raise yaml.constructor.ConstructorError('while constructing a mapping',
                    node.start_mark, 'found unacceptable key (%s)' % exc, key_node.start_mark)
            value = self.construct_object(value_node, deep=deep)
            mapping[key] = value
        return mapping

def represent_attributedict(dumper, data):
    value = []

    for item_key, item_value in data.items():
        node_key = dumper.represent_data(item_key)
        node_value = dumper.represent_data(item_value)

        value.append((node_key, node_value))

    return yaml.nodes.MappingNode(u'tag:yaml.org,2002:map', value)

yaml.add_representer(AttributeDict, represent_attributedict)

class AbstractSettings(object):
    my_instance = None
    def __init__(self,name,logger = None):
        self.original_args = None
        self.logger = logger or logging.getLogger(__name__)
        self.name = name
        self.settings_container = AttributeDict()
        self.explanations = AttributeDict()
        self._set_defaults()
        pass

    def get_original_args(self):
        return self.original_args

    def _cast_string_to_correct_type(self,string):
        #Negative Numbers isdigit:
        if string.replace('-','').isdigit():
            return int(string)
        try:
            float(string)
            return float(string)
        except ValueError:
            pass
        if string == "True":
            return True
        if string == "False":
            return False

        try:
            mylist = literal_eval(string)
            if isinstance(mylist,list):
                return mylist
        except:
            # In this case anything above could have gone wrong, which means
            # that the string is just a string.
            pass

        return string

    @classmethod
    def cls_print_options(cls,outstream):
        tempini = cls()
        tempini.print_options(outstream=outstream)

    @classmethod
    def cls_dump_to_file_template(cls, outfile):
        tempini = cls()
        tempini.dump_to_file(outfile)

    @classmethod
    def get_instance(cls,filename = "settings.yml", commandline_args = None):

        if cls.my_instance == None:
            cls.my_instance = cls()
            cls.my_instance.read_from_file(filename)
            if (commandline_args != None):
                cls.my_instance.parse_args(commandline_args)
            cls.my_instance._finish_parsing()
            cls.my_instance.dump_to_file(filename)

        return cls.my_instance

    def read_from_file(self,filename):
        with open(filename,'r') as infile:
            self.settings_container = yaml.load(infile,OrderedDictYAMLLoader)

    def dump_to_file(self,filename):
        with open(filename,'w') as outfile:
            outfile.write(yaml.dump(self.settings_container,default_flow_style=False))

    def as_dict(self):
        return self.settings_container

    def __getattr__(self, item):
        returndict = self.get_value(item)
        if isinstance(returndict,dict):
            return AttributeDict(returndict)
        else:
            return returndict

    @abc.abstractmethod
    def _set_defaults(self):
        raise NotImplementedError("Abstract Virtual Method, please implement in child class")
        return

    def _add_default(self,valuename,value,explanation):
        eq_arg = "%s=%s" %(valuename,value)
        self.explanations[valuename] = explanation
        self.parse_eq_args([eq_arg],True)

    def get_value(self,valuename):
        splitname = valuename.split(".")
        current_dict = self.settings_container
        for key in splitname[:-1]:
            current_dict = current_dict[key]
        return current_dict[splitname[-1]]

    #Set Value actually creates the entry:
    def set_value(self,valuename,value):
        splitname = valuename.split(".")
        current_dict = self.settings_container
        for key in splitname[:-1]:
            if not key in current_dict:
                current_dict[key] = AttributeDict()
            current_dict = current_dict[key]
        current_dict[splitname[-1]] = value

    def print_options(self,outstream):
        outstream.write("%s paramaters: \n" %(self.name))
        for valuename in sorted(self.explanations.keys()):
            explanation = self.explanations[valuename]
            outstream.write("\t%s:\n\t\t%s\n\t\tDefault: %s.\n" %(valuename,explanation,self.get_value(valuename)))

    #The next two functions allow overriding dict values
    #This function returns
    # for the input abc.def=540.0
    # [["abc","def"],540.0]
    @staticmethod
    def settingsplit(infield):
        splitvalues = infield.split("=")
        if len(splitvalues) > 1:
            return (splitvalues[0].split("."),"=".join(splitvalues[1:]))
        else:
            raise ValueError()

    #if args contains abc.def=640.0, self["abc"]["def"]=640.0 will be set
    #with createdicts == False, the dicts have to exist already
    def parse_eq_args(self,args, createdicts = False):
        self.original_args = args
        for argtuple in args:
            self.logger.debug("Parsing:",argtuple)
            try:
                splitset = AbstractSettings.settingsplit(argtuple)
                current_dict=self.settings_container
                for field in splitset[0][:-1]:
                    if (not field in current_dict) and createdicts:
                        current_dict[field] = AttributeDict()
                    if (not field in current_dict):
                        raise KeyError("The settings module did not contain %s. Please check your input."
                        % argtuple )
                    current_dict = current_dict[field]
                final_key = splitset[0][-1]
                if final_key in current_dict or createdicts:
                    current_dict[final_key] = self._cast_string_to_correct_type(splitset[1])
                else:
                    raise KeyError("The settings module did not contain %s. Please check your input."
                    % argtuple )
            except ValueError:
                #We don't discard args with another format to allow for things like argparse
                pass


    def _recursive_helper_finish(self,mydict):
        for key,value in mydict.items():
            if isinstance(value, dict):
                self._recursive_helper_finish(value)
            else:
                if isinstance(value,string_types):
                    if value.startswith("sameas:"):
                        splitsameas = value.split(":")
                        mydict[key] = self.get_value(splitsameas[1])

    def _finish_parsing(self):
        self._recursive_helper_finish(self.settings_container)


if __name__ == '__main__':
    #Small unit test.  
    import os,sys
    
    class TestSettings(AbstractSettings):
        def __init__(self):
            super(TestSettings,self).__init__("TestSettings")

        def _set_defaults(self):
            defaults = [
                ('Box.Lx' , 25.0 , "Half box length, x direction [Angstrom]"),
                ('Box.Ly' , "sameas:Box.Lx",  "Half box length, y direction [Angstrom] By default same as Box.Lx"),
                ('Temperature', 50.0, "Temperature of the sim"),
                ('simparams.acceptance', 1.0, 'Acceptance factor of simulation'),
                ('settings.filename','TestSettings.yml','Filename of the file the chosen settings are written to')
                ]
            for valuename,default,explanation in defaults:
                self._add_default(valuename,default,explanation)
    
    myset = TestSettings()
    myset.parse_eq_args(sys.argv[1:])
    myset._finish_parsing()
    
    if len(sys.argv) <= 1:
        print("Use this class with: %s Box.Lx=11" % os.path.basename(__file__))
        print("Afterwards check the file TestSettings.yml\n")
        myset.print_options(sys.stdout)
        
    #These are the current two ways to access the data:
    settings_filename = myset.get_value('settings.filename')
    settings_filename2 = myset.as_dict()['settings']['filename']
    assert(settings_filename == settings_filename2)
    myset.dump_to_file(settings_filename)
    print("\nWrote settings to %s" % settings_filename)
