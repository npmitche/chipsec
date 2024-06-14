from chipsec.parsers import BaseConfigParser, BaseConfigHelper
from chipsec.parsers import Stage
from collections import namedtuple
from chipsec.lib.tpmi import PFS_TPMI_ID

tpmientry = namedtuple('TPMIEntry', ['name', 'type', 'size', 'tpmiOffset', 'tpmiId', 'subId', 'featureId', 'default', 'desc', 'fields'])
fieldentry = namedtuple('fieldEntry', ['name', 'bit', 'size', 'access', 'default', 'desc'])

class TPMIParser(BaseConfigParser):
    def startup(self):
        if not hasattr(self.cfg, 'TPMI'):
            setattr(self.cfg, 'TPMI', [])

    def get_metadata(self):
        return {'register': self.access_handler}

    def parser_name(self):
        return 'TPMI'

    def get_stage(self):
        return Stage.EXTRA

    def access_handler(self, et_node, stage_data):
        for child in et_node.iter('register'):
            reg_fields = []
            for field in child.iter('field'):
                reg_fields.append(self._convert_field_data(field.attrib))
            child.attrib['fields'] = reg_fields
            self.cfg.TPMI.append(self._convert_range_data(child.attrib))

    def _convert_range_data(self, xml_node):
        entries = ['name', 'type', 'size', 'tpmiOffset', 'tpmiId', 'subId', 'featureId', 'default', 'desc', 'fields']
        tmp = {}
        for entry in entries:
            if entry in xml_node:
                if entry == 'size':
                    tmp[entry] = int(xml_node[entry], 10)
                elif entry in ['subId', 'featureId'] and xml_node[entry] == 'N/A':
                    tmp[entry] = None
                elif entry in ['tpmiOffset', 'tpmiId', 'subId', 'featureId', 'default']:
                    tmp[entry] = int(xml_node[entry], 16)
                else:
                    tmp[entry] = xml_node[entry]
            else:
                tmp[entry] = None
        return tpmientry(tmp['name'], tmp['type'], tmp['size'], tmp['tpmiOffset'], tmp['tpmiId'], tmp['subId'], tmp['featureId'], tmp['default'], tmp['desc'], tmp['fields'])

    def _convert_field_data(self, xml_node):
        entries = ['name', 'bit', 'size', 'access', 'default', 'desc']
        tmp = {}
        for entry in entries:
            if entry in xml_node:
                if entry in ['size', 'bit']:
                    tmp[entry] = int(xml_node[entry], 10)
                elif entry in ['default']:
                    tmp[entry] = int(xml_node[entry], 16)
                else:
                    tmp[entry] = xml_node[entry]
            else:
                tmp[entry] = None
        return fieldentry(tmp['name'], tmp['bit'], tmp['size'], tmp['access'], tmp['default'], tmp['desc'])

class TPMICommands(BaseConfigHelper):
    def __init__(self, cfg_obj):
        super().__init__(cfg_obj)
        self.regs = self.cfg.TPMI
        self.start_addrs = {}

    def get_reg(self, name):
        for reg in self.regs:
            if reg.name == name:
                return reg
        return None

    def get_regs(self, id=None):
        ret = []
        for reg in self.regs:
            if id is None or id == reg.tpmiId:
                ret.append(reg)
        return ret

    def set_start_addrs(self, addrs):
        self.start_addrs = addrs

    def get_start_addr(self, id, instance):
        if id in self.start_addrs.keys() and instance in self.start_addrs[id].keys():
            return self.start_addrs[id][instance]
        return None

    def get_available(self):
        ret = []
        for id in PFS_TPMI_ID:
            if id in self.start_addrs:
                for instance in self.start_addrs[id].keys():
                    ret.append((id, instance))
        return ret


parsers = {TPMIParser}
