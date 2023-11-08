
from chipsec.logger import logger
from chipsec.chipset import cs
from chipsec.banner import print_banner as csb_print_banner
from chipsec.defines import get_version as csd_get_version, get_message as csd_get_message


class ChipsecTerminal:
    def __call__(self):
        print("wat2")
    class Platform:
        def __init__(self, cst):
            self.selected = False 
            self.cfg = None
            self.cst = cst

        def init_cfg_bus(self):
            self.cst.chipset.init_cfg_bus()

        def detect(self):
            self.cst.chipset.Cfg.platform_detection(None, None, None)

        def select(self):
            print("selected")
            pass

        def forget(self):
            print("forgotten")
            pass

        def unload_cfg(self):
            print("unloaded cfg")
            del self.cfg
            self.cfg = None

        def load_cfg(self):
            pass

    class Helper:
        def __call__(self):
            if self.cst.chipset.helper is None:
                print("No helper loaded. Please load a helper or use cst.helper.default()")
            return self.cst.chipset.helper

        def __init__(self, cst):
            self.cst = cst
            self._is_loaded = False
            self._is_running = False
        
        def load(self, helper):
            self.cst.chipset.load_helper(helper)
            self._is_loaded = True

        def unload(self):
            self.cst.chipset.destroy_helper()
            self._is_loaded = False
            self._is_running = False
        
        def start(self):
            if not self._is_loaded:
                raise HelperNotLoadedException()
            self.cst.chipset.start_helper()
            self._is_running = True

        def stop(self):
            self._is_running = not self.cst.chipset.helper.stop()

        def switch(self, helper):
            self.cst.chipset.switch_helper(helper)
            self._is_loaded = True
            self._is_running = True

        def default(self):
            defaulthelper = self.cst.chipset.os_helper.get_default_helper()
            self.load(defaulthelper)
            self.start()
        
        def isloaded(self):
            return self._is_loaded and self.cst.chipset.helper is not None

        def isrunning(self):
            return self._is_running

        def list_helpers(self):
            print(self.cst.chipset.os_helper.get_available_helpers())


    def print_banner(self):
        csb_print_banner("N/A", csd_get_version(), csd_get_message())
    
    def __init__(self):
        self.logger = logger()
        self.chipset = cs()
        self.platform = self.Platform(self)
        self.helper = self.Helper(self)



        
    


def __call__():
    print("wat")

cst = ChipsecTerminal()


# Need:
#   Way to list commands
#   Load commands (From Helpers/HALs/Utils)
#   Load helper
#   Unload helper
#   Load config
#   Unload config
#   Run command


class HelperNotLoadedException(RuntimeError):
    pass