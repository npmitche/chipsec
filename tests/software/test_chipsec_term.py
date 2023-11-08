

import unittest
from unittest.mock import Mock
import chipsec_term as cst
import chipsec.logger

class TestChipsecTerminal(unittest.TestCase):
    def setUp(self):
        self._cst = cst.ChipsecTerminal()
        self._cst.logger = Mock()
        self._cst.chipset = Mock()
        pass

    def test_cst(self):
        self.assertIsInstance(self._cst, cst.ChipsecTerminal)

    def test_cst_platform(self):
        self.assertIsInstance(self._cst.platform, cst.ChipsecTerminal.Platform)

    def test_cst_helper(self):
        self.assertIsInstance(self._cst.helper, cst.ChipsecTerminal.Helper)

    def test_cst_platform_init_cfg_bus_was_run(self):
        self._cst.platform.init_cfg_bus()
        self._cst.chipset.init_cfg_bus.assert_called_once()

    def test_cst_helper_load_was_run(self):
        self._cst.helper.load("replayhelper")
        self._cst.chipset.load_helper.assert_called_once()

    def test_cst_helper_unload_was_run(self):
        self._cst.helper.unload()
        self._cst.chipset.destroy_helper.assert_called_once()

    def test_cst_helper_switch_was_run(self):
        self._cst.helper.switch("recordhelper")
        self._cst.chipset.switch_helper.assert_called_once()

    def test_cst_helper_is_loaded_freash(self):
        is_loaded = self._cst.helper.isloaded()
        self.assertFalse(is_loaded)

    def test_cst_helper_is_loaded_after_load(self):
        self._cst.helper.load("replayhelper")
        is_loaded = self._cst.helper.isloaded()
        self.assertTrue(is_loaded)

    def test_cst_helper_is_unloaded_after_load_unload(self):
        self._cst.helper.load("replayhelper")
        self._cst.helper.unload()
        is_loaded = self._cst.helper.isloaded()
        self.assertFalse(is_loaded)

    def test_cst_helper_is_loaded_after_switch(self):
        self._cst.helper.switch("replayhelper")
        is_loaded = self._cst.helper.isloaded()
        self.assertTrue(is_loaded)

    def test_cst_helper_is_unloaded_after_switch_unload(self):
        self._cst.helper.switch("replayhelper")
        self._cst.helper.unload()
        is_loaded = self._cst.helper.isloaded()
        self.assertFalse(is_loaded)

    def test_cst_helper_stopped_freash(self):
        is_running = self._cst.helper.isrunning()
        self.assertFalse(is_running)

    def test_cst_helper_started_freash(self):
        self._cst.helper.load("windowshelper")
        self._cst.helper.start()
        is_running = self._cst.helper.isrunning()
        self.assertTrue(is_running)

    def test_cst_helper_stopped_after_start(self):
        self._cst.helper.load("windowshelper")
        self._cst.helper.start()
        self._cst.helper.stop()
        is_running = self._cst.helper.isrunning()
        self.assertFalse(is_running)

    def test_cst_helper_exception_when_start_before_load(self):
        self.assertRaises(cst.HelperNotLoadedException, self._cst.helper.start)

    def test_cst_helper_load_and_start_default(self):
        self._cst.helper.default()
        self.assertTrue(self._cst.helper.isloaded())
        self.assertTrue(self._cst.helper.isrunning())