import unittest
from ProcessPools import CabMgr, PSFXMgr, PEMgr, SymMgr, DBMgr

class test_managers(unittest.TestCase):

    patchdir = ""
    basedir = ""
    destdir = ""
    symserver = ""
    symdest = ""

    def setUp(self) -> None:
        symbols = SymMgr(4, test_managers.symserver, test_managers.symdest, None)
        pes = PEMgr(4, symbols, None)
        psfx = PSFXMgr(test_managers.patchdir, test_managers.destdir, 4, pes, None, False, None, test_managers.basedir)
        cab = CabMgr(test_managers.patchdir, test_managers.destdir, 4, pes, psfx, None, False, None)
        return super().setUp()

    def tearDown(self) -> None:
        return super().tearDown()

    def test_extractTask():
        return
    
    def test_passresult():
        return
