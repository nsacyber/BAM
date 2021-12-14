from sqlite3.dbapi2 import connect
import unittest
import pefile
import asyncio
from unittest import TestCase
from pefile import set_flags
from ProcessPools import SymMgr, DBMgr
from db.wsuse_db import construct_tables
from globs import DBCONN
from support.utils import getfilehashes, getpesigwoage, getpearch

class test_SymManager(unittest.TestCase):

    def setUp(self) -> None:
        self.dbmgr = DBMgr("C:\\BAM testing\\testoutput", DBCONN)
        self.symmgr = SymMgr(4, "https://msdl.microsoft.com/download/symbols", 'C:\\BAM Testing\\symbols', self.dbmgr)

        construct_tables(DBCONN)

        return super().setUp()

    def tearDown(self) -> None:
        return super().tearDown()

    def test_pestarstsig(self):
        self.symmgr.peRunning.clear()
        self.symmgr.pestartsig()

        unittest.TestCase.assertTrue(self, self.symmgr.peRunning.is_set())

    def test_pedonesig(self):
        self.symmgr.peRunning.set()
        self.symmgr.pedonesig()

        unittest.TestCase.assertFalse(self, self.symmgr.peRunning.is_set())

    def test_addjob(self):
        item = "C:\\BAM testing\\testoutput\\windows10.0-kb5003690-x86_e10cb6c6d79dd3b4e559c6b5612a4c46c7ecc5f2\\Windows10.0-KB5003690-x86\\SSU-19041.1081-x86\\x86_microsoft-windows-s..cingstack-onecoreds_31bf3856ad364e35_10.0.19041.1081_none_cd17c81a1e6cbd31\\offlinelsa.dll"
        self.symmgr.addjob(item)
        output = self.symmgr.jobs.get(item)

        unittest.TestCase.assertEqual(self, item, output)

    def test_symtask(self):
        item = "C:\\BAM testing\\testoutput\\windows10.0-kb5003690-x86_e10cb6c6d79dd3b4e559c6b5612a4c46c7ecc5f2\\Windows10.0-KB5003690-x86\\SSU-19041.1081-x86\\x86_microsoft-windows-s..cingstack-onecoreds_31bf3856ad364e35_10.0.19041.1081_none_cd17c81a1e6cbd31\\offlinelsa.dll"
        hashes = getfilehashes(item)
        package = (item, hashes[0], hashes[1])

        try:
            unpefile = pefile.PE(item)
        except pefile.PEFormatError as peerror:
            unittest.TestCase.fail()
        signature = getpesigwoage(unpefile)
        arch = getpearch(unpefile)
        unpefile.close()

        output = SymMgr.symtask(package, self.symmgr.symserver, self.symmgr.symdest, False)

        unittest.TestCase.assertIsNotNone(self, output[0])
        unittest.TestCase.assertEqual(self, signature, output[3]['signature'])
        unittest.TestCase.assertEqual(self, arch, output[3]['arch'])
    
    def test_makedbrequest(self):
        event_loop = asyncio.new_event_loop()
        future = event_loop.create_future()
        item = "C:\\BAM testing\\testoutput\\windows10.0-kb5003690-x86_e10cb6c6d79dd3b4e559c6b5612a4c46c7ecc5f2\\Windows10.0-KB5003690-x86\\SSU-19041.1081-x86\\x86_microsoft-windows-s..cingstack-onecoreds_31bf3856ad364e35_10.0.19041.1081_none_cd17c81a1e6cbd31\\offlinelsa.dll"
        hashes = getfilehashes(item)
        package = (item, hashes[0], hashes[1])
        result = self.symmgr.symtask(package, self.symmgr.symserver, self.symmgr.symdest, False)
        future.set_result(result)
        optype = "symbol"
        sampletask = (optype, result[0], result[1], result[2], result[3])

        self.symmgr.makedbrequest(future)

        unittest.TestCase.assertEqual(self, self.dbmgr.jobqueue.get(), sampletask)
        unittest.TestCase.assertTrue(self, self.dbmgr.jobsig.is_set())
        

    def test_run(self):
        item = "C:\\BAM testing\\testoutput\\windows10.0-kb5003690-x86_e10cb6c6d79dd3b4e559c6b5612a4c46c7ecc5f2\\Windows10.0-KB5003690-x86\\SSU-19041.1081-x86\\x86_microsoft-windows-s..cingstack-onecoreds_31bf3856ad364e35_10.0.19041.1081_none_cd17c81a1e6cbd31\\offlinelsa.dll"
        hashes = getfilehashes(item)
        package = (item, hashes[0], hashes[1])
        self.symmgr.addjob(package)
        self.symmgr.peRunning.set()
        self.symmgr.start()
        self.symmgr.peRunning.clear()
        self.symmgr.join()

        unittest.TestCase.assertEqual(self, self.dbmgr.donecount, 1)