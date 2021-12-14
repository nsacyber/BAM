from sqlite3.dbapi2 import connect
import unittest
import asyncio
from unittest import TestCase
from pefile import set_flags
from ProcessPools import PEMgr, SymMgr, DBMgr
from db.wsuse_db import construct_tables
from globs import DBCONN
from support.utils import getfilehashes

class test_PEManager(unittest.TestCase):

    def setUp(self) -> None:
        self.dbmgr = DBMgr("C:\\BAM testing\\testoutput", None)
        self.symmgr = SymMgr(4, None, 'C:\\BAM Testing\\symbols', None)
        self.pemgr = PEMgr(4, self.symmgr, self.dbmgr, None)

        construct_tables(DBCONN)

        return super().setUp()

    def tearDown(self) -> None:
        return super().tearDown()

    def test_addjob(self):
        '''
        should be adding directory full of PE files and checking to see if that is 
        added to the queue
        '''
        testdir = "C:\\BAM testing\\expansions\\Windows10.0-KB5000802-x64\\test\\test\\cab2"
        self.pemgr.addjob(testdir)
        inqueue = self.pemgr.jobs.get()

        unittest.TestCase.assertEqual(self, testdir, inqueue)

    def test_cabstartsig(self):
        self.pemgr.cabstartsig()

        unittest.TestCase.assertTrue(self, self.pemgr.cabmgrRunning.is_set())

    def test_cabdonesig(self):
        self.pemgr.cabdonesig()

        unittest.TestCase.assertFalse(self, self.pemgr.cabmgrRunning.is_set())

    def test_psfxstartsig(self):
        self.pemgr.psfxstartsig()

        unittest.TestCase.assertTrue(self, self.pemgr.psfxmgrRunning.is_set())

    def test_psfxdonesig(self):
        self.pemgr.psfxdonesig()

        unittest.TestCase.assertFalse(self, self.pemgr.psfxmgrRunning.is_set())

    def test_passresult(self):
        testfile = "C:\\BAM testing\\expansions\\Windows10.0-KB5000802-x64\\test\\test\\cab2\\amd64_desktop_shell-search-srchadmin_31bf3856ad364e35_7.0.19041.746_none_642d63be8a0f4ca4\\srchadmin.dll"
        hash1, hash2 = getfilehashes(testfile)
        updateid = 'abcdef1234567890'
        info = {'builtwithdbginfo': True}
        result = ((testfile, updateid), hash1, hash2, info)
        event_loop = asyncio.new_event_loop()
        future = event_loop.create_future()
        future.set_result(result)
        optype = "binary"
        jobtuple = (testfile, updateid)
        sampletask = (optype, jobtuple, hash1, hash2, info)

        self.pemgr.passresult(future)
        testjob = self.symmgr.jobs.get()

        unittest.TestCase.assertEqual(self, testfile, testjob[0])
        unittest.TestCase.assertEqual(self, hash1, testjob[1])
        unittest.TestCase.assertEqual(self, hash2, testjob[2])
        unittest.TestCase.assertEqual(self, self.dbmgr.jobqueue.get(), sampletask)
        unittest.TestCase.assertTrue(self, self.dbmgr.jobsig.is_set())

    def test_petask(self):
        testfile = "C:\\BAM testing\\expansions\\Windows10.0-KB5000802-x64\\test\\test\\cab2\\amd64_desktop_shell-search-srchadmin_31bf3856ad364e35_7.0.19041.746_none_642d63be8a0f4ca4\\srchadmin.dll"
        updateid = "abcdef123456789"
        testhash1, testhash2 = getfilehashes(testfile)
        (filename, update), hash1, hash2, info = PEMgr.petask(testfile, updateid)

        unittest.TestCase.assertEqual(self, testfile, filename)
        unittest.TestCase.assertEqual(self, update, updateid)
        unittest.TestCase.assertEqual(self, testhash1, hash1)
        unittest.TestCase.assertEqual(self, testhash2, hash2)
        unittest.TestCase.assertIsInstance(self, info, dict)

    def test_run(self):
        testdir = "C:\\BAM testing\\testoutput\\windows10.0-kb5005394-x64_911ff8871acdfecebdd69bb09c3785236a6984a9\\Windows10.0-KB5005394-x64_PSFX\\Cab_1_for_KB5005394_PSFX"
        self.pemgr.addjob(testdir)
        self.pemgr.cabmgrRunning.set()
        self.pemgr.psfxmgrRunning.set()
        self.pemgr.start()
        self.pemgr.cabmgrRunning.clear()
        self.pemgr.psfxmgrRunning.clear()
        self.pemgr.join()

        unittest.TestCase.assertEqual(self, self.dbmgr.donecount, 1)
        unittest.TestCase.assertFalse(self, self.symmgr.peRunning.is_set())
