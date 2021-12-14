from sqlite3.dbapi2 import connect
import unittest
import asyncio
import cProfile
from unittest import TestCase
from ProcessPools import CabMgr, DBMgr, PSFXMgr, PEMgr
from db.wsuse_db import construct_tables
from globs import DBCONN

class test_CabManager(TestCase):

    patchdir = "C:\\BAM testing\\updates"
    basedir = "C:\\BAM testing\\FileFinderTest"
    destdir = "C:\\BAM testing\\testoutput"

    def setUp(self) -> None:

        # set up  the managers that will be used
        self.db = DBMgr(None, DBCONN)
        self.pes = PEMgr(4, None, None, None)
        self.psfx = PSFXMgr(test_CabManager.patchdir, test_CabManager.destdir, 4, self.pes, None, False, None, test_CabManager.basedir)
        self.cab = CabMgr(test_CabManager.patchdir, test_CabManager.destdir, 4, self.pes, self.psfx, self.db, False, None)
        
        # create the database connection and the empty database
        construct_tables(DBCONN)

        return super().setUp()

    def tearDown(self) -> None:

        # TODO: kill the sqlite3 connection and remove the database file 
        
        return super().tearDown()

    # Unit tests for individual functions
    def test_extractTaskPE(self):
        # download regular test patch and put directory here
        non_psfx_patches = "C:\\BAM testing\\updates\\windows10.0-kb5005393-x64_3f60f953496eecf090ccf96f69d8ebfe85c8d4ee.msu"
        result = CabMgr.extracttask(non_psfx_patches, test_CabManager.destdir)
        correctResult = (result[0] == "nonPSFX")

        unittest.TestCase.assertTrue(self, correctResult)
        unittest.TestCase.assertIsInstance(self, result[1], list)
        unittest.TestCase.assertIsNone(self, result[2])
        return

    def test_extractTaskPSFX(self):
        # download PSFX test patch and put directory here
        psfx_patches = "C:\\BAM testing\\updates\\windows10.0-kb5004760-x64_b1789ff430beaa785e620ea39fa7a6e1254e555d.msu"
        result = CabMgr.extracttask(psfx_patches, test_CabManager.destdir)
        correctResult = (result[0] == "PSFX")

        unittest.TestCase.assertTrue(self, correctResult)
        unittest.TestCase.assertIsInstance(self, result[1], list)
        unittest.TestCase.assertIsInstance(self, result[2], list)
        return

    def test_addq(self):
        prev_value = self.cab.workremaining
        taskpath = test_CabManager.patchdir
        self.cab.addq(taskpath)
        set = self.cab.jobsincoming.is_set()

        unittest.TestCase.assertTrue(self, set)
        unittest.TestCase.assertEqual(self, self.cab.workremaining, prev_value + 1)

        jobs_added = self.cab.jobs.get_nowait()
        unittest.TestCase.assertEqual(self, taskpath, jobs_added)
        return
    
    # integration tests for related functions
    def test_passresultPSFX(self):
        
        event_loop = asyncio.new_event_loop()
        future = event_loop.create_future()
        psfxdirs = ["C:\\BAM testing\\testoutput\\windows10.0-kb5000802-x64_f1da84b3bfa1c402d98dfb3815b1f81d7dceb001"]
        testhash1 = 239847092345869087519
        testhash2 = 21093487102957820934857029875
        testname = "windows10.0-kb5000802-x64_f1da84b3bfa1c402d98dfb3815b1f81d7dceb001"
        future.set_result(("PSFX", None, psfxdirs, testhash1, testhash2, testname))
        self.cab.workremaining = 1

        self.cab.passresult(future)

        unittest.TestCase.assertTrue(self, self.cab.jobsincoming.is_set())
        unittest.TestCase.assertEqual(self, self.psfx.jobs.get_nowait(), future.result()[2][0])

        self.cab.workremaining = 2
        self.cab.jobsincoming.clear()

        self.cab.passresult(future)

        unittest.TestCase.assertFalse(self, self.cab.jobsincoming.is_set())
        return

    def test_passresultPE(self):
        
        event_loop = asyncio.new_event_loop()
        future = event_loop.create_future()
        testResult = ["C:\\BAM testing\\testoutput\\windows6.2-kb2862551-x64_dd3d78955791410fe0d543e7022158c90f3925a9"]
        testhash1 = 23493287112132
        testhash2 = 19238470895467
        testname = "windows6.2-kb2862551-x64_dd3d78955791410fe0d543e7022158c90f3925a9"
        future.set_result(("nonPSFX", testResult, None, testhash1, testhash2, testname))
        result = future.result()
        self.cab.workremaining = 1

        self.cab.passresult(future)

        unittest.TestCase.assertEqual(self, "nonPSFX", result[0])
        unittest.TestCase.assertTrue(self, self.cab.jobsincoming.is_set())
        unittest.TestCase.assertEqual(self, self.pes.jobs.get_nowait(), result[1][0])
        unittest.TestCase.assertIsNone(self, result[2])

        self.cab.workremaining = 2
        self.cab.jobsincoming.clear()

        self.cab.passresult(future)

        unittest.TestCase.assertFalse(self, self.cab.jobsincoming.is_set())
        return

    def test_queueDbTaskPE(self):
        event_loop = asyncio.new_event_loop()
        future = event_loop.create_future()
        testResult = ["C:\\BAM testing\\testoutput\\windows6.2-kb2862551-x64_dd3d78955791410fe0d543e7022158c90f3925a9"]
        testhash1 = 23493287112132
        testhash2 = 19238470895467
        testname = "windows6.2-kb2862551-x64_dd3d78955791410fe0d543e7022158c90f3925a9"
        future.set_result(("nonPSFX", testResult, None, testhash1, testhash2, testname))
        result = future.result()
        optype = "update"
        jobtuple = (result[5], result[0])
        sha256 = testhash1
        sha1 = testhash2
        sampletask = (optype, jobtuple, sha256, sha1, None)

        self.cab.queueDbTask(future)

        unittest.TestCase.assertEqual(self, self.db.jobqueue.get(), sampletask)
        unittest.TestCase.assertTrue(self, self.db.jobsig.is_set())

    def test_queueDbTaskPSFX(self):
        event_loop = asyncio.new_event_loop()
        future = event_loop.create_future()
        psfxdirs = ["C:\\BAM testing\\testoutput\\windows10.0-kb5000802-x64_f1da84b3bfa1c402d98dfb3815b1f81d7dceb001"]
        testhash1 = 239847092345869087519
        testhash2 = 21093487102957820934857029875
        testname = "windows10.0-kb5000802-x64_f1da84b3bfa1c402d98dfb3815b1f81d7dceb001"
        future.set_result(("PSFX", None, psfxdirs, testhash1, testhash2, testname))
        result = future.result()
        optype = "update"
        jobtuple = (result[5], result[0])
        sha256 = testhash1
        sha1 = testhash2
        sampletask = (optype, jobtuple, sha256, sha1, None)

        self.cab.queueDbTask(future)

        unittest.TestCase.assertEqual(self, self.db.jobqueue.get(), sampletask)
        unittest.TestCase.assertTrue(self, self.db.jobsig.is_set())

    def test_run(self):
        # test state of donseig for pemgr and psfx mgr
        # check on queues of pe and psfxmgr to determine whether or not updates were sent correctly
        # check destination folders to ensure that things were extracted properly.

        self.cab.run()
        pe_cabstate = self.pes.cabmgrRunning.is_set()
        pe_psfxstate = self.pes.psfxmgrRunning.is_set()
        psfx_state = self.psfx.cabmgrRunning.is_set()

        unittest.TestCase.assertFalse(self, pe_cabstate)
        unittest.TestCase.assertFalse(self, pe_psfxstate)
        unittest.TestCase.assertFalse(self, psfx_state)

        pes_queue = self.pes.jobs.empty()
        psfx_queue = self.psfx.jobs.empty()

        unittest.TestCase.assertFalse(self, pes_queue)
        unittest.TestCase.assertFalse(self, psfx_queue)

    def test_runcProfile(self):
        vars = dict(self=self)
        cProfile.runctx('self.cab.run()', vars, vars)
