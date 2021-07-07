from sqlite3.dbapi2 import connect
import unittest
import asyncio
import sqlite3
from unittest import TestCase
from ProcessPools import CabMgr, PSFXMgr, PEMgr, SymMgr
from db.wsuse_db import construct_tables
from globs import DBCONN

class test_CabManager(TestCase):

    patchdir = "C:\\Users\\ghpham\\Desktop\\verysmalltest"
    basedir = "C:\\Windows\\System32"
    destdir = "C:\\Users\\ghpham\\Desktop\\testout"

    def setUp(self) -> None:

        # set up  the managers that will be used
        self.pes = PEMgr(4, None, None, None)
        self.psfx = PSFXMgr(test_CabManager.patchdir, test_CabManager.destdir, 4, self.pes, None, False, None, test_CabManager.basedir)
        self.cab = CabMgr(test_CabManager.patchdir, test_CabManager.destdir, 4, self.pes, self.psfx, None, False, None)

        # create the database connection and the empty database
        construct_tables(DBCONN)

        return super().setUp()

    def tearDown(self) -> None:

        # TODO: kill the sqlite3 connection and remove the database file 
        
        return super().tearDown()

    # Unit tests for individual functions
    def test_extractTaskPE(self):
        non_psfx_patches = "C:\\Users\\ghpham\\Desktop\\verysmalltest\\windows10.0-kb4567515-x86_8f2d9133052f8aa683ab7d958bdca8471fa11fb6.msu"
        result = CabMgr.extracttask(non_psfx_patches, test_CabManager.destdir)

        unittest.TestCase.assertIsInstance(self, result[0], tuple)
        return

    def test_extractTaskPSFX(self):
        psfx_patches = "C:\\Users\\ghpham\\Desktop\\verysmalltest\\Windows10.0-KB5003169-x64_PSFX.cab"
        result = CabMgr.extracttask(psfx_patches, test_CabManager.patchdir)
        correctResult = (result[0] == "PSFX")

        unittest.TestCase.assertTrue(self, correctResult)
        return

    def test_addq(self):
        prev_value = self.cab.workremaining
        taskpath = test_CabManager.patchdir
        self.cab.addq(taskpath)
        set = self.cab.jobsincoming.is_set()

        unittest.TestCase.assertTrue(self, set)
        unittest.TestCase.assertEqual(self, self.cab.workremaining, prev_value + 1)

        jobs_added = self.cab.jobs.get_nowait()
        unittest.TestCase.assertEquals(self, taskpath, jobs_added)
        return
    
    # integration tests for related functions
    def test_passresultPSFX(self):
        
        event_loop = asyncio.new_event_loop()
        future = event_loop.create_future()
        future.set_result(("PSFX", test_CabManager.patchdir))
        self.cab.workremaining = 1

        self.cab.passresult(future)

        unittest.TestCase.assertTrue(self, self.cab.jobsincoming.is_set())
        unittest.TestCase.assertEqual(self, self.psfx.jobs.get_nowait(), future.result()[1])

        self.cab.workremaining = 2
        self.cab.jobsincoming.clear()

        self.cab.passresult(future)

        unittest.TestCase.assertFalse(self, self.cab.jobsincoming.is_set())
        return

    def test_passresultPE(self):
        
        event_loop = asyncio.new_event_loop()
        future = event_loop.create_future()
        testhash1 = 23493287112132
        testhash2 = 19238470895467
        future.set_result(((test_CabManager.patchdir,[]), testhash1, testhash2))
        self.cab.workremaining = 1

        self.cab.passresult(future)

        unittest.TestCase.assertTrue(self, self.cab.jobsincoming.is_set())
        unittest.TestCase.assertEqual(self, self.pes.jobs.get_nowait(), future.result()[0][0])

        self.cab.workremaining = 2
        self.cab.jobsincoming.clear()

        self.cab.passresult(future)

        unittest.TestCase.assertFalse(self, self.cab.jobsincoming.is_set())
        return

    
