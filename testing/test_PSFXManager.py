from sqlite3.dbapi2 import connect
import unittest
import asyncio
import cProfile
from unittest import TestCase
from ProcessPools import PSFXMgr, PEMgr
from db.wsuse_db import construct_tables
from globs import DBCONN

class test_PSFXManager(unittest.TestCase):

    def setUp(self) -> None:
        self.pemgr = PEMgr(4, None, DBCONN, None)
        self.psfxmgr = PSFXMgr(None, None, 4, self.pemgr, DBCONN, False, None, None)

        construct_tables(DBCONN)

        return super().setUp()

    def tearDown(self) -> None:
        return super().tearDown()

    def test_getVersion(self):
        '''rudimentary test for version number'''
        xmlfile = "C:\\BAM testing\\testoutput\\windows10.0-kb5000802-x64_f1da84b3bfa1c402d98dfb3815b1f81d7dceb001\\Windows10.0-KB5000802-x64\\Windows10.0-KB5000802-x64\\update.mum"

        version = PSFXMgr.getVersion(xmlfile)

        unittest.TestCase.assertIsNotNone(self, version)
        unittest.TestCase.assertIsInstance(self, version, int)
    
    def test_addjob(self):
        psfxjob = "C:\\BAM testing\\expansions\\Windows10.0-KB5003169-x64_PSFX"
        
        self.psfxmgr.addjob(psfxjob)
        testjob = self.psfxmgr.jobs.get()

        unittest.TestCase.assertEqual(self, psfxjob, testjob)


    def test_passresult(self):
        pejob = "C:\\BAM testing\\expansions\\Windows10.0-KB5003169-x64_PSFX"
        event_loop = asyncio.new_event_loop()
        future = event_loop.create_future()
        future.set_result(pejob)

        self.psfxmgr.passresult(future)
        testjob = self.pemgr.jobs.get()

        unittest.TestCase.assertEqual(self, pejob, testjob)

    def test_PSFXExtract(self):
        psfxext = "C:\\BAM testing\\testoutput\\windows10.0-kb5005394-x64_911ff8871acdfecebdd69bb09c3785236a6984a9\\Windows10.0-KB5005394-x64_PSFX\\Cab_1_for_KB5005394_PSFX\\Cab_1_for_KB5005394_PSFX.cab"
        dest = "C:\\BAM testing\\testoutput\\windows10.0-kb5005394-x64_911ff8871acdfecebdd69bb09c3785236a6984a9\\Windows10.0-KB5005394-x64_PSFX\\Cab_1_for_KB5005394_PSFX"
        basedir = "C:\\BAM testing\\FileFinderTest"
        update = "C:\\BAM testing\\testoutput\\windows10.0-kb5005394-x64_911ff8871acdfecebdd69bb09c3785236a6984a9\\Windows10.0-KB5005394-x64_PSFX\\update.mum"
        version = PSFXMgr.getVersion(update)

        pedir = PSFXMgr.PSFXExtract(psfxext, dest, basedir, version)

        TestCase.assertIsInstance(self, pedir, str)
        # this is a bad test, will have to come up with better expected results later

    def test_findBaseFile(self):
        file = "C:\\BAM testing\\expansions\\Windows10.0-KB5004760-x64\\test\\test2\\cab2\\amd64_adaptivecards-xamlcardrenderer_31bf3856ad364e35_10.0.19041.746_none_b8cd46df7d27c889"
        basedir = "C:\\BAM testing\\FileFinderTest"
        xml = "C:\\BAM testing\\expansions\\Windows10.0-KB5004760-x64\\test\\update.mum"
        version = PSFXMgr.getVersion(xml)

        outfile = PSFXMgr.findBaseFile(basedir, file, version)
        

        unittest.TestCase.assertIsNotNone(self, outfile)

    def test_psfxextracttime(self):
        psfxext = 'C:\\BAM testing\\expansions\\Windows10.0-KB5000802-x64\\test\\test\\cab2\\Cab_2_for_KB5000802_PSFX.cab'
        dest = 'C:\\BAM testing\\expansions\\Windows10.0-KB5000802-x64\\test\\test\\cab2'
        basedir = 'C:\\BAM testing\\FileFinderTest'
        update = 'C:\\BAM testing\\expansions\\Windows10.0-KB5000802-x64\\test\\test\\update.mum'
        version = PSFXMgr.getVersion(update)

        command = 'PSFXMgr.PSFXExtract(psfxext, dest, basedir, version)'
        vars = dict(PSFXMgr=PSFXMgr, psfxext=psfxext, dest=dest, basedir=basedir, version=version)
        cProfile.runctx(command, vars, vars)
