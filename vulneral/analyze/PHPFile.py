import sys
from vulneral.phplex import lexer
from vulneral.phpparse import make_parser
from vulneral.analyze.scanner import Scanner
from vulneral.analyze.issuehandler import IssueHandler
from api import models
import simplejson, os

class PHPFile:
    def __init__(self, file_name, text_data=None, application=None, scanResult=None, issue_counts={}, summary_object=None, persist=True):
        self.summary_object = summary_object
        self.issue_counts = issue_counts
        self.file_name = file_name
        self.text_data = text_data
        self.persist = persist
        self.application = application
        self.scanResult = scanResult
        self.parser = make_parser()
        self.with_lineno = True
        self.vulnFile = None
        self.scanner = None

        self.vulnTree = self.getScanner()
        self.syntax_error = False 

        if persist:
            self.createFile()
    
    def _get_name(self, name):
        # Sanitize the file name so that it can't be dangerous.
        if name is not None:
            # Just use the basename of the file -- anything else is dangerous.
            name = os.path.basename(name)

        return name

    def getCodeData(self):
        if self.text_data:
            return self.text_data
        
        with open(self.file_name, "r") as f:
            input_file = f.read()


        return input_file    
        

    def createFile(self):
        if not self.vulnTree.length():
            return
        path = '/'.join(self.file_name.split('/')[1:])
        try:
            phpFile = self.application.files.get(path=path)
        except:
            phpFile = models.File.objects.create(path=path, project=self.application, name=self._get_name(path))

        phpFile.scanResults.add( self.scanResult )
        self.vulnFile = phpFile

    def export(self, items):
        result = []
        if items:
            for item in items:
                if hasattr(item, 'generic'):
                    item = item.generic(with_lineno=self.with_lineno)
                result.append(item)
        return result

    def getScanner(self):
        try:
            input_file = self.getCodeData()
            input_file.replace('<?xml version="1.0" encoding="iso-8859-1"?>', '')
            tokens = self.export(self.parser.parse(input_file,
                                                lexer=lexer.clone(),tracking=self.with_lineno))

            output = sys.stdout

            # simplejson.dump(tokens,output, indent=2)
            # output.write('\n')
                
            self.scanner = Scanner(tokens, file_name=self.file_name)
            vulnTree = self.scanner.scan()
           
            return vulnTree
        
        except (RuntimeError) as e:
            scanner = Scanner([], file_name=self.file_name)
        
        except (SyntaxError) as e:
            self.syntax_error = True
            scanner = Scanner([], file_name=self.file_name)
        
        vulnTree = scanner.scan()

        return vulnTree
    
    
    def handle(self):
        if self.persist:
            print "IT is persisiting"
            IssueHandler(self.vulnTree, self.vulnFile, self.scanResult)

            if self.summary_object:
                
                if self.scanner:
                    self.summary_object.totalClasses += len(self.scanner.classes)

                self.summary_object.totalVulns += len(self.vulnTree.vulns)
                self.summary_object.totalLines += len(open(self.file_name).readlines())
               
                for vuln in self.vulnTree.vulns:
                    if vuln.issue_name:
                        issueType = self.issue_counts.get( vuln.issue_name,  models.IssueTypeCount(issueName=vuln.issue_name, count=0) )
                        issueType.count += 1
                        self.issue_counts[vuln.issue_name] = issueType


        
        return self.vulnTree
