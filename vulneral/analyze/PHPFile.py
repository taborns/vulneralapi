import sys
from vulneral.phplex import lexer
from vulneral.phpparse import make_parser
from vulneral.analyze.scanner import Scanner
from vulneral.analyze.issuehandler import IssueHandler
from api import models
import simplejson

class PHPFile:
    def __init__(self, file_name, text_data=None, application=None, scanResult=None, persist=True):
        self.file_name = file_name
        self.text_data = text_data
        self.persist = persist
        self.application = application
        self.scanResult = scanResult
        self.parser = make_parser()
        self.with_lineno = True
        self.vulnFile = None
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
        return
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
                
            scanner = Scanner(tokens, file_name=self.file_name)
            return scanner.scan()
        
        except (RuntimeError) as e:
            scanner = Scanner([], file_name=self.file_name)
        
        except (SyntaxError) as e:
            self.syntax_error = True
            scanner = Scanner([], file_name=self.file_name)
        
        return scanner.scan()
    
    
    def handle(self):
        if self.persist:
            IssueHandler(self.vulnTree, self.vulnFile, self.scanResult)
        
        return self.vulnTree
