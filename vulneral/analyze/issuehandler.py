from api import models

class IssueHandler:
    def __init__(self, vulnTree, vulnFile, scanResult):
        self.vulnFile = vulnFile
        self.scanResult = scanResult
        self.vulnTree = vulnTree
        self.__handle()

    def __handle(self):
        for vuln in self.vulnTree.vulns:
            print '=> %2s' % ( str(vuln))
            vuln.display()
            print '-' * 30

    def save(self):
        for vuln in self.vulnTree.vulns:
            if not vuln.is_rootable:
                continue

            print '=> %2s' % ( str(vuln))
    
            vuln.save(self)
            
            if vuln.patch_methods:
                print "%2s [=>]Patches : %s " %( '', ', '.join(vuln.patch_methods))
                            
            print "---" * 20
    
    def saveIssue(self, vuln, parent):
        issue = models.Issue()
        issue.title = vuln.title
        issue.line = vuln.line
        issue.snippet = vuln.snippet
        issue.parent = parent
        issue.vulnFile = self.vulnFile
        issue.scanResult = self.scanResult
        
        if vuln.issue_name:

            try:
                issueType = models.IssueType.objects.get(name__icontains=vuln.issue_name)
                issue.issueType = issueType
            except:
                pass
        
        if parent:
            issue.parent = parent
        
        issue.save()
        
        return issue

