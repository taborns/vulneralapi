from vulneral.phplex import lexer
from vulneral.phpparse import make_parser
from vulneral.analyze.scanner import Scanner
from vulneral.analyze.issuehandler import IssueHandler
from vulneral.analyze.FileHandler import FileHandler
from vulneral.analyze.PHPFile import PHPFile
import os,os.path,sys,shutil,simplejson,random,hashlib
import zipfile
from api import models
class ProjectHandler:
    fileHandler = FileHandler()
    parser = make_parser()
    FILETYPES = [						# filetypes to scan
		'.php', 
		'.inc', 
		'.phps', 
		'.php4', 
		'.php5', 
		'.html', 
		'.htm', 
		'.txt',
		'.phtml', 
		'.tpl',  
		'.cgi',
		'.test',
		'.module',
		'.plugin'
	]
    summary = models.Summary()
    issue_counts = {}


    @staticmethod
    def unzipFolder(zipName):
        output_directory_arr = []
        for i in range(100):
            output_directory_arr.append(str(random.randint(1000,1000000000)))

        output_directory = ''.join(output_directory_arr)
        from hashlib import md5
        m = hashlib.md5()
        m.update( output_directory )
        output_directory =  m.hexdigest()
        zip_file = zipfile.ZipFile(zipName, "r")
        zip_file.extractall(output_directory)
        zip_file.close()

        return output_directory       

    @staticmethod
    def getFiles(dir_path):
        file_paths = []
        dirs = [dir_path]
        counter = 0
        while True:
            if counter == len(dirs):
                break
            cur_dir = dirs[counter]
            files = os.listdir(cur_dir)

            for name in files:
                full_path = os.path.join(cur_dir, name)
                if os.path.isdir(full_path):
                    ProjectHandler.summary.totalFolders += 1
                    dirs.append(full_path)
                else:
                    filename, file_extension = os.path.splitext(full_path)
                    if file_extension in ProjectHandler.FILETYPES:
                        ProjectHandler.summary.totalFiles += 1
                        file_paths.append( full_path )
            counter +=1
        
        return file_paths
                    
        

    @staticmethod
    def handle(zipName, application, scanResult):
        output_directory = ProjectHandler.unzipFolder(zipName)
        #os.remove(zipName)
        file_paths = ProjectHandler.getFiles(output_directory)
        
        import time 
        scan_start_time = time.time()
        for file_path in file_paths:
            phpFile = PHPFile(file_path, 
                                application=application, 
                                summary_object=ProjectHandler.summary, 
                                scanResult=scanResult,
                                issue_counts = ProjectHandler.issue_counts)

            ProjectHandler.fileHandler.addFile(phpFile)
            phpFile.handle()
        


        scan_end_time = time.time()
        ProjectHandler.summary.scanTime = '%.2f' % ((scan_end_time - scan_start_time)/60)
        ProjectHandler.summary.project = application
        ProjectHandler.summary.scanResult = scanResult
        ProjectHandler.summary.save()

        
        for issue_name in ProjectHandler.issue_counts:
            issue_count = ProjectHandler.issue_counts[issue_name]
            issue_count.summary = ProjectHandler.summary
            issue_count.save()

        shutil.rmtree(output_directory)

        # simplejson.dump(tokens,output, indent=2)
        # output.write('\n')
