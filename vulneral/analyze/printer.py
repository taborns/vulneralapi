class Printer:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    @staticmethod
    def createColorBlock( block, data):
        return block + str(data) + Printer.ENDC
    
    @staticmethod
    def bold( data):
        return Printer.createColorBlock(Printer.BOLD, data)
    
    @staticmethod
    def warning( data):
        return Printer.createColorBlock(Printer.WARNING, data)
    
    @staticmethod
    def green( data):
        return Printer.createColorBlock(Printer.OKGREEN, data)
    
    @staticmethod
    def blue( data):
        return Printer.createColorBlock(Printer.OKBLUE, data)
    
    @staticmethod
    def fail( data):
        return Printer.createColorBlock(Printer.FAIL, data)
    



