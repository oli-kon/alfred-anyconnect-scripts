from workflow import Workflow3
from workflow.workflow import Settings

class config:
    '''Alfred VPN workflow configuration management'''
    __wf = None
    __config = None
    __is_init = False

    def __init__(self, wf):
        self.__wf = wf
        self.__config = Settings('./config.json')

        log = self.__wf.logger
        func_name = self.__init__.__name__

        log.info("%s reading configuration", func_name)

        if len(self.__config) is not 0:
            log.info("%s configuration read OK", func_name)
            self.__is_init = True

    def get_field(self, field):
        '''Get configuration field'''
        if self.__is_init is False:
            return None

        return self.__config[field]

    def set_field(self, field, value):
        '''Set configuration field'''
        if self.__is_init is False:
            return False

        self.__config[field] = value
        self.__config.save()
        return True
