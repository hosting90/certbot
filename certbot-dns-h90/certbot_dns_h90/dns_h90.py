"""DNS Authenticator for Hosting90."""
import logging

import zope.interface
from lexicon.providers import linode

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

HAPI_URL='https://bero.devel.hosting90.cz/api'

class HostingApi(object):
    """docstring for HostingApi"""
    
    def __init__(self,sid = None,fn = None):
        self.sid = sid
        self.fn = fn
    
    def __getattr__(self, name):
        attr = type(self)(self.sid, name)
        
        return attr.__call__
    
    def __call__(self,**kwargs):
        """docstring for __call"""
        if self.fn == None:
            return None
        if self.sid != None:
            kwargs['sid'] = self.sid
        if kwargs.has_key('post'):
            post_args = kwargs['post']
            del kwargs['post']
        else:
            post_args = None
        myurl = HAPI_URL+'/'+self.fn+'?reply=json&'+urllib.urlencode(kwargs)
        if post_args == None:
            u = requests.get(myurl)
            text = u.content
        else:
            u = requests.post(myurl, data=post_args)
            text = u.content
            
        ret = json.loads(text)
        
        if ret['reply']['status']['code'] == 0:
            del(ret['reply']['status'])
            return ret['reply']
        else:
            raise Exception((ret['reply']['status']['code'], ret['reply']['status']['text']))
        
    def login(self,uid,password):
        self.fn = 'login'
        self.sid = None
        ret = self.__call__(uid=uid,password=password)
        
        self.sid = ret['sid']
    
    def login_callback(self,domain,callback_hash):
        self.fn = 'login_callback'
        self.sid = None
        ret = self.__call__(domain=domain,password=callback_hash)
        
        self.sid = ret['sid']

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Linode

    This Authenticator uses the Linode API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certs using a DNS TXT record (if you are using Linode for DNS).'

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=960)
        add('credentials', help='Linode credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Linode API.'

    def _perform(self, domain, validation_name, validation):
        api = self._get_h90_client(domain)
        dl = api.domain_list()
        domain_id = dl['domains'][0]['domain_id']
        # ověřím, že je
        dl = api.domain_list_dns(domain_id=domain_id)
        # check non exists
        if len(filter(lambda x: x['type'] == 'TXT' and x['name'] == validation_name and x['ip'] == validation,dl)) > 0:
            # záznam už existuje. není co dělat
            return True
        ret = api.domain_add_dns(domain_id=domain_id, post= {'name':validation_name, 'ttl':60, 'type':'TXT','ip':validation})
        # tady počkej na to, až bude v DNS
        # optional
        # while not _check_dns_active()
        
    
    # def _check_dns_active(self, domain_name):
        
        
    def _cleanup(self, domain, validation_name, validation):
        # som dodelat smazani TXT zaznamu

    def _get_h90_client(self,domain):
        api = HostingApi()
        api.login_callback(domain,'heslo')
        return api

