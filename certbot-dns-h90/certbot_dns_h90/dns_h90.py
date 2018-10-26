"""DNS Authenticator for Hosting90."""
import logging,urllib,requests,json

import zope.interface
from lexicon.providers import linode

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon
import pprint
import dns.resolver, time
pp = pprint.PrettyPrinter(indent=4)

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
	try:
	    ret = json.loads(text)
	except:
	    raise
        
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
        add('apikey', help='H90 API key string.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Linode API.'
    def _setup_credentials(self):
        #print self.conf('credentials')
        self.credentials = self.conf('apikey')


    def _perform(self, domain, validation_name, validation):
        api = self._get_h90_client(domain)
        dl = api.domain_list()
        domain_id = dl['domains'][0]['domain_id']
        # ověřím, že je
        
        dl = api.domain_list_dns(domain_id=domain_id)
        #pp.pprint(dl)
        txt_records = self.get_type_records(dl['zone'],'TXT')
        validation_name = validation_name.split('.')[0]

	    # check non exists
        
        #print filter(lambda x: x['type'],dl)
        #print filter(lambda x: x['name'],dl)

        if len(filter(lambda x: x['type'] == 'TXT' and x['name'] == validation_name and x['ip'] == validation, dl['zone'])) > 0:
            # záznam už existuje. není co dělat
            return True
        ret = api.domain_add_dns(domain_id=domain_id, post= {'name':validation_name, 'ttl':60, 'type':'TXT','ip':validation})
        # tady počkej na to, až bude v DNS
        # optional
        #time.sleep(3)
        #_check_dns_active(validation_name, domain)
        
        myResolver = dns.resolver.Resolver()
        myResolver.nameservers = ['130.193.8.82','77.78.100.57']
        #waitingdns = True
        print validation
        waitingperiod = 360
        while waitingperiod > 0:
            try:
                myAnswers = myResolver.query(validation_name + "." + domain, "TXT")
                for rdata in myAnswers:
                    if str(rdata) == str("\"" + validation + "\""):
                        print "DNS check - OK"
                        waitingperiod = 0
                    else:
                        print "Active checking DNS - Waiting"
                        waitingperiod = waitingperiod - 1
            except:
                print "Active checking DNS - Waiting"
                waitingperiod = waitingperiod - 1
            time.sleep(1)
            
        
    def _cleanup(self, domain, validation_name, validation):
        api = self._get_h90_client(domain)
        dl = api.domain_list()
        domain_id = dl['domains'][0]['domain_id']
        # ověřím, že je
        dl = api.domain_list_dns(domain_id=domain_id)
        txt_records = self.get_type_records(dl['zone'],'TXT')
        #pp.pprint(txt_records)
        #ret = api.domain_delete_dns(dns_id=txt_records[0]['dns_id'])
        for r in txt_records:
            if r['ip']==validation:
                ret = api.domain_delete_dns(dns_id=r['dns_id'])

    def _get_h90_client(self,domain):
        api = HostingApi()
        api.login_callback(domain,self.conf('apikey'))
        return api
    
    def get_type_records(self, record_list, mytype):
        """docstring for find_txt_records"""
        return filter(lambda x: x['type'] == mytype,record_list)

