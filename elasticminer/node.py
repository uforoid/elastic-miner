from __future__ import absolute_import

import logging
from elasticsearch import Elasticsearch

from minemeld.ft.basepoller import BasePollerFT

LOG = logging.getLogger(__name__)


class Miner(BasePollerFT):
    def configure(self):
        super(Miner, self).configure()

        self.polling_timeout = self.config.get('polling_timeout', 60)

        self.index_pattern = self.config.get('index_pattern', 'index')
        if self.index_pattern is None:
            raise ValueError('%s - index pattern name is required' % self.name)

        fields = self.config.get('fields', 'event.dataset')
        self.query = self.config.get('query', '{query}')

        self.fields = {}
        for field in fields.keys():
            self.fields["_source']['" + field.replace(".", "']['")] = fields[field]

        ips = self.config.get('elastic_ips', '8.8.8.8')
        user = self.config.get('user', 'user')
        password = self.config.get('password', 'password')
        self.es = Elasticsearch(ips, http_auth=(user, password), request_timeout=60)

    def _process_item(self, item):
        returns = []
        for field, minemeld_type in self.fields.items():
            try:
                indicator = eval("item['{}']".format(field))
            except:
                LOG.debug('error while reading ip for item {}'.format(item['_id']))
                continue

            if indicator is None:
                LOG.error('%s - no data-context-item-id attribute', self.name)
                continue

            value = {
                'type': minemeld_type,
                'confidence': 100
            }
            returns.append([indicator, value])

        return returns

    def _build_iterator(self, now):
        try:
            es_docs = self.es.search(index=self.index_pattern, body=self.query, request_timeout=60, size=1000000)['hits']['hits']
        except:
            LOG.debug('cannot get results from elasticsearch')
            raise

        return es_docs
