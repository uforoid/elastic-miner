from __future__ import absolute_import

import logging
import requests
import bs4  # we use bs4 to parse the HTML page
from elasticsearch import Elasticsearch

from minemeld.ft.basepoller import BasePollerFT

LOG = logging.getLogger(__name__)

query = {
    "query": {
        "bool": {
            "must": [
                {
                    "match": {
                        "event.detail": "Sign-in was blocked because it came from an IP address with malicious activity."
                    }
                },
                {
                    "range": {
                        "@timestamp": {
                            "gte": "now-100d/d",
                            "lte": "now"
                        }
                    }
                }
            ]
        }
    }
}


class Miner(BasePollerFT):
    def configure(self):
        super(Miner, self).configure()

        self.polling_timeout = self.config.get('polling_timeout', 60)

        self.index_pattern = self.config.get('index_pattern', 'ecs-office365-*')
        if self.index_pattern is None:
            raise ValueError('%s - index pattern name is required' % self.name)

        ips = self.config.get('elastic_ips', '8.8.8.8')
        user = self.config.get('user', 'user')
        password = self.config.get('password', 'password')
        self.es = Elasticsearch(ips, http_auth=(user, password), request_timeout=60)

    def _process_item(self, item):
        try:
            indicator = item['_source']['source']['ip']
        except:
            LOG.debug('error while reading ip for item {}'.format(item['_id']))
            raise

        if indicator is None:
            LOG.error('%s - no data-context-item-id attribute', self.name)
            return []

        value = {
            'type': 'IPv4',
            'confidence': 100
        }

        return [[indicator, value]]

    def _build_iterator(self, now):
        try:
            es_docs = self.es.search(index=self.index_pattern, body=query, request_timeout=60)['hits']['hits']
        except:
            LOG.debug('cannot get results from elasticsearch')
            raise

        return es_docs
