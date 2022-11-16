from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
# from loguru import logger
import re


class EsQuery:
    def __init__(self):
        pass

    @staticmethod
    def detect_phrase(data):
        """
        Parameters
        ----------
        data: (string) containing words or multiple words of a query

        Returns
        -------
        (bool) if data is phrase or not
        """

        whitelist_operators = ["AND", "OR", "NOT"]
        word_tokens = re.findall("[\w']+", data)
        # logger.debug(f"Word tokens: {word_tokens}")

        if any([True if op in word_tokens else False for op in whitelist_operators]) \
                or len(re.findall("\s", data)) == 0 \
                or (data.startswith("/") and data.endswith("/")):
            return False

        elif len(word_tokens) > 1:
            return True

        else:
            return False

    def content_query(self, content):
        is_phrase = self.detect_phrase(content)

        if not is_phrase:
            query_mapping = {
                "from": 0,
                "size": 10,
                "_source": ["UUID"],
                "query": {
                    "wildcard": {
                        "content": {
                            "value": content
                        }
                    }
                }
            }
        else:
            {"match_phrase":
                {"content": content}
             }
            query_mapping = {
                "from": 0,
                "size": 1000,
                "_source": ["UUID"],
                "query": {
                    "regexp": {
                        "content": {

                        }
                    }
                }
            }
        return query_mapping


class ESConnection:
    def __init__(self, host, user, secret, port, timeout=30):
        self.client = Elasticsearch(hosts=[host], http_auth=(
            user, secret), port=port, verify_certs=False, timeout=timeout)
        # self.client = Elasticsearch(
        #     [
        #         {'host': host, 'port': port, 'scheme': 'https'},
        #     ],
        #     verify_certs=False,
        #     http_auth=(user, secret))

    def search(self, index, body):
        try:
            response = self.client.search(index=index, body=body)
        except Exception as e:
            # logger.warning("Search exception occurred", exc_info=True)
            raise e
        return response
