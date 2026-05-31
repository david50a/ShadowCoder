import sys
from unittest.mock import MagicMock

class MockFinder:
    def find_spec(self, fullname, path, target=None):
        return __import__("importlib.util").util.spec_from_loader(fullname, self)
    def create_module(self, spec):
        return MagicMock()
    def exec_module(self, module):
        pass

sys.meta_path.append(MockFinder())

import requests, yaml, jinja2
print("Mocks loaded:", requests, yaml, jinja2)
