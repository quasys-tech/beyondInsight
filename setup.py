from setuptools import setup, find_packages
setup(name='beyondtrust_agent',
      version='0.1',
      packages = find_packages(),
      install_requires=['requests', 'pyOpenSSL'],
      )