# codeguru-analyzer-package/setup.py

import setuptools
import os

# Read the README for the long description
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read the requirements.txt file for dependencies (optional, could list directly)
# If you don't create requirements.txt, remove this block and list dependencies below
install_requires = []
if os.path.exists('requirements.txt'):
    with open('requirements.txt') as f:
        install_requires = f.read().splitlines()


setuptools.setup(
    name="codeguru-analyzer-package",  # This is the name that will be used to install the package (e.g., pip install codeguru-analyzer-package)
    version="0.1.0",                   # Start with a version number
    author="Team Alquist",              # Replace with your name
    description="AWS CodeGuru Security Analyzer with Boto3 and automated Batching", # Short description
    long_description=long_description,     # Use the README as the long description
    long_description_content_type="text/markdown", # Indicate that the long description is Markdown
    packages=setuptools.find_packages(), # Automatically find all packages (directories with __init__.py)
    install_requires=install_requires, # List your dependencies here OR read from requirements.txt
    python_requires='>=3.7', # Specify supported Python versions
)
