from setuptools import setup, find_packages

setup(
    name="floss2yar",
    version="0.1",
    description="Generate YARA Based on code similarity",
    author="Greg Lesnewich and Connor McLaughlin",
    author_email="glesnewich@gmail.com",
    packages=find_packages(),
    install_requires=open("requirements.txt").read().splitlines(),
    entry_points={
        "console_scripts": ["floss2yar=floss2yar.main:main",],
    },
    python_requires=">=3.6",
)
