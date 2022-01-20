import setuptools
import os


def rel(*xs):
    return os.path.join(os.path.abspath(os.path.dirname(__file__)), *xs)

with open("README.md", "r") as fh:
    long_description = fh.read()

with open(rel('r2analyze', '__init__.py'), 'r') as f:
    version_marker = '__version__ = '
    for line in f:
        if line.startswith(version_marker):
            _, version = line.split(version_marker)
            version = version.strip().strip("'")
            break
    else:
        raise RuntimeError('Version marker not found.')

packages = [
    "r2analyze",
]

entry_points = {
    'console_scripts': [
        'r2analyze=r2analyze.pipe:main',
    ],
}

setuptools.setup(
    name='r2analyze',
    version=version,
    author="Intezer",
    description="r2pipe script for Intezer Analyze",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/",
    packages=packages,
    entry_points=entry_points,
    install_requires=[
            "r2pipe",
            "requests",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: BSD License",
        "Development Status :: 4 - Beta",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: MacOS :: MacOS X",
    ],

)
