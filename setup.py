import os
try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup

    def find_packages(where='.'):
        # os.walk -> list[(dirname, list[subdirs], list[files])]
        return [folder.replace("/", ".").lstrip(".")
                for (folder, _, fils) in os.walk(where)
                if "__init__.py" in fils]


setup(
    name='adapter_engine',
    version='0.0.1',
    url='https://github.com/cn-kali-team/adapter_engine',
    description='Adapter for pocsuite3 and nuclei.',
    long_description="""Adapter for pocsuite3 and nuclei""",
    keywords='adapter_engine,nuclei-engine,pocsuite3',
    author='Kali-Team',
    author_email='root@kali-team.cn',
    platforms=['any'],
    license='GPL 2.0',
    zip_safe=False,
    packages=find_packages(),
    include_package_data=True,
    python_requires='>=3.7',
    install_requires=[
        'requests',
        'requests-toolbelt',
    ],
)
