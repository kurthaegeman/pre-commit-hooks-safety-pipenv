from setuptools import find_packages, setup

setup(
    name="pre-commit-hooks-safety-pipenv",
    description="A pre-commit hook to check your Python pipenv-based project against safety-db",
    url="https://github.com/kurthaegeman/pre-commit-hooks-safety-pipenv",
    version="0.0.1",
    author="Kurt Haegeman",
    author_email="kurt@act1.be",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
    ],
    packages=find_packages("."),
    install_requires=[
        "pipenv",
    ],
    entry_points={
        "console_scripts": [
            "safety_check = src.safety_check:main",
        ],
    },
)
