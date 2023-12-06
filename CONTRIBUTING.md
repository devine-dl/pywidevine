# Development

This project is managed using [Poetry](https://python-poetry.org), a fantastic Python packaging and dependency manager.
Install the latest version of Poetry before continuing. Development currently requires Python 3.8+.

## Set up

Starting from Zero? Not sure where to begin? Here's steps on setting up this Python project using Poetry. Note that
Poetry installation instructions should be followed from the Poetry Docs: https://python-poetry.org/docs/#installation

1. While optional, It's recommended to configure Poetry to install Virtual environments within project folders:
    ```shell
    poetry config virtualenvs.in-project true
    ```
    This makes it easier for Visual Studio Code to detect the Virtual Environment, as well as other IDEs and systems.
    I've also had issues with Poetry creating duplicate Virtual environments in the default folder for an unknown
    reason which quickly filled up my System storage.
2. Clone the Repository:
    ```shell
    git clone https://github.com/devine-dl/pywidevine
    cd pywidevine
    ```
3. Install the Project with Poetry:
    ```shell
    poetry install
    ```
    This creates a Virtual environment and then installs all project dependencies and executables into the Virtual
    environment. Your System Python environment is not affected at all.
4. Now activate the Virtual environment:
    ```shell
    poetry shell
    ```
    Note:
    - You can alternatively just prefix `poetry run` to any command you wish to run under the Virtual environment.
    - I recommend entering the Virtual environment and all further instructions will have assumed you did.
    - JetBrains PyCharm has integrated support for Poetry and automatically enters Poetry Virtual environments, assuming
      the Python Interpreter on the bottom right is set up correctly.
    - For more information, see: https://python-poetry.org/docs/basic-usage/#using-your-virtual-environment
5. Install Pre-commit tooling to ensure safe and quality commits:
    ```shell
    pre-commit install
    ```

## Building Source and Wheel distributions

    poetry build

You can optionally specify `-f` to build `sdist` or `wheel` only.
Built files can be found in the `/dist` directory.
