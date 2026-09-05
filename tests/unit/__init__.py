"""Test package marker.

Present so mypy and pytest agree on module names: without it mypy resolves
``tests/support/apps.py`` as ``support.apps`` while the code imports
``tests.support.apps``, and the same file is checked twice under two names.
"""
