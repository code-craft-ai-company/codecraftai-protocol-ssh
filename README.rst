==============================
Automation Mojo Protocol SSH
==============================

The ``automojo-protocol-ssh`` package is the dedicated SSH-protocol implementation for the automojo suite. It provides the building blocks (transport, session, packet handling, SFTP, tunnels, key and authentication handling, and a client/agent facade) used by any higher-level automojo package that needs to manage remote systems over SSH. It is consumed by ``automojo-interop``, ``automojo-landscaping`` (SSH-based coordinators), and the sysman packages that reach hosts over SSH.

Highlights
==========

- Connection lifecycle classes: ``SshBase``, ``SshClient``, ``SshConnection``, ``SshSession``, ``SshTransport``, and ``SshAgent``.
- ``SshAspects`` for packaging behaviour parameters (retry, timeout, action pattern) on SSH calls in the aspects style.
- Key and authentication helpers in ``sshkeys.py`` and ``sshauth.py``.
- SFTP and tunnel support in ``sshsftp.py`` and ``sshtunnel.py``.
- RFC-aligned implementations of the SSH transport and user authentication layers.

Repository Structure
====================

- ``development/`` - Runtime environment scripts.
- ``repository-setup/`` - Repository homing and setup scripts.
- ``source/packages/`` - Package source code.
- ``source/tests/`` - ``unittest``-based tests.
- ``source/testroots/testbase/`` - TestBase test roots.
- ``specs/`` - Requirements, design, and reference RFC documents.
- ``userguide/`` - Standards, conventions, and documentation.

Environment Setup
=================

When working in a Codex container:

.. code-block:: bash

   ./development/setup-agent-container

For local development:

.. code-block:: bash

   ./repository-setup/rehome-repository
   ./development/setup-envrionment

Running Tests
=============

Activate the virtual environment:

.. code-block:: bash

   source .venv/bin/activate

Run ``unittest`` tests:

.. code-block:: bash

   python -m unittest discover -s source/tests -p "test_*.py"

Run TestBase tests (when test roots are populated):

.. code-block:: bash

   testbase testing run --root source/testroots/testbase --includes=automojo --output=./.output

Standards and Conventions
=========================

- Naming conventions: ``userguide/10-02-naming-conventions.rst``
- Code organization: ``userguide/10-01-code-organization.rst``
- Coding standards: ``userguide/10-00-coding-standards.rst``

Additional Resources
====================

- Design documentation: ``specs/design.md``
- Requirements: ``specs/requirements.md``
- SSH protocol RFCs: ``specs/rfc4251.txt``, ``specs/rfc4252.txt``, ``specs/rfc4254.txt``
